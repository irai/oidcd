package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v3"

	"oidcd/server"
)

func main() {
	configPath := flag.String("config", os.Getenv("OIDCD_CONFIG"), "Path to YAML config")
	logLevel := flag.String("log-level", "info", "Logging level (debug, info, warn, error)")
	flag.StringVar(logLevel, "l", "info", "Alias for -log-level")
	flag.Parse()

	level, err := parseLogLevel(*logLevel)
	if err != nil {
		log.Fatalf("invalid log level %q: %v", *logLevel, err)
	}

	args := flag.Args()
	command := ""
	commandArgs := args
	if len(commandArgs) > 0 && commandArgs[0] == "connect" {
		command = "connect"
		commandArgs = commandArgs[1:]
	}

	configFile := *configPath
	if configFile == "" && command == "" && len(commandArgs) > 0 {
		configFile = commandArgs[0]
		commandArgs = commandArgs[1:]
	}
	if configFile == "" {
		configFile = "./config.yaml"
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	cfg, err := loadOrSetupConfig(configFile, logger)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if command == "connect" {
		if len(commandArgs) == 0 {
			log.Fatalf("usage: %s [--config path] connect <provider>", os.Args[0])
		}
		providerName := commandArgs[0]
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := runConnect(ctx, cfg, logger, providerName, nil, nil); err != nil {
			logger.Error("provider connectivity failed", "provider", providerName, "error", err)
			os.Exit(1)
		}
		logger.Info("provider connectivity succeeded", "provider", providerName)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	application, err := server.NewApp(ctx, cfg, logger)
	if err != nil {
		log.Fatalf("init app: %v", err)
	}

	stopRotate := make(chan struct{})
	application.JWKS.StartRotation(stopRotate)
	defer close(stopRotate)

	handler := application.Routes()
	if !cfg.Server.DevMode {
		handler = withHSTS(handler, cfg)
	}

	var shutdownFns []func(context.Context) error

	if cfg.Server.DevMode {
		srv := &http.Server{
			Addr:         cfg.Server.DevListenAddr,
			Handler:      handler,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
		}
		shutdownFns = append(shutdownFns, srv.Shutdown)
		logger.Info("server listening", "mode", "dev", "addr", cfg.Server.DevListenAddr)
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("server error", "error", err)
			}
		}()
	} else {
		m := &autocert.Manager{
			Cache:      autocert.DirCache(cfg.Server.TLS.CacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Server.DomainNames...),
			Email:      cfg.Server.TLS.Email,
		}
		tlsCfg := &tls.Config{
			GetCertificate: m.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}

		httpRedirect := &http.Server{
			Addr:    cfg.Server.HTTPListenAddr,
			Handler: m.HTTPHandler(http.HandlerFunc(redirectToHTTPS)),
		}
		shutdownFns = append(shutdownFns, httpRedirect.Shutdown)
		go func() {
			if err := httpRedirect.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("http redirect error", "error", err)
			}
		}()

		httpsSrv := &http.Server{
			Addr:      cfg.Server.HTTPSListenAddr,
			Handler:   handler,
			TLSConfig: tlsCfg,
		}
		shutdownFns = append(shutdownFns, httpsSrv.Shutdown)
		logger.Info("server listening", "mode", "prod", "addr", cfg.Server.HTTPSListenAddr)
		go func() {
			if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logger.Error("https server error", "error", err)
			}
		}()
	}

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, fn := range shutdownFns {
		_ = fn(shutdownCtx)
	}
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func withHSTS(h http.Handler, cfg server.Config) http.Handler {
	if cfg.Server.DevMode {
		return h
	}
	return server.SecurityHeadersMiddleware(cfg.Server.TLS.HSTSMaxAge)(h)
}

func runConnect(ctx context.Context, cfg server.Config, logger *slog.Logger, providerName string, provided map[string]server.IdentityProvider, httpClient *http.Client) error {
	if providerName == "" {
		return errors.New("provider name required")
	}

	providers := provided
	if providers == nil {
		var err error
		providers, err = server.BuildProviders(ctx, cfg, logger)
		if err != nil {
			return fmt.Errorf("build providers: %w", err)
		}
	}

	provider, ok := providers[providerName]
	if !ok {
		return fmt.Errorf("provider %s not configured", providerName)
	}

	state := randomHex(8)
	nonce := randomHex(8)
	authURL := provider.AuthCodeURL(state, nonce, "", "")
	logger.Info("connect.start", "provider", providerName, "auth_url", authURL)
	logger.Info("connect.instructions", "provider", providerName, "message", "Open auth_url in a browser to perform interactive login if needed", "auth_url", authURL)

	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	originalRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		step := len(via) + 1
		logger.Info("connect.redirect", "step", step, "url", req.URL.String())
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects (%d)", len(via))
		}
		if originalRedirect != nil {
			return originalRedirect(req, via)
		}
		return nil
	}
	defer func() { client.CheckRedirect = originalRedirect }()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return fmt.Errorf("create authorize request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call authorize endpoint: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	logger.Info("connect.result", "status", resp.StatusCode, "effective_url", resp.Request.URL.String())

	switch {
	case resp.StatusCode >= 400:
		return fmt.Errorf("provider returned %s for %s", resp.Status, resp.Request.URL.String())
	case resp.StatusCode >= 300:
		return fmt.Errorf("unexpected additional redirect (status %d)", resp.StatusCode)
	}

	logger.Info("connect.success", "provider", providerName, "message", "Reached provider login endpoint")
	return nil
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func loadOrSetupConfig(path string, logger *slog.Logger) (server.Config, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return runSetup(path, logger)
		}
		return server.Config{}, fmt.Errorf("stat config: %w", err)
	}
	logger.Debug("loading config", "path", path)
	return server.LoadConfig(path)
}

func runSetup(path string, logger *slog.Logger) (server.Config, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("No configuration file found at %s.\n", path)
	fmt.Println("Starting guided setup for Microsoft Entra ID (Azure AD). Press Enter to accept defaults.")

	cfg := server.DefaultConfig()

	devMode := askYesNo(reader, "Run in development mode?", true)
	cfg.Server.DevMode = devMode

	defaultIssuer := cfg.Server.PublicURL
	if !devMode {
		defaultIssuer = "https://auth.example.com"
	}
	issuer := strings.TrimSuffix(ask(reader, "Gateway public URL", defaultIssuer), "/")
	if issuer == "" {
		issuer = defaultIssuer
	}
	cfg.Server.PublicURL = issuer

	if devMode {
		cfg.Server.DevListenAddr = ask(reader, "Gateway dev listen address", cfg.Server.DevListenAddr)
		corsOrigins := ask(reader, "Client CORS origin URLs (comma separated)", strings.Join(cfg.Server.CORS.ClientOriginURLs, ", "))
		cfg.Server.CORS.ClientOriginURLs = normalizeList(corsOrigins, cfg.Server.CORS.ClientOriginURLs)
	} else {
		domain := askRequired(reader, "Primary public domain (e.g. auth.example.com)")
		cfg.Server.DomainNames = []string{domain}
		cfg.Server.PublicURL = "https://" + strings.TrimSuffix(domain, "/")
		acmeEmail := ask(reader, "ACME contact email", cfg.Server.TLS.Email)
		cfg.Server.TLS.Email = acmeEmail
		cfg.Server.HTTPListenAddr = ":80"
		cfg.Server.HTTPSListenAddr = ":443"
	}

	clientID := ask(reader, "Client OAuth ID", "webapp")
	redirect := ask(reader, "Client redirect URI", "http://127.0.0.1:3000/callback")
	redirects := normalizeList(redirect, []string{"http://127.0.0.1:3000/callback"})

	cfg.Clients = []server.ClientConfig{{
		ClientID:     clientID,
		ClientSecret: "",
		RedirectURIs: redirects,
		Scopes:       []string{"openid", "profile", "email"},
		Audiences:    []string{cfg.Tokens.AudienceDefault},
	}}

	tenantID := askRequired(reader, "Microsoft Entra tenant ID (GUID)")
	upstreamClientID := askRequired(reader, "Gateway app registration client ID")
	upstreamClientSecret := askRequired(reader, "Gateway app registration client secret")

	cfg.Providers.Default = "entra"
	cfg.Providers.Entra.Issuer = "https://login.microsoftonline.com/common/v2.0"
	cfg.Providers.Entra.TenantID = tenantID
	cfg.Providers.Entra.ClientID = upstreamClientID
	cfg.Providers.Entra.ClientSecret = upstreamClientSecret
	cfg.Providers.Auth0 = server.UpstreamProvider{}

	if err := writeConfigFile(path, cfg); err != nil {
		return server.Config{}, err
	}
	logger.Info("configuration created", "path", path)

	return server.LoadConfig(path)
}

func ask(reader *bufio.Reader, prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return strings.TrimSpace(def)
	}
	return input
}

func askRequired(reader *bufio.Reader, prompt string) string {
	for {
		fmt.Printf("%s: ", prompt)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			return input
		}
		fmt.Println("This value is required. Please enter a value.")
	}
}

func askYesNo(reader *bufio.Reader, prompt string, def bool) bool {
	defLabel := "Y"
	if !def {
		defLabel = "N"
	}
	for {
		fmt.Printf("%s [%s]: ", prompt, defLabel)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "" {
			return def
		}
		switch input {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		default:
			fmt.Println("Please enter 'y' or 'n'.")
		}
	}
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "err":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level")
	}
}

func normalizeList(input string, fallback []string) []string {
	if strings.TrimSpace(input) == "" {
		return fallback
	}
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

func writeConfigFile(path string, cfg server.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
