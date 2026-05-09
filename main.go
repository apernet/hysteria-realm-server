package main

import (
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/spf13/pflag"
)

type config struct {
	Listen             string
	Token              string
	Cert               string
	Key                string
	Debug              bool
	MaxRealms          int
	MaxRealmsPerIP     int
	TrustedProxyHeader string
	RealmNamePattern   string
}

var (
	realmToken string
	debugLogs  bool
)

func debugf(format string, v ...any) {
	if debugLogs {
		log.Printf("debug: "+format, v...)
	}
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	realmToken = cfg.Token
	if cfg.Token == "" {
		log.Fatal("HYSTERIA_REALM_TOKEN is required")
	}
	debugLogs = cfg.Debug

	pat, err := regexp.Compile(cfg.RealmNamePattern)
	if err != nil {
		log.Fatalf("invalid realm name pattern %q: %v", cfg.RealmNamePattern, err)
	}
	s := newServer(serverConfig{
		maxRealms:      cfg.MaxRealms,
		maxRealmsPerIP: cfg.MaxRealmsPerIP,
		proxyHeader:    cfg.TrustedProxyHeader,
		realmIDPattern: pat,
	})
	go s.reaper()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("hysteria realm server listening on %s", cfg.Listen)
	if debugLogs {
		log.Println("debug logging enabled")
	}
	if cfg.Cert != "" && cfg.Key != "" {
		log.Fatal(srv.ListenAndServeTLS(cfg.Cert, cfg.Key))
	}
	log.Println("warning: serving plain HTTP; set HYSTERIA_REALM_CERT and HYSTERIA_REALM_KEY for TLS")
	log.Fatal(srv.ListenAndServe())
}

func parseConfig(args []string) (config, error) {
	cfg := config{
		Listen:             getenv("HYSTERIA_REALM_LISTEN", ":8443"),
		Token:              getenv("HYSTERIA_REALM_TOKEN", ""),
		Cert:               getenv("HYSTERIA_REALM_CERT", ""),
		Key:                getenv("HYSTERIA_REALM_KEY", ""),
		Debug:              getenvBool("HYSTERIA_REALM_DEBUG", false),
		MaxRealms:          getenvInt("HYSTERIA_REALM_MAX_REALMS", 65536),
		MaxRealmsPerIP:     getenvInt("HYSTERIA_REALM_MAX_REALMS_PER_IP", 4),
		TrustedProxyHeader: getenv("HYSTERIA_REALM_TRUSTED_PROXY_HEADER", ""),
		RealmNamePattern:   getenv("HYSTERIA_REALM_NAME_PATTERN", defaultRealmNamePattern),
	}
	fs := pflag.NewFlagSet("hysteria-realm-server", pflag.ContinueOnError)
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "address to listen on")
	fs.StringVar(&cfg.Token, "token", cfg.Token, "shared bearer token for registration and connection")
	fs.StringVar(&cfg.Cert, "cert", cfg.Cert, "path to TLS certificate")
	fs.StringVar(&cfg.Key, "key", cfg.Key, "path to TLS private key")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable debug logs")
	fs.IntVar(&cfg.MaxRealms, "max-realms", cfg.MaxRealms, "maximum total realms (0 = unlimited)")
	fs.IntVar(&cfg.MaxRealmsPerIP, "max-realms-per-ip", cfg.MaxRealmsPerIP, "maximum realms per client IP (0 = unlimited)")
	fs.StringVar(&cfg.TrustedProxyHeader, "trusted-proxy-header", cfg.TrustedProxyHeader, "header to read real client IP from (e.g. X-Forwarded-For)")
	fs.StringVar(&cfg.RealmNamePattern, "realm-name-pattern", cfg.RealmNamePattern, "regex realm names must match")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getenvBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
