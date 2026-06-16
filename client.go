// Package pwndoc is an idiomatic, zero-dependency Go client for the pwndoc
// pentest-reporting REST API (https://github.com/pwndoc/pwndoc).
//
// It covers the entire API surface — audits, findings, images, clients,
// companies, users, the vulnerability template database, data catalogs, report
// templates, settings and backups — and adds a high-level orchestration layer
// (see the *Client methods such as NewPentest, AddFindingWithImages,
// AttachImageToFinding and GenerateReport) so common workflows take only a
// handful of calls.
//
// # Authentication
//
// pwndoc authenticates with a session cookie rather than a bearer token. Call
// Client.Login (or the Connect helper) once; the client stores the access and
// refresh tokens and attaches them to subsequent requests, transparently
// refreshing an expired access token on a 401.
//
//	c, err := pwndoc.Connect(ctx, "https://pwndoc.example.com:8443",
//	    "user", "pass", pwndoc.WithInsecureTLS())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	audits, err := c.Audits.List(ctx, nil)
//
// Every method takes a context.Context and returns typed models and *APIError
// values for server-side failures (classify them with IsNotFound, IsForbidden,
// and the other package-level helpers).
package pwndoc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// Version is the library version, sent in the default User-Agent.
	Version = "0.2.0"

	defaultTimeout    = 30 * time.Second
	defaultMaxRetries = 2
	defaultUserAgent  = "go-pwndocapi/" + Version + " (+https://github.com/RaynLight/go-pwndocapi)"
)

// Client is a pwndoc API client. Create one with New or Connect. A Client is
// safe for concurrent use by multiple goroutines.
//
// Resources are grouped into services accessed via the exported fields, e.g.
// c.Audits.Create, c.Findings.Create, c.Images.Upload. High-level "do
// everything" verbs (Login, NewPentest, AddFindingWithImages, GenerateReport,
// ...) are methods on *Client directly.
type Client struct {
	baseURL     *url.URL
	doer        Doer
	userAgent   string
	autoRefresh bool
	maxRetries  int
	retryBase   time.Duration
	retryMax    time.Duration

	// Configuration captured by options before the default Doer is built.
	timeout     time.Duration
	insecureTLS bool
	tlsConfig   *tls.Config
	caBundle    []byte

	mu           sync.RWMutex
	accessToken  string
	refreshToken string
	refreshMu    sync.Mutex // serializes refreshes so concurrent 401s collapse to one

	// Audits manages audits (engagements): findings, sections, comments,
	// scope, retests, the review workflow and report generation.
	Audits *AuditsService
	// Findings is a convenience view over an audit's findings.
	Findings *FindingsService
	// Clients manages client contacts (modeled as Contact to avoid colliding
	// with this Client type).
	Clients *ClientsService
	// Companies manages companies.
	Companies *CompaniesService
	// Users manages user accounts and the current profile.
	Users *UsersService
	// Data manages the shared catalogs: languages, audit types, vulnerability
	// types and categories, custom sections and custom fields.
	Data *DataService
	// Vulnerabilities manages the reusable vulnerability template database.
	Vulnerabilities *VulnerabilitiesService
	// Templates manages Word report templates.
	Templates *TemplatesService
	// Settings reads and updates instance settings.
	Settings *SettingsService
	// Images uploads, fetches and deletes images referenced by findings.
	Images *ImagesService
	// Backups manages instance backups.
	Backups *BackupsService
}

// New creates a Client for the pwndoc instance at baseURL (for example
// "https://pwndoc.example.com:8443"). It performs no network I/O; authenticate
// with Client.Login, or use Connect to do both at once.
func New(baseURL string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("pwndoc: baseURL is required")
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil {
		return nil, fmt.Errorf("pwndoc: invalid baseURL %q: %w", baseURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("pwndoc: baseURL %q must include a scheme and host", baseURL)
	}

	c := &Client{
		baseURL:     u,
		userAgent:   defaultUserAgent,
		autoRefresh: true,
		maxRetries:  defaultMaxRetries,
		retryBase:   200 * time.Millisecond,
		retryMax:    2 * time.Second,
		timeout:     defaultTimeout,
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	if c.doer == nil {
		hc, err := c.buildHTTPClient()
		if err != nil {
			return nil, err
		}
		c.doer = hc
	}

	c.Audits = &AuditsService{c: c}
	c.Findings = &FindingsService{c: c}
	c.Clients = &ClientsService{c: c}
	c.Companies = &CompaniesService{c: c}
	c.Users = &UsersService{c: c}
	c.Data = &DataService{c: c}
	c.Vulnerabilities = &VulnerabilitiesService{c: c}
	c.Templates = &TemplatesService{c: c}
	c.Settings = &SettingsService{c: c}
	c.Images = &ImagesService{c: c}
	c.Backups = &BackupsService{c: c}

	return c, nil
}

func (c *Client) buildHTTPClient() (*http.Client, error) {
	tlsCfg := c.tlsConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
	}
	if c.insecureTLS {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // opt-in for self-signed pwndoc instances
	}
	if len(c.caBundle) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(c.caBundle) {
			return nil, errors.New("pwndoc: WithCABundle: no valid certificates found in PEM data")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout: c.timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     tlsCfg,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}, nil
}

// BaseURL returns the normalized base URL the client targets (without the
// trailing /api path).
func (c *Client) BaseURL() string { return c.baseURL.String() }

// IsAuthenticated reports whether the client currently holds an access token.
func (c *Client) IsAuthenticated() bool { return c.accessTokenValue() != "" }

// Tokens returns the current access and refresh tokens, allowing a session to
// be persisted and later restored with WithToken.
func (c *Client) Tokens() (access, refresh string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken, c.refreshToken
}

func (c *Client) accessTokenValue() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken
}

func (c *Client) refreshTokenValue() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.refreshToken
}

func (c *Client) setTokens(access, refresh string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if access != "" {
		c.accessToken = access
	}
	if refresh != "" {
		c.refreshToken = refresh
	}
}

func (c *Client) clearTokens() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = ""
	c.refreshToken = ""
}
