package pwndoc

import (
	"crypto/tls"
	"errors"
	"net/http"
	"time"
)

// Option configures a Client. Options are applied in order by New and may
// return an error to reject an invalid or conflicting combination.
type Option func(*Client) error

// WithHTTPClient sets a custom *http.Client. It conflicts with WithInsecureTLS,
// WithTLSConfig, WithCABundle and WithTimeout, which configure the default
// client — set those on your own client instead.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) error {
		if hc == nil {
			return errors.New("pwndoc: WithHTTPClient: nil *http.Client")
		}
		c.doer = hc
		return nil
	}
}

// WithHTTPDoer sets a custom transport implementing Doer. Useful in tests.
func WithHTTPDoer(d Doer) Option {
	return func(c *Client) error {
		if d == nil {
			return errors.New("pwndoc: WithHTTPDoer: nil Doer")
		}
		c.doer = d
		return nil
	}
}

// WithTimeout sets the per-request timeout on the default HTTP client (default
// 30s). Ignored when WithHTTPClient/WithHTTPDoer is used.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d < 0 {
			return errors.New("pwndoc: WithTimeout: negative timeout")
		}
		c.timeout = d
		return nil
	}
}

// WithInsecureTLS disables TLS certificate verification. pwndoc instances are
// frequently deployed with self-signed certificates, so this is commonly
// required for lab setups. Prefer WithCABundle in production.
func WithInsecureTLS() Option {
	return func(c *Client) error {
		c.insecureTLS = true
		return nil
	}
}

// WithCABundle trusts the given PEM-encoded CA certificate(s) for TLS
// verification — a safer alternative to WithInsecureTLS for instances using a
// private CA.
func WithCABundle(pem []byte) Option {
	return func(c *Client) error {
		if len(pem) == 0 {
			return errors.New("pwndoc: WithCABundle: empty PEM data")
		}
		c.caBundle = pem
		return nil
	}
}

// WithTLSConfig sets a base *tls.Config for the default HTTP client. Any
// WithInsecureTLS / WithCABundle settings are layered on top of a clone of it.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(c *Client) error {
		c.tlsConfig = cfg
		return nil
	}
}

// WithUserAgent overrides the User-Agent header sent with every request.
func WithUserAgent(ua string) Option {
	return func(c *Client) error {
		if ua != "" {
			c.userAgent = ua
		}
		return nil
	}
}

// WithToken seeds the client with an existing access token (and optionally a
// refresh token), so a persisted session can be reused without calling Login.
func WithToken(access, refresh string) Option {
	return func(c *Client) error {
		c.accessToken = access
		c.refreshToken = refresh
		return nil
	}
}

// WithAutoRefresh controls whether the client transparently refreshes an
// expired access token and retries the request on a 401. Enabled by default.
func WithAutoRefresh(enabled bool) Option {
	return func(c *Client) error {
		c.autoRefresh = enabled
		return nil
	}
}

// WithRetries configures automatic retries for transient failures (network
// timeouts and 429/5xx responses) on idempotent requests. max is the number of
// extra attempts; base and max delay bound the exponential backoff.
func WithRetries(maxAttempts int, base, maxDelay time.Duration) Option {
	return func(c *Client) error {
		if maxAttempts < 0 {
			return errors.New("pwndoc: WithRetries: negative attempts")
		}
		c.maxRetries = maxAttempts
		if base > 0 {
			c.retryBase = base
		}
		if maxDelay > 0 {
			c.retryMax = maxDelay
		}
		return nil
	}
}
