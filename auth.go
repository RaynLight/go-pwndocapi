package pwndoc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// sessionTokens is the datas payload returned by login/refresh.
type sessionTokens struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

// Connect creates a Client and immediately logs in, returning a ready-to-use
// authenticated client. It is the most convenient entry point.
func Connect(ctx context.Context, baseURL, username, password string, opts ...Option) (*Client, error) {
	c, err := New(baseURL, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Login(ctx, username, password, ""); err != nil {
		return nil, err
	}
	return c, nil
}

// Login authenticates with a username and password (and an optional TOTP token
// for accounts with two-factor authentication — pass "" when not used), storing
// the resulting session tokens on the client.
func (c *Client) Login(ctx context.Context, username, password, totp string) error {
	body := map[string]string{"username": username, "password": password}
	if totp != "" {
		body["totpToken"] = totp
	}
	tok, err := call[sessionTokens](ctx, c, apiReq{
		method: http.MethodPost, path: "/users/token", body: body, op: "Login",
	})
	if err != nil {
		return err
	}
	c.setTokens(tok.Token, tok.RefreshToken)
	return nil
}

// Logout invalidates the server-side session and clears the stored tokens.
func (c *Client) Logout(ctx context.Context) error {
	rt := c.refreshTokenValue()
	cookie := ""
	if rt != "" {
		cookie = "refreshToken=" + rt
	}
	status, body, err := c.do(ctx, apiReq{
		method: http.MethodDelete, path: "/users/refreshtoken", op: "Logout", cookie: cookie,
	})
	c.clearTokens()
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		_, derr := decodeEnvelope[json.RawMessage](body, status)
		return derr
	}
	return nil
}

// Refresh exchanges the stored refresh token for a fresh access token. The
// client does this automatically on a 401 when auto-refresh is enabled (the
// default), so calling it directly is rarely necessary.
func (c *Client) Refresh(ctx context.Context) error { return c.refresh(ctx) }

// refresh performs the token exchange, collapsing concurrent callers into a
// single network refresh.
func (c *Client) refresh(ctx context.Context) error {
	prev := c.accessTokenValue()

	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	// Another goroutine may have refreshed while we waited for the lock.
	if cur := c.accessTokenValue(); cur != "" && cur != prev {
		return nil
	}

	rt := c.refreshTokenValue()
	if rt == "" {
		return ErrNotAuthenticated
	}
	status, body, err := c.do(ctx, apiReq{
		method: http.MethodGet, path: "/users/refreshtoken", op: "Refresh", cookie: "refreshToken=" + rt,
	})
	if err != nil {
		return err
	}
	out, derr := decodeEnvelope[sessionTokens](body, status)
	if derr != nil {
		return errors.Join(ErrRefreshFailed, derr)
	}
	c.setTokens(out.Token, out.RefreshToken)
	return nil
}

// CheckToken returns the raw token cookie value if the current session is valid,
// or an *APIError otherwise.
func (c *Client) CheckToken(ctx context.Context) (string, error) {
	return call[string](ctx, c, apiReq{
		method: http.MethodGet, path: "/users/checktoken", op: "CheckToken",
	})
}
