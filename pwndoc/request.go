package pwndoc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const apiPrefix = "/api"

// Doer is the minimal HTTP transport seam, satisfied by *http.Client. Supplying
// a custom Doer (via WithHTTPDoer) makes the client trivial to unit-test.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// envelope is the universal pwndoc wire wrapper: {"status":...,"datas":...}.
// datas is the payload on success and a string message on error.
type envelope struct {
	Status string          `json:"status"`
	Datas  json.RawMessage `json:"datas"`
}

// decodeEnvelope splits a successful payload from an error message. T is the
// inner datas type the caller expects. It is a pure function, independently
// unit-testable against raw bytes.
func decodeEnvelope[T any](body []byte, httpStatus int) (T, error) {
	var zero T
	var env envelope
	if len(body) > 0 {
		if err := json.Unmarshal(body, &env); err != nil {
			// Non-JSON body (proxy/HTML error page): surface raw, truncated.
			return zero, &APIError{StatusCode: httpStatus, Message: truncate(strings.TrimSpace(string(body)), 512)}
		}
	}
	if httpStatus >= 200 && httpStatus < 300 && (env.Status == "success" || len(body) == 0) {
		var out T
		if len(env.Datas) > 0 && string(env.Datas) != "null" {
			if err := json.Unmarshal(env.Datas, &out); err != nil {
				return zero, &APIError{StatusCode: httpStatus, Message: "decoding datas: " + err.Error(), Err: err}
			}
		}
		return out, nil
	}
	// Error path: datas is usually a string message.
	var msg string
	if json.Unmarshal(env.Datas, &msg) != nil || msg == "" {
		msg = strings.TrimSpace(string(env.Datas))
	}
	return zero, &APIError{StatusCode: httpStatus, Message: msg, Status: env.Status}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// apiReq is the internal description of one logical call.
type apiReq struct {
	method string
	path   string            // relative to /api, e.g. "/audits/{id}/findings"
	query  map[string]string // optional query params
	body   any               // JSON-marshaled if non-nil
	op     string            // for error context, e.g. "Findings.List"
	raw    bool              // if true, caller wants raw bytes (binary: docx, image)
	cookie string            // overrides the default token cookie (used by refresh)
}

// do executes r with retries, 401 auto-refresh, and envelope-aware errors.
func (c *Client) do(ctx context.Context, r apiReq) (status int, body []byte, err error) {
	var bodyBytes []byte
	if r.body != nil {
		if bodyBytes, err = json.Marshal(r.body); err != nil {
			return 0, nil, &APIError{Op: r.op, Message: "encoding body: " + err.Error(), Err: err}
		}
	}

	attempt := 0
	refreshed := false
	for {
		httpReq, rerr := c.newRequest(ctx, r, bodyBytes)
		if rerr != nil {
			return 0, nil, rerr
		}

		resp, derr := c.doer.Do(httpReq)
		if derr != nil {
			if ctx.Err() == nil && shouldRetryNetErr(derr) && idempotent(r.method) && attempt < c.maxRetries {
				if werr := sleepCtx(ctx, c.backoff(attempt+1)); werr != nil {
					return 0, nil, werr
				}
				attempt++
				continue
			}
			return 0, nil, &APIError{Op: r.op, Method: r.method, Path: apiPrefix + r.path,
				Message: derr.Error(), Err: derr}
		}
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		// 401 -> refresh once, replay (orthogonal to retry).
		if resp.StatusCode == http.StatusUnauthorized && c.autoRefresh && !refreshed && r.cookie == "" {
			if c.refresh(ctx) == nil {
				refreshed = true
				continue
			}
		}
		// Transient 429/5xx retry for idempotent methods.
		if shouldRetryStatus(resp.StatusCode) && idempotent(r.method) && attempt < c.maxRetries {
			if werr := sleepCtx(ctx, c.backoff(attempt+1)); werr != nil {
				return resp.StatusCode, nil, werr
			}
			attempt++
			continue
		}

		if r.raw && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp.StatusCode, respBody, nil
		}
		return resp.StatusCode, respBody, nil
	}
}

func (c *Client) newRequest(ctx context.Context, r apiReq, body []byte) (*http.Request, error) {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + apiPrefix + r.path
	if len(r.query) > 0 {
		q := u.Query()
		for k, v := range r.query {
			if v != "" {
				q.Set(k, v)
			}
		}
		u.RawQuery = q.Encode()
	}

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), rdr)
	if err != nil {
		return nil, &APIError{Op: r.op, Message: "building request: " + err.Error(), Err: err}
	}
	if body != nil {
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	// Cookie-based auth: pwndoc expects `token=JWT <jwt>` (the Authorization
	// header is rejected). The header is set verbatim — net/http's AddCookie
	// would double-quote the space-containing value, which the server mishandles.
	cookie := r.cookie
	if cookie == "" {
		if tok := c.accessTokenValue(); tok != "" {
			cookie = "token=JWT " + tok
		}
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	return req, nil
}

// annotate fills in operation/method/path context on an *APIError. It returns a
// clone so the original error (which may be shared or constructed elsewhere) is
// never mutated in place.
func annotate(err error, r apiReq) error {
	var ae *APIError
	if !errors.As(err, &ae) {
		return err
	}
	clone := *ae
	if clone.Op == "" {
		clone.Op = r.op
	}
	if clone.Method == "" {
		clone.Method, clone.Path = r.method, apiPrefix+r.path
	}
	return &clone
}

// call performs an apiReq and decodes the success datas into T.
func call[T any](ctx context.Context, c *Client, r apiReq) (T, error) {
	status, body, err := c.do(ctx, r)
	if err != nil {
		var zero T
		return zero, annotate(err, r)
	}
	out, derr := decodeEnvelope[T](body, status)
	if derr != nil {
		var zero T
		return zero, annotate(derr, r)
	}
	return out, nil
}

// callNoContent runs an apiReq whose datas payload is discarded (deletes, etc.).
func callNoContent(ctx context.Context, c *Client, r apiReq) error {
	_, err := call[json.RawMessage](ctx, c, r)
	return err
}

// callRawTo streams a binary response (docx, image, backup) to w.
func callRawTo(ctx context.Context, c *Client, r apiReq, w io.Writer) error {
	r.raw = true
	status, body, err := c.do(ctx, r)
	if err != nil {
		return annotate(err, r)
	}
	if status < 200 || status >= 300 {
		_, derr := decodeEnvelope[json.RawMessage](body, status)
		return annotate(derr, r)
	}
	_, werr := w.Write(body)
	return werr
}

// callRawBytes returns a binary response as []byte.
func callRawBytes(ctx context.Context, c *Client, r apiReq) ([]byte, error) {
	r.raw = true
	status, body, err := c.do(ctx, r)
	if err != nil {
		return nil, annotate(err, r)
	}
	if status < 200 || status >= 300 {
		_, derr := decodeEnvelope[json.RawMessage](body, status)
		return nil, annotate(derr, r)
	}
	return body, nil
}

func pathID(id string) string { return url.PathEscape(id) }

// --- retry helpers ---

func idempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

func shouldRetryStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

func shouldRetryNetErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

func (c *Client) backoff(attempt int) time.Duration {
	const maxShift = 30 // guard against overflow for very large retry counts
	shift := attempt - 1
	if shift > maxShift {
		return c.retryMax
	}
	d := c.retryBase * time.Duration(int64(1)<<shift)
	if d <= 0 || d > c.retryMax {
		d = c.retryMax
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
