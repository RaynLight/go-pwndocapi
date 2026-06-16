package pwndoc

import (
	"errors"
	"fmt"
	"net/http"
)

// APIError is returned whenever the server reports a non-success outcome, or a
// transport/decoding problem is attributable to a specific request. Inspect it
// with errors.As, the package-level classifiers (IsNotFound, IsUnauthorized,
// ...), or the predicate methods (NotFound, Unauthorized, ...).
type APIError struct {
	StatusCode int    // HTTP status (400/401/403/404/...)
	Status     string // envelope "status" field, usually "error"
	Message    string // human-readable message from datas
	Method     string // request method, for diagnostics
	Path       string // request path (no host), for diagnostics
	Op         string // logical operation, e.g. "Findings.Create"
	Err        error  // wrapped low-level cause (decode/transport failures); usually nil
}

func (e *APIError) Error() string {
	loc := e.Op
	if loc == "" && e.Method != "" {
		loc = e.Method + " " + e.Path
	}
	if loc != "" {
		return fmt.Sprintf("pwndoc: %s: %d %s: %s", loc, e.StatusCode, http.StatusText(e.StatusCode), e.Message)
	}
	return fmt.Sprintf("pwndoc: %d %s: %s", e.StatusCode, http.StatusText(e.StatusCode), e.Message)
}

// Unwrap exposes the wrapped low-level cause, if any.
func (e *APIError) Unwrap() error { return e.Err }

// Predicate methods — match on these instead of magic numbers.
func (e *APIError) Unauthorized() bool { return e.StatusCode == http.StatusUnauthorized }
func (e *APIError) Forbidden() bool    { return e.StatusCode == http.StatusForbidden }
func (e *APIError) NotFound() bool     { return e.StatusCode == http.StatusNotFound }
func (e *APIError) BadRequest() bool   { return e.StatusCode == http.StatusBadRequest }
func (e *APIError) Conflict() bool {
	return e.StatusCode == http.StatusConflict || e.StatusCode == http.StatusUnprocessableEntity
}
func (e *APIError) Server() bool { return e.StatusCode >= 500 }

// Sentinel errors, comparable with errors.Is.
var (
	// ErrNotAuthenticated is returned when an authenticated request is attempted
	// before a successful Login (or after the session was cleared).
	ErrNotAuthenticated = errors.New("pwndoc: not authenticated (call Login first)")
	// ErrRefreshFailed indicates the refresh token could not be exchanged.
	ErrRefreshFailed = errors.New("pwndoc: token refresh failed")
	// ErrNoTOTP indicates the account requires a TOTP token to log in.
	ErrNoTOTP = errors.New("pwndoc: account requires a TOTP token")
	// ErrEmptyID indicates a required resource id argument was empty.
	ErrEmptyID = errors.New("pwndoc: empty id")
)

// Package-level classifiers usable on any returned error (wrap-aware).
func IsNotFound(err error) bool     { return classify(err, (*APIError).NotFound) }
func IsUnauthorized(err error) bool { return classify(err, (*APIError).Unauthorized) }
func IsForbidden(err error) bool    { return classify(err, (*APIError).Forbidden) }
func IsBadRequest(err error) bool   { return classify(err, (*APIError).BadRequest) }
func IsConflict(err error) bool     { return classify(err, (*APIError).Conflict) }
func IsServer(err error) bool       { return classify(err, (*APIError).Server) }

func classify(err error, pred func(*APIError) bool) bool {
	var ae *APIError
	return errors.As(err, &ae) && pred(ae)
}

// AsAPIError extracts the underlying *APIError, if any.
//
//	if ae, ok := pwndoc.AsAPIError(err); ok && ae.StatusCode == 403 { ... }
func AsAPIError(err error) (*APIError, bool) {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}
