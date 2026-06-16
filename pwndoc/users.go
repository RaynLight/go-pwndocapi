package pwndoc

import (
	"context"
	"net/http"
)

// User represents a pwndoc user account.
type User struct {
	ID          string `json:"_id,omitempty"`
	Username    string `json:"username,omitempty"`
	Firstname   string `json:"firstname,omitempty"`
	Lastname    string `json:"lastname,omitempty"`
	Role        string `json:"role,omitempty"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
	JobTitle    string `json:"jobTitle,omitempty"`
	TOTPEnabled bool   `json:"totpEnabled,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
}

// CreateUserParams are the fields for creating a user. Username, Password,
// Firstname and Lastname are required; Role defaults to "user".
type CreateUserParams struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Role      string `json:"role,omitempty"`
	Email     string `json:"email,omitempty"`
	Phone     string `json:"phone,omitempty"`
	JobTitle  string `json:"jobTitle,omitempty"`
}

// UpdateUserParams updates another user (admin). Only non-nil fields are sent.
type UpdateUserParams struct {
	Username    *string `json:"username,omitempty"`
	Firstname   *string `json:"firstname,omitempty"`
	Lastname    *string `json:"lastname,omitempty"`
	Email       *string `json:"email,omitempty"`
	Phone       *string `json:"phone,omitempty"`
	JobTitle    *string `json:"jobTitle,omitempty"`
	Password    *string `json:"password,omitempty"`
	Role        *string `json:"role,omitempty"`
	TOTPEnabled *bool   `json:"totpEnabled,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

// UpdateProfileParams updates the current user's own profile. CurrentPassword is
// required; set NewPassword and ConfirmPassword together to change the password.
type UpdateProfileParams struct {
	CurrentPassword string  `json:"currentPassword"`
	NewPassword     string  `json:"newPassword,omitempty"`
	ConfirmPassword string  `json:"confirmPassword,omitempty"`
	Username        string  `json:"username,omitempty"`
	Firstname       string  `json:"firstname,omitempty"`
	Lastname        string  `json:"lastname,omitempty"`
	Email           *string `json:"email,omitempty"`
	Phone           *string `json:"phone,omitempty"`
	JobTitle        *string `json:"jobTitle,omitempty"`
}

// TOTPSetup carries the data needed to enable two-factor authentication.
type TOTPSetup struct {
	QRCode string `json:"totpQrUrl,omitempty"`
	Secret string `json:"totpSecret,omitempty"`
}

// TOTPEnableParams enables TOTP using the secret from GetTOTP and a current code.
type TOTPEnableParams struct {
	Secret string `json:"totpSecret"`
	Token  string `json:"totpToken"`
}

// TOTPDisableParams disables TOTP using a current code.
type TOTPDisableParams struct {
	Token string `json:"totpToken"`
}

// UsersService manages user accounts.
type UsersService struct{ c *Client }

// List returns all users.
func (s *UsersService) List(ctx context.Context) ([]User, error) {
	return call[[]User](ctx, s.c, apiReq{method: http.MethodGet, path: "/users", op: "Users.List"})
}

// Reviewers returns all users permitted to review audits.
func (s *UsersService) Reviewers(ctx context.Context) ([]User, error) {
	return call[[]User](ctx, s.c, apiReq{method: http.MethodGet, path: "/users/reviewers", op: "Users.Reviewers"})
}

// Me returns the currently authenticated user.
func (s *UsersService) Me(ctx context.Context) (*User, error) {
	u, err := call[User](ctx, s.c, apiReq{method: http.MethodGet, path: "/users/me", op: "Users.Me"})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// Get returns a user by username.
func (s *UsersService) Get(ctx context.Context, username string) (*User, error) {
	if username == "" {
		return nil, opEmptyID("Users.Get")
	}
	u, err := call[User](ctx, s.c, apiReq{method: http.MethodGet, path: "/users/" + pathID(username), op: "Users.Get"})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// Create creates a user and returns the stored record (re-read by username,
// since pwndoc returns only a status message).
func (s *UsersService) Create(ctx context.Context, p CreateUserParams) (*User, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPost, path: "/users", body: p, op: "Users.Create"}); err != nil {
		return nil, err
	}
	return s.Get(ctx, p.Username)
}

// Update updates another user (admin) and returns the stored record.
func (s *UsersService) Update(ctx context.Context, id string, p UpdateUserParams) (*User, error) {
	if id == "" {
		return nil, opEmptyID("Users.Update")
	}
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/users/" + pathID(id), body: p, op: "Users.Update"}); err != nil {
		return nil, err
	}
	if users, err := s.List(ctx); err == nil {
		for i := range users {
			if users[i].ID == id {
				return &users[i], nil
			}
		}
	}
	// The update succeeded; fall back to a minimal record so callers never get
	// a (nil, nil) result to dereference.
	return &User{ID: id}, nil
}

// UpdateMe updates the current user's own profile. On success the rotated access
// token is stored automatically.
func (s *UsersService) UpdateMe(ctx context.Context, p UpdateProfileParams) (*User, error) {
	tok, err := call[sessionTokens](ctx, s.c, apiReq{method: http.MethodPut, path: "/users/me", body: p, op: "Users.UpdateMe"})
	if err != nil {
		return nil, err
	}
	if tok.Token != "" {
		s.c.setTokens(tok.Token, "")
	}
	return s.Me(ctx)
}

// InitRequired reports whether the instance has no users yet and therefore needs
// its first (admin) user created with Init.
func (s *UsersService) InitRequired(ctx context.Context) (bool, error) {
	return call[bool](ctx, s.c, apiReq{method: http.MethodGet, path: "/users/init", op: "Users.InitRequired"})
}

// Init creates the first user on a fresh instance (always an admin) and logs the
// client in. It fails if the instance is already initialized.
func (s *UsersService) Init(ctx context.Context, p CreateUserParams) (*User, error) {
	tok, err := call[sessionTokens](ctx, s.c, apiReq{method: http.MethodPost, path: "/users/init", body: p, op: "Users.Init"})
	if err != nil {
		return nil, err
	}
	s.c.setTokens(tok.Token, tok.RefreshToken)
	return s.Me(ctx)
}

// GetTOTP returns the QR-code URL and secret for enabling TOTP on the current
// account.
func (s *UsersService) GetTOTP(ctx context.Context) (*TOTPSetup, error) {
	t, err := call[TOTPSetup](ctx, s.c, apiReq{method: http.MethodGet, path: "/users/totp", op: "Users.GetTOTP"})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// EnableTOTP enables TOTP on the current account.
func (s *UsersService) EnableTOTP(ctx context.Context, p TOTPEnableParams) error {
	return callNoContent(ctx, s.c, apiReq{method: http.MethodPost, path: "/users/totp", body: p, op: "Users.EnableTOTP"})
}

// DisableTOTP disables TOTP on the current account.
func (s *UsersService) DisableTOTP(ctx context.Context, p TOTPDisableParams) error {
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/users/totp", body: p, op: "Users.DisableTOTP"})
}
