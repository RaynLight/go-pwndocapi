package pwndoc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
)

// Backup describes an instance backup archive.
type Backup struct {
	Slug      string   `json:"slug,omitempty"`
	Name      string   `json:"name,omitempty"`
	Type      string   `json:"type,omitempty"`
	State     string   `json:"state,omitempty"`
	Data      []string `json:"data,omitempty"`
	Size      int64    `json:"size,omitempty"`
	CreatedAt string   `json:"createdAt,omitempty"`
}

// BackupStatus is the state of an in-progress backup or restore.
type BackupStatus struct {
	State    string `json:"state,omitempty"`
	Progress int    `json:"progress,omitempty"`
	Message  string `json:"message,omitempty"`
}

// CreateBackupParams configures a new backup. Data optionally restricts which
// data domains are included; Password encrypts the archive.
type CreateBackupParams struct {
	Name     string   `json:"name,omitempty"`
	Type     string   `json:"type,omitempty"`
	Data     []string `json:"data,omitempty"`
	Password string   `json:"password,omitempty"`
}

// RestoreParams configures a restore. Mode "revert" reverts instead of merging;
// Password decrypts an encrypted archive.
type RestoreParams struct {
	Mode     string   `json:"mode,omitempty"`
	Data     []string `json:"data,omitempty"`
	Password string   `json:"password,omitempty"`
}

// BackupsService manages instance backups.
type BackupsService struct{ c *Client }

// List returns all backups.
func (s *BackupsService) List(ctx context.Context) ([]Backup, error) {
	return call[[]Backup](ctx, s.c, apiReq{method: http.MethodGet, path: "/backups", op: "Backups.List"})
}

// Status returns the current backup/restore worker status.
func (s *BackupsService) Status(ctx context.Context) (*BackupStatus, error) {
	st, err := call[BackupStatus](ctx, s.c, apiReq{method: http.MethodGet, path: "/backups/status", op: "Backups.Status"})
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// Create requests a new backup.
func (s *BackupsService) Create(ctx context.Context, p CreateBackupParams) (*Backup, error) {
	b, err := call[Backup](ctx, s.c, apiReq{method: http.MethodPost, path: "/backups", body: p, op: "Backups.Create"})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// Restore restores the backup identified by slug.
func (s *BackupsService) Restore(ctx context.Context, slug string, p RestoreParams) error {
	if slug == "" {
		return opEmptyID("Backups.Restore")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodPost, path: "/backups/" + pathID(slug) + "/restore", body: p, op: "Backups.Restore"})
}

// Delete deletes the backup identified by slug.
func (s *BackupsService) Delete(ctx context.Context, slug string) error {
	if slug == "" {
		return opEmptyID("Backups.Delete")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/backups/" + pathID(slug), op: "Backups.Delete"})
}

// Download returns the raw .tar bytes of the backup identified by slug.
func (s *BackupsService) Download(ctx context.Context, slug string) ([]byte, error) {
	if slug == "" {
		return nil, opEmptyID("Backups.Download")
	}
	return callRawBytes(ctx, s.c, apiReq{method: http.MethodGet, path: "/backups/download/" + pathID(slug), op: "Backups.Download"})
}

// DownloadTo streams the backup .tar to w.
func (s *BackupsService) DownloadTo(ctx context.Context, slug string, w io.Writer) error {
	if slug == "" {
		return opEmptyID("Backups.DownloadTo")
	}
	return callRawTo(ctx, s.c, apiReq{method: http.MethodGet, path: "/backups/download/" + pathID(slug), op: "Backups.DownloadTo"}, w)
}

// Upload uploads a backup .tar archive read from r. filename must end in ".tar".
func (s *BackupsService) Upload(ctx context.Context, r io.Reader, filename string) (*Backup, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, filename))
	h.Set("Content-Type", "application/x-tar")
	fw, err := mw.CreatePart(h)
	if err != nil {
		return nil, fmt.Errorf("pwndoc: Backups.Upload: %w", err)
	}
	if _, err := io.Copy(fw, r); err != nil {
		return nil, fmt.Errorf("pwndoc: Backups.Upload: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("pwndoc: Backups.Upload: %w", err)
	}

	payload := buf.Bytes()
	contentType := mw.FormDataContentType()
	url := s.c.baseURL.String() + apiPrefix + "/backups/upload"

	send := func() (int, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, fmt.Errorf("pwndoc: Backups.Upload: %w", err)
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("User-Agent", s.c.userAgent)
		req.Header.Set("Accept", "application/json")
		if tok := s.c.accessTokenValue(); tok != "" {
			req.Header.Set("Cookie", "token=JWT "+tok)
		}
		resp, err := s.c.doer.Do(req)
		if err != nil {
			return 0, nil, &APIError{Op: "Backups.Upload", Method: http.MethodPost, Path: apiPrefix + "/backups/upload", Message: err.Error(), Err: err}
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body, nil
	}

	status, body, err := send()
	if err != nil {
		return nil, err
	}
	// Honor auto-refresh on a 401, mirroring the JSON transport.
	if status == http.StatusUnauthorized && s.c.autoRefresh && s.c.refreshTokenValue() != "" {
		if s.c.refresh(ctx) == nil {
			if status, body, err = send(); err != nil {
				return nil, err
			}
		}
	}
	out, derr := decodeEnvelope[Backup](body, status)
	if derr != nil {
		return nil, annotate(derr, apiReq{method: http.MethodPost, path: "/backups/upload", op: "Backups.Upload"})
	}
	return &out, nil
}
