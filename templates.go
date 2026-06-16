package pwndoc

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Template represents a Word report template.
type Template struct {
	ID   string `json:"_id,omitempty"`
	Name string `json:"name"`
	Ext  string `json:"ext,omitempty"`
	File string `json:"file,omitempty"` // base64, on create/update only
}

// CreateTemplateParams are the fields for creating or updating a template. File
// is the base64-encoded document contents (use CreateFromFile to build it).
type CreateTemplateParams struct {
	Name string `json:"name"`
	File string `json:"file,omitempty"`
	Ext  string `json:"ext,omitempty"`
}

// TemplatesService manages Word report templates.
type TemplatesService struct{ c *Client }

// List returns all report templates.
func (s *TemplatesService) List(ctx context.Context) ([]Template, error) {
	return call[[]Template](ctx, s.c, apiReq{method: http.MethodGet, path: "/templates", op: "Templates.List"})
}

// Create uploads a new template. Name, File (base64) and Ext are required.
func (s *TemplatesService) Create(ctx context.Context, p CreateTemplateParams) (*Template, error) {
	out, err := call[Template](ctx, s.c, apiReq{method: http.MethodPost, path: "/templates", body: p, op: "Templates.Create"})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateFromFile uploads a template document from disk. The extension is taken
// from the file name.
func (s *TemplatesService) CreateFromFile(ctx context.Context, name, path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pwndoc: Templates.CreateFromFile: %w", err)
	}
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	if ext == "" {
		ext = "docx"
	}
	return s.Create(ctx, CreateTemplateParams{Name: name, File: base64.StdEncoding.EncodeToString(data), Ext: ext})
}

// Update updates a template's name (and optionally its file/ext).
func (s *TemplatesService) Update(ctx context.Context, id string, p CreateTemplateParams) (*Template, error) {
	if id == "" {
		return nil, opEmptyID("Templates.Update")
	}
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/templates/" + pathID(id), body: p, op: "Templates.Update"}); err != nil {
		return nil, err
	}
	return &Template{ID: id, Name: p.Name, Ext: p.Ext}, nil
}

// Delete deletes the template by id.
func (s *TemplatesService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return opEmptyID("Templates.Delete")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/templates/" + pathID(id), op: "Templates.Delete"})
}

// Download returns the raw bytes of the template document by id.
func (s *TemplatesService) Download(ctx context.Context, id string) ([]byte, error) {
	if id == "" {
		return nil, opEmptyID("Templates.Download")
	}
	return callRawBytes(ctx, s.c, apiReq{method: http.MethodGet, path: "/templates/download/" + pathID(id), op: "Templates.Download"})
}

// DownloadTo streams the template document to w.
func (s *TemplatesService) DownloadTo(ctx context.Context, id string, w io.Writer) error {
	if id == "" {
		return opEmptyID("Templates.DownloadTo")
	}
	return callRawTo(ctx, s.c, apiReq{method: http.MethodGet, path: "/templates/download/" + pathID(id), op: "Templates.DownloadTo"}, w)
}
