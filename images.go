package pwndoc

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Image represents an image stored in pwndoc. Value is a data URI of the form
// "data:image/png;base64,...". When uploading, only ID is returned.
type Image struct {
	ID      string `json:"_id,omitempty"`
	Value   string `json:"value,omitempty"`
	Name    string `json:"name,omitempty"`
	AuditID string `json:"auditId,omitempty"`
}

// UploadImageParams are the fields for uploading an image. Value is a data URI;
// AuditID is optional but recommended so the image is scoped to an audit.
type UploadImageParams struct {
	Value   string `json:"value"`
	Name    string `json:"name,omitempty"`
	AuditID string `json:"auditId,omitempty"`
}

// ImagesService uploads, fetches and deletes images referenced by findings.
type ImagesService struct{ c *Client }

// Upload uploads an image from a data URI. pwndoc de-duplicates by value, so
// uploading identical bytes returns the existing image's id.
func (s *ImagesService) Upload(ctx context.Context, p UploadImageParams) (*Image, error) {
	out, err := call[Image](ctx, s.c, apiReq{method: http.MethodPost, path: "/images/", body: p, op: "Images.Upload"})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// UploadBytes uploads raw image bytes with the given MIME type and display name.
func (s *ImagesService) UploadBytes(ctx context.Context, data []byte, mimeType, name, auditID string) (*Image, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pwndoc: Images.UploadBytes: empty data")
	}
	if mimeType == "" {
		mimeType = detectMime(name, data)
	}
	return s.Upload(ctx, UploadImageParams{Value: DataURI(mimeType, data), Name: name, AuditID: auditID})
}

// UploadReader uploads an image read from r.
func (s *ImagesService) UploadReader(ctx context.Context, r io.Reader, name, mimeType, auditID string) (*Image, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("pwndoc: Images.UploadReader: %w", err)
	}
	return s.UploadBytes(ctx, data, mimeType, name, auditID)
}

// UploadFile reads an image file from disk and uploads it, inferring the MIME
// type from the file.
func (s *ImagesService) UploadFile(ctx context.Context, path, auditID string) (*Image, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pwndoc: Images.UploadFile: %w", err)
	}
	return s.UploadBytes(ctx, data, detectMime(path, data), filepath.Base(path), auditID)
}

// Get returns the image (including its data URI value) by id.
func (s *ImagesService) Get(ctx context.Context, id string) (*Image, error) {
	if id == "" {
		return nil, opEmptyID("Images.Get")
	}
	img, err := call[Image](ctx, s.c, apiReq{method: http.MethodGet, path: "/images/" + pathID(id), op: "Images.Get"})
	if err != nil {
		return nil, err
	}
	return &img, nil
}

// Download returns the decoded raw bytes of the image by id.
func (s *ImagesService) Download(ctx context.Context, id string) ([]byte, error) {
	if id == "" {
		return nil, opEmptyID("Images.Download")
	}
	return callRawBytes(ctx, s.c, apiReq{method: http.MethodGet, path: "/images/download/" + pathID(id), op: "Images.Download"})
}

// DownloadTo streams the decoded raw image bytes to w.
func (s *ImagesService) DownloadTo(ctx context.Context, id string, w io.Writer) error {
	if id == "" {
		return opEmptyID("Images.DownloadTo")
	}
	return callRawTo(ctx, s.c, apiReq{method: http.MethodGet, path: "/images/download/" + pathID(id), op: "Images.DownloadTo"}, w)
}

// Delete deletes the image by id.
func (s *ImagesService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return opEmptyID("Images.Delete")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/images/" + pathID(id), op: "Images.Delete"})
}

// DataURI builds a "data:<mime>;base64,<...>" string from raw bytes.
func DataURI(mimeType string, data []byte) string {
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	return "data:" + mimeType + ";base64," + base64.StdEncoding.EncodeToString(data)
}

// detectMime infers a MIME type from the file extension, falling back to content
// sniffing.
func detectMime(name string, data []byte) string {
	if ext := strings.ToLower(filepath.Ext(name)); ext != "" {
		if mt := mime.TypeByExtension(ext); mt != "" {
			if i := strings.IndexByte(mt, ';'); i >= 0 {
				mt = strings.TrimSpace(mt[:i])
			}
			return mt
		}
	}
	mt := http.DetectContentType(data)
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = strings.TrimSpace(mt[:i])
	}
	return mt
}
