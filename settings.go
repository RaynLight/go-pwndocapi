package pwndoc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// Settings is the instance settings document. Because the document is large and
// version-dependent, the full JSON blob is preserved in Raw so that a
// get-mutate-update round-trip never clobbers keys this library does not model.
// The typed fields (e.g. report.public.captions) are overlaid back onto Raw on
// marshal.
type Settings struct {
	Report ReportSettings `json:"report"`

	// Raw holds the full settings JSON for lossless round-trips.
	Raw json.RawMessage `json:"-"`
}

// ReportSettings is the report section of the settings.
type ReportSettings struct {
	Public ReportPublicSettings `json:"public"`
}

// ReportPublicSettings carries the public report settings this library models
// explicitly. Other keys are preserved via Settings.Raw.
type ReportPublicSettings struct {
	Captions []string `json:"captions,omitempty"` // figure caption labels, e.g. ["Figure"]
}

// UnmarshalJSON decodes the typed fields and preserves the full blob in Raw.
func (s *Settings) UnmarshalJSON(data []byte) error {
	s.Raw = append(json.RawMessage(nil), data...)
	type alias Settings
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	s.Report = a.Report
	return nil
}

// MarshalJSON overlays the typed fields onto the preserved Raw blob.
func (s Settings) MarshalJSON() ([]byte, error) {
	base := map[string]any{}
	if len(s.Raw) > 0 {
		if err := json.Unmarshal(s.Raw, &base); err != nil {
			return nil, err
		}
	}
	report, _ := base["report"].(map[string]any)
	if report == nil {
		report = map[string]any{}
	}
	public, _ := report["public"].(map[string]any)
	if public == nil {
		public = map[string]any{}
	}
	public["captions"] = s.Report.Public.Captions
	report["public"] = public
	base["report"] = report
	return json.Marshal(base)
}

// SettingsService reads and updates instance settings.
type SettingsService struct{ c *Client }

// Get returns the full settings document.
func (s *SettingsService) Get(ctx context.Context) (*Settings, error) {
	out, err := call[Settings](ctx, s.c, apiReq{method: http.MethodGet, path: "/settings", op: "Settings.Get"})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// GetPublic returns the public subset of the settings.
func (s *SettingsService) GetPublic(ctx context.Context) (*Settings, error) {
	out, err := call[Settings](ctx, s.c, apiReq{method: http.MethodGet, path: "/settings/public", op: "Settings.GetPublic"})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Update saves the settings and returns the stored result. Get, mutate, then
// Update for a forward-compatible round-trip.
func (s *SettingsService) Update(ctx context.Context, in Settings) (*Settings, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/settings", body: in, op: "Settings.Update"}); err != nil {
		return nil, err
	}
	return s.Get(ctx)
}

// Revert restores the default settings.
func (s *SettingsService) Revert(ctx context.Context) (*Settings, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/settings/revert", op: "Settings.Revert"}); err != nil {
		return nil, err
	}
	return s.Get(ctx)
}

// Export returns the settings as JSON bytes.
func (s *SettingsService) Export(ctx context.Context) ([]byte, error) {
	return callRawBytes(ctx, s.c, apiReq{method: http.MethodGet, path: "/settings/export", op: "Settings.Export"})
}

// ExportTo streams the settings JSON to w.
func (s *SettingsService) ExportTo(ctx context.Context, w io.Writer) error {
	return callRawTo(ctx, s.c, apiReq{method: http.MethodGet, path: "/settings/export", op: "Settings.ExportTo"}, w)
}

// Captions returns the configured figure caption labels (report.public.captions).
func (s *SettingsService) Captions(ctx context.Context) ([]string, error) {
	st, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}
	return st.Report.Public.Captions, nil
}

// SetCaptions sets the figure caption labels, preserving all other settings.
func (s *SettingsService) SetCaptions(ctx context.Context, labels []string) error {
	st, err := s.Get(ctx)
	if err != nil {
		return err
	}
	st.Report.Public.Captions = labels
	_, err = s.Update(ctx, *st)
	return err
}
