package pwndoc

import (
	"context"
	"encoding/json"
	"net/http"
)

// Vulnerability is a reusable entry in the vulnerability template database. Its
// localized content lives in Details (one per locale).
type Vulnerability struct {
	ID                    string                `json:"_id,omitempty"`
	CVSSv3                string                `json:"cvssv3,omitempty"`
	CVSSv4                string                `json:"cvssv4,omitempty"`
	Priority              Priority              `json:"priority,omitempty"`
	RemediationComplexity RemediationComplexity `json:"remediationComplexity,omitempty"`
	Category              string                `json:"category,omitempty"`
	Details               []VulnDetail          `json:"details,omitempty"`
	Status                int                   `json:"status,omitempty"`
}

// VulnDetail is the localized content of a vulnerability.
type VulnDetail struct {
	Locale       string             `json:"locale"`
	Title        string             `json:"title,omitempty"`
	VulnType     string             `json:"vulnType,omitempty"`
	Description  string             `json:"description,omitempty"`
	Observation  string             `json:"observation,omitempty"`
	Remediation  string             `json:"remediation,omitempty"`
	References   []string           `json:"references,omitempty"`
	CustomFields []CustomFieldValue `json:"customFields,omitempty"`
}

// MergeParams configures a vulnerability merge: VulnID is the source vulnerability
// whose Locale content is merged into the target.
type MergeParams struct {
	VulnID string `json:"vulnId"`
	Locale string `json:"locale"`
}

// VulnerabilitiesService manages the reusable vulnerability template database.
type VulnerabilitiesService struct{ c *Client }

// List returns all vulnerabilities (full, with all locales).
func (s *VulnerabilitiesService) List(ctx context.Context) ([]Vulnerability, error) {
	return call[[]Vulnerability](ctx, s.c, apiReq{method: http.MethodGet, path: "/vulnerabilities", op: "Vulnerabilities.List"})
}

// ListByLocale returns vulnerabilities flattened to a single locale's content.
func (s *VulnerabilitiesService) ListByLocale(ctx context.Context, locale string) ([]Vulnerability, error) {
	if locale == "" {
		return nil, opEmptyID("Vulnerabilities.ListByLocale")
	}
	return call[[]Vulnerability](ctx, s.c, apiReq{method: http.MethodGet, path: "/vulnerabilities/" + pathID(locale), op: "Vulnerabilities.ListByLocale"})
}

// Create bulk-creates vulnerabilities. Each must have at least one detail with a
// locale and title.
func (s *VulnerabilitiesService) Create(ctx context.Context, v []Vulnerability) ([]Vulnerability, error) {
	raw, err := call[json.RawMessage](ctx, s.c, apiReq{method: http.MethodPost, path: "/vulnerabilities", body: v, op: "Vulnerabilities.Create"})
	if err != nil {
		return nil, err
	}
	var out []Vulnerability
	_ = json.Unmarshal(raw, &out) // server may return the created docs or a count
	return out, nil
}

// Update updates a vulnerability by id.
func (s *VulnerabilitiesService) Update(ctx context.Context, id string, v Vulnerability) (*Vulnerability, error) {
	if id == "" {
		return nil, opEmptyID("Vulnerabilities.Update")
	}
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/vulnerabilities/" + pathID(id), body: v, op: "Vulnerabilities.Update"}); err != nil {
		return nil, err
	}
	v.ID = id
	return &v, nil
}

// Delete deletes a vulnerability by id.
func (s *VulnerabilitiesService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return opEmptyID("Vulnerabilities.Delete")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/vulnerabilities/" + pathID(id), op: "Vulnerabilities.Delete"})
}

// DeleteAll deletes every vulnerability in the database.
func (s *VulnerabilitiesService) DeleteAll(ctx context.Context) error {
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/vulnerabilities", op: "Vulnerabilities.DeleteAll"})
}

// Export returns the full vulnerability database as JSON bytes (suitable for a
// backup or for re-import via Create).
func (s *VulnerabilitiesService) Export(ctx context.Context) ([]byte, error) {
	raw, err := call[json.RawMessage](ctx, s.c, apiReq{method: http.MethodGet, path: "/vulnerabilities/export", op: "Vulnerabilities.Export"})
	if err != nil {
		return nil, err
	}
	return []byte(raw), nil
}

// Updates returns the pending community updates for a vulnerability id.
func (s *VulnerabilitiesService) Updates(ctx context.Context, vulnID string) ([]Vulnerability, error) {
	if vulnID == "" {
		return nil, opEmptyID("Vulnerabilities.Updates")
	}
	return call[[]Vulnerability](ctx, s.c, apiReq{method: http.MethodGet, path: "/vulnerabilities/updates/" + pathID(vulnID), op: "Vulnerabilities.Updates"})
}

// Merge merges the source vulnerability's locale content (p.VulnID / p.Locale)
// into the target vulnerability vulnID.
func (s *VulnerabilitiesService) Merge(ctx context.Context, vulnID string, p MergeParams) error {
	if vulnID == "" {
		return opEmptyID("Vulnerabilities.Merge")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/vulnerabilities/merge/" + pathID(vulnID), body: p, op: "Vulnerabilities.Merge"})
}

// CreateFromFinding promotes a finding into the vulnerability template database
// for the given locale, returning the server's status message.
func (s *VulnerabilitiesService) CreateFromFinding(ctx context.Context, locale string, f Finding) (string, error) {
	if locale == "" {
		return "", opEmptyID("Vulnerabilities.CreateFromFinding")
	}
	return call[string](ctx, s.c, apiReq{method: http.MethodPost, path: "/vulnerabilities/finding/" + pathID(locale), body: f, op: "Vulnerabilities.CreateFromFinding"})
}
