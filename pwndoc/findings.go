package pwndoc

import (
	"context"
	"net/http"
)

// Finding is a vulnerability finding within an audit. The rich-text fields
// (Description, Observation, Remediation, POC) are HTML; embed images in them
// with <img src="<imageID>" alt="<caption>"> — see AttachImageToFinding and
// AddFindingWithImages for helpers that do this for you.
type Finding struct {
	ID                    string                `json:"_id,omitempty"`
	Identifier            int                   `json:"identifier,omitempty"` // server-assigned
	Title                 string                `json:"title"`                // required
	VulnType              string                `json:"vulnType,omitempty"`
	Description           string                `json:"description,omitempty"` // HTML
	Observation           string                `json:"observation,omitempty"` // HTML
	Remediation           string                `json:"remediation,omitempty"` // HTML
	RemediationComplexity RemediationComplexity `json:"remediationComplexity,omitempty"`
	Priority              Priority              `json:"priority,omitempty"`
	References            []string              `json:"references,omitempty"`
	CVSSv3                string                `json:"cvssv3,omitempty"`
	CVSSv4                string                `json:"cvssv4,omitempty"`
	POC                   string                `json:"poc,omitempty"` // HTML (proof of concept)
	Scope                 string                `json:"scope,omitempty"`
	Status                *FindingStatus        `json:"status,omitempty"` // pointer: 0=Done is meaningful
	Category              string                `json:"category,omitempty"`
	CustomFields          []CustomFieldValue    `json:"customFields,omitempty"`
	Paragraphs            []Paragraph           `json:"paragraphs,omitempty"`
	RetestStatus          RetestStatus          `json:"retestStatus,omitempty"`
	RetestDescription     string                `json:"retestDescription,omitempty"`
}

// Paragraph is one block of finding prose plus its inline images. pwndoc derives
// paragraphs from the HTML rich-text fields at report-generation time, so this
// is primarily a read model — set images by embedding <img> tags in the HTML
// fields rather than by populating Paragraphs.
type Paragraph struct {
	Text   string           `json:"text,omitempty"`
	Images []ParagraphImage `json:"images,omitempty"`
}

// ParagraphImage links an image reference to its caption.
type ParagraphImage struct {
	Image   string `json:"image"`
	Caption string `json:"caption,omitempty"`
}

// FindingsService manages the findings of an audit.
type FindingsService struct{ c *Client }

// List returns all findings of an audit. (pwndoc has no findings-list endpoint;
// this reads the audit and returns its findings.)
func (s *FindingsService) List(ctx context.Context, auditID string) ([]Finding, error) {
	if auditID == "" {
		return nil, opEmptyID("Findings.List")
	}
	a, err := s.c.Audits.Get(ctx, auditID)
	if err != nil {
		return nil, err
	}
	return a.Findings, nil
}

// Create adds a finding to an audit. Title is required. pwndoc returns only a
// status message on create, so the audit is re-read to return the stored
// finding (with its server-assigned id and identifier).
func (s *FindingsService) Create(ctx context.Context, auditID string, f Finding) (*Finding, error) {
	if auditID == "" {
		return nil, opEmptyID("Findings.Create")
	}
	if err := callNoContent(ctx, s.c, apiReq{
		method: http.MethodPost, path: "/audits/" + pathID(auditID) + "/findings", body: f, op: "Findings.Create",
	}); err != nil {
		return nil, err
	}
	a, err := s.c.Audits.Get(ctx, auditID)
	if err != nil {
		return nil, err
	}
	if created := newestFindingByTitle(a.Findings, f.Title); created != nil {
		return created, nil
	}
	out := f
	return &out, nil
}

// Get returns a single finding of an audit.
func (s *FindingsService) Get(ctx context.Context, auditID, findingID string) (*Finding, error) {
	if auditID == "" || findingID == "" {
		return nil, opEmptyID("Findings.Get")
	}
	f, err := call[Finding](ctx, s.c, apiReq{
		method: http.MethodGet, path: "/audits/" + pathID(auditID) + "/findings/" + pathID(findingID), op: "Findings.Get",
	})
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// Update updates a finding and returns the stored result (re-read, since pwndoc
// returns only a status message).
func (s *FindingsService) Update(ctx context.Context, auditID, findingID string, f Finding) (*Finding, error) {
	if auditID == "" || findingID == "" {
		return nil, opEmptyID("Findings.Update")
	}
	if err := callNoContent(ctx, s.c, apiReq{
		method: http.MethodPut, path: "/audits/" + pathID(auditID) + "/findings/" + pathID(findingID), body: f, op: "Findings.Update",
	}); err != nil {
		return nil, err
	}
	return s.Get(ctx, auditID, findingID)
}

// Delete removes a finding from an audit.
func (s *FindingsService) Delete(ctx context.Context, auditID, findingID string) error {
	if auditID == "" || findingID == "" {
		return opEmptyID("Findings.Delete")
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodDelete, path: "/audits/" + pathID(auditID) + "/findings/" + pathID(findingID), op: "Findings.Delete",
	})
}

// CreateFromVulnerability imports a vulnerability from the template database
// into the audit as a new finding, using the given locale's details.
func (s *FindingsService) CreateFromVulnerability(ctx context.Context, auditID, locale, vulnID string) (*Finding, error) {
	if auditID == "" || vulnID == "" {
		return nil, opEmptyID("Findings.CreateFromVulnerability")
	}
	vulns, err := s.c.Vulnerabilities.List(ctx)
	if err != nil {
		return nil, err
	}
	var vuln *Vulnerability
	for i := range vulns {
		if vulns[i].ID == vulnID {
			vuln = &vulns[i]
			break
		}
	}
	if vuln == nil {
		return nil, &APIError{Op: "Findings.CreateFromVulnerability", StatusCode: http.StatusNotFound,
			Message: "vulnerability " + vulnID + " not found"}
	}
	f := findingFromVulnerability(*vuln, locale)
	return s.Create(ctx, auditID, f)
}

// newestFindingByTitle returns the matching finding with the highest identifier.
func newestFindingByTitle(findings []Finding, title string) *Finding {
	var best *Finding
	for i := range findings {
		if findings[i].Title != title {
			continue
		}
		if best == nil || findings[i].Identifier >= best.Identifier {
			best = &findings[i]
		}
	}
	return best
}

// findingFromVulnerability maps a template vulnerability (for one locale) onto a
// new finding payload.
func findingFromVulnerability(v Vulnerability, locale string) Finding {
	f := Finding{
		CVSSv3:                v.CVSSv3,
		CVSSv4:                v.CVSSv4,
		Priority:              v.Priority,
		RemediationComplexity: v.RemediationComplexity,
		Category:              v.Category,
	}
	var detail *VulnDetail
	for i := range v.Details {
		if v.Details[i].Locale == locale {
			detail = &v.Details[i]
			break
		}
	}
	if detail == nil && len(v.Details) > 0 {
		detail = &v.Details[0]
	}
	if detail != nil {
		f.Title = detail.Title
		f.VulnType = detail.VulnType
		f.Description = detail.Description
		f.Observation = detail.Observation
		f.Remediation = detail.Remediation
		f.References = detail.References
		f.CustomFields = detail.CustomFields
	}
	return f
}
