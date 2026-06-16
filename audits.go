package pwndoc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AuditSummary is the condensed audit shape returned by List/Children.
type AuditSummary struct {
	ID            string    `json:"_id"`
	Name          string    `json:"name"`
	Language      string    `json:"language,omitempty"`
	AuditType     string    `json:"auditType,omitempty"`
	Type          AuditMode `json:"type,omitempty"`
	Company       *Company  `json:"company,omitempty"`
	Collaborators []User    `json:"collaborators,omitempty"`
	ParentID      string    `json:"parentId,omitempty"`
	State         string    `json:"state,omitempty"`
	CreatedAt     time.Time `json:"createdAt,omitempty"`
}

// Audit is the full audit (engagement) document.
type Audit struct {
	ID            string             `json:"_id,omitempty"`
	Name          string             `json:"name"`
	Language      string             `json:"language,omitempty"`
	AuditType     string             `json:"auditType,omitempty"`
	Type          AuditMode          `json:"type,omitempty"`
	ParentID      string             `json:"parentId,omitempty"`
	Date          string             `json:"date,omitempty"`
	DateStart     string             `json:"date_start,omitempty"`
	DateEnd       string             `json:"date_end,omitempty"`
	Client        *Contact           `json:"client,omitempty"`
	Company       *Company           `json:"company,omitempty"`
	Collaborators []User             `json:"collaborators,omitempty"`
	Reviewers     []User             `json:"reviewers,omitempty"`
	Scope         []ScopeHost        `json:"scope,omitempty"`
	Findings      []Finding          `json:"findings,omitempty"`
	Sections      []SectionData      `json:"sections,omitempty"`
	Template      string             `json:"template,omitempty"`
	CustomFields  []CustomFieldValue `json:"customFields,omitempty"`
	State         string             `json:"state,omitempty"`
	Approvals     []User             `json:"approvals,omitempty"`
	CreatedAt     time.Time          `json:"createdAt,omitempty"`
	UpdatedAt     time.Time          `json:"updatedAt,omitempty"`
}

// CreateAuditParams are the fields for creating an audit. Name, Language and
// AuditType are required.
type CreateAuditParams struct {
	Name      string    `json:"name"`
	Language  string    `json:"language"`
	AuditType string    `json:"auditType"`
	Type      AuditMode `json:"type,omitempty"`     // default|multi
	ParentID  string    `json:"parentId,omitempty"` // only for default-type children
}

// AuditListFilter maps the ?findingTitle= and ?type= query params. A nil filter
// applies none.
type AuditListFilter struct {
	FindingTitle string
	Type         string // default|multi
}

// AuditGeneral is the PUT /general body. Pointer scalar fields distinguish
// "unset" (leave as-is) from "set to empty".
type AuditGeneral struct {
	Name          *string            `json:"name,omitempty"`
	Date          *string            `json:"date,omitempty"`
	DateStart     *string            `json:"date_start,omitempty"`
	DateEnd       *string            `json:"date_end,omitempty"`
	Client        *Contact           `json:"client,omitempty"`
	Company       *CompanyRef        `json:"company,omitempty"` // {_id} or {name}
	Collaborators []User             `json:"collaborators,omitempty"`
	Reviewers     []User             `json:"reviewers,omitempty"`
	Language      *string            `json:"language,omitempty"`
	Scope         []ScopeHost        `json:"scope,omitempty"`
	Template      *string            `json:"template,omitempty"`
	CustomFields  []CustomFieldValue `json:"customFields,omitempty"`
}

// CompanyRef references a company by id or name (PUT /general accepts either).
type CompanyRef struct {
	ID   string `json:"_id,omitempty"`
	Name string `json:"name,omitempty"`
}

// ScopeHost is one named scope entry with optional discovered hosts.
type ScopeHost struct {
	Name  string `json:"name"`
	Hosts []Host `json:"hosts,omitempty"`
}

// Host is a discovered network host within a scope entry.
type Host struct {
	IP       string    `json:"ip,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	OS       string    `json:"os,omitempty"`
	Services []Service `json:"services,omitempty"`
}

// Service is a network service on a Host.
type Service struct {
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // tcp|udp
	Name     string `json:"name,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

// AuditNetwork is the audit's network scope (GET/PUT /network).
type AuditNetwork struct {
	Scope []ScopeHost `json:"scope,omitempty"`
}

// SectionData is a custom section of an audit (its per-section custom fields).
type SectionData struct {
	ID           string             `json:"_id,omitempty"`
	Field        string             `json:"field,omitempty"`
	Name         string             `json:"name,omitempty"`
	Text         string             `json:"text,omitempty"`
	CustomFields []CustomFieldValue `json:"customFields,omitempty"`
}

// SortFindingsParams configures finding sort order for an audit.
type SortFindingsParams struct {
	SortOrder string    `json:"sortOrder,omitempty"` // asc|desc
	SortField string    `json:"sortField,omitempty"`
	SortAuto  bool      `json:"sortAuto,omitempty"`
	Findings  []Finding `json:"findings,omitempty"`
}

// Comment is a review comment on a finding or section, with nested replies.
type Comment struct {
	ID        string    `json:"_id,omitempty"`
	FindingID string    `json:"findingId,omitempty"`
	SectionID string    `json:"sectionId,omitempty"`
	FieldName string    `json:"fieldName,omitempty"`
	Author    string    `json:"author,omitempty"`
	Text      string    `json:"text,omitempty"`
	Replies   []Comment `json:"replies,omitempty"`
	Resolved  bool      `json:"resolved,omitempty"`
}

// RetestParams configures retest creation.
type RetestParams struct {
	AuditType string `json:"auditType,omitempty"`
}

// Report bundles a generated .docx with its metadata.
type Report struct {
	Filename    string
	ContentType string
	Data        []byte
}

// AuditsService manages audits and everything nested under them.
type AuditsService struct{ c *Client }

type createAuditResponse struct {
	Message string `json:"message"`
	Audit   Audit  `json:"audit"`
}

// Create creates an audit and returns the created document.
func (s *AuditsService) Create(ctx context.Context, p CreateAuditParams) (*Audit, error) {
	r, err := call[createAuditResponse](ctx, s.c, apiReq{
		method: http.MethodPost, path: "/audits", body: p, op: "Audits.Create",
	})
	if err != nil {
		return nil, err
	}
	return &r.Audit, nil
}

// List returns audits visible to the current user, optionally filtered.
func (s *AuditsService) List(ctx context.Context, f *AuditListFilter) ([]AuditSummary, error) {
	q := map[string]string{}
	if f != nil {
		q["findingTitle"], q["type"] = f.FindingTitle, f.Type
	}
	return call[[]AuditSummary](ctx, s.c, apiReq{
		method: http.MethodGet, path: "/audits", query: q, op: "Audits.List",
	})
}

// Get returns the full audit by id.
func (s *AuditsService) Get(ctx context.Context, id string) (*Audit, error) {
	if id == "" {
		return nil, opEmptyID("Audits.Get")
	}
	a, err := call[Audit](ctx, s.c, apiReq{
		method: http.MethodGet, path: "/audits/" + pathID(id), op: "Audits.Get",
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// Delete deletes the audit by id.
func (s *AuditsService) Delete(ctx context.Context, id string) error {
	if id == "" {
		return opEmptyID("Audits.Delete")
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodDelete, path: "/audits/" + pathID(id), op: "Audits.Delete",
	})
}

// UpdateGeneral updates an audit's general information (name, dates, company,
// client, scope, collaborators, reviewers, template, custom fields).
func (s *AuditsService) UpdateGeneral(ctx context.Context, id string, g AuditGeneral) error {
	if id == "" {
		return opEmptyID("Audits.UpdateGeneral")
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodPut, path: "/audits/" + pathID(id) + "/general", body: g, op: "Audits.UpdateGeneral",
	})
}

// GetNetwork returns the audit's network scope.
func (s *AuditsService) GetNetwork(ctx context.Context, id string) (*AuditNetwork, error) {
	if id == "" {
		return nil, opEmptyID("Audits.GetNetwork")
	}
	n, err := call[AuditNetwork](ctx, s.c, apiReq{
		method: http.MethodGet, path: "/audits/" + pathID(id) + "/network", op: "Audits.GetNetwork",
	})
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// UpdateNetwork replaces the audit's network scope (e.g. to import nmap data).
func (s *AuditsService) UpdateNetwork(ctx context.Context, id string, n AuditNetwork) error {
	if id == "" {
		return opEmptyID("Audits.UpdateNetwork")
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodPut, path: "/audits/" + pathID(id) + "/network", body: n, op: "Audits.UpdateNetwork",
	})
}

// GetSection returns a custom section of the audit.
func (s *AuditsService) GetSection(ctx context.Context, id, sectionID string) (*SectionData, error) {
	if id == "" || sectionID == "" {
		return nil, opEmptyID("Audits.GetSection")
	}
	sec, err := call[SectionData](ctx, s.c, apiReq{
		method: http.MethodGet, path: "/audits/" + pathID(id) + "/sections/" + pathID(sectionID), op: "Audits.GetSection",
	})
	if err != nil {
		return nil, err
	}
	return &sec, nil
}

// UpdateSection updates a custom section's custom fields (and optional text).
func (s *AuditsService) UpdateSection(ctx context.Context, id, sectionID string, data SectionData) error {
	if id == "" || sectionID == "" {
		return opEmptyID("Audits.UpdateSection")
	}
	if data.CustomFields == nil {
		data.CustomFields = []CustomFieldValue{}
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodPut, path: "/audits/" + pathID(id) + "/sections/" + pathID(sectionID), body: data, op: "Audits.UpdateSection",
	})
}

// SortFindings updates the audit's finding sort options.
func (s *AuditsService) SortFindings(ctx context.Context, id string, p SortFindingsParams) error {
	if id == "" {
		return opEmptyID("Audits.SortFindings")
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodPut, path: "/audits/" + pathID(id) + "/sortfindings", body: p, op: "Audits.SortFindings",
	})
}

// MoveFinding moves a finding from oldIndex to newIndex.
func (s *AuditsService) MoveFinding(ctx context.Context, id string, oldIndex, newIndex int) error {
	if id == "" {
		return opEmptyID("Audits.MoveFinding")
	}
	body := map[string]int{"oldIndex": oldIndex, "newIndex": newIndex}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodPut, path: "/audits/" + pathID(id) + "/movefinding", body: body, op: "Audits.MoveFinding",
	})
}

// AddComment adds a comment to a finding or section. Set exactly one of
// comment.FindingID or comment.SectionID, plus FieldName and Author (user id).
func (s *AuditsService) AddComment(ctx context.Context, id string, comment Comment) (*Comment, error) {
	if id == "" {
		return nil, opEmptyID("Audits.AddComment")
	}
	body := map[string]any{
		"fieldName": comment.FieldName,
		"authorId":  comment.Author,
		"text":      comment.Text,
	}
	if comment.FindingID != "" {
		body["findingId"] = comment.FindingID
	}
	if comment.SectionID != "" {
		body["sectionId"] = comment.SectionID
	}
	if comment.ID != "" {
		body["commentId"] = comment.ID
	}
	out, err := call[Comment](ctx, s.c, apiReq{
		method: http.MethodPost, path: "/audits/" + pathID(id) + "/comments", body: body, op: "Audits.AddComment",
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateComment updates a comment's text, replies or resolved state.
func (s *AuditsService) UpdateComment(ctx context.Context, id, commentID string, comment Comment) (*Comment, error) {
	if id == "" || commentID == "" {
		return nil, opEmptyID("Audits.UpdateComment")
	}
	body := map[string]any{"text": comment.Text, "resolved": comment.Resolved}
	if comment.Replies != nil {
		body["replies"] = comment.Replies
	}
	out, err := call[Comment](ctx, s.c, apiReq{
		method: http.MethodPut, path: "/audits/" + pathID(id) + "/comments/" + pathID(commentID), body: body, op: "Audits.UpdateComment",
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteComment deletes a comment.
func (s *AuditsService) DeleteComment(ctx context.Context, id, commentID string) error {
	if id == "" || commentID == "" {
		return opEmptyID("Audits.DeleteComment")
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodDelete, path: "/audits/" + pathID(id) + "/comments/" + pathID(commentID), op: "Audits.DeleteComment",
	})
}

// GetRetest returns the retest audit linked to the given audit, if any.
func (s *AuditsService) GetRetest(ctx context.Context, id string) (*Audit, error) {
	if id == "" {
		return nil, opEmptyID("Audits.GetRetest")
	}
	a, err := call[Audit](ctx, s.c, apiReq{
		method: http.MethodGet, path: "/audits/" + pathID(id) + "/retest", op: "Audits.GetRetest",
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// CreateRetest creates a retest of the given audit.
func (s *AuditsService) CreateRetest(ctx context.Context, id string, p RetestParams) (*Audit, error) {
	if id == "" {
		return nil, opEmptyID("Audits.CreateRetest")
	}
	r, err := call[createAuditResponse](ctx, s.c, apiReq{
		method: http.MethodPost, path: "/audits/" + pathID(id) + "/retest", body: p, op: "Audits.CreateRetest",
	})
	if err != nil {
		return nil, err
	}
	return &r.Audit, nil
}

// Children returns the child audits of a multi-audit.
func (s *AuditsService) Children(ctx context.Context, id string) ([]AuditSummary, error) {
	if id == "" {
		return nil, opEmptyID("Audits.Children")
	}
	return call[[]AuditSummary](ctx, s.c, apiReq{
		method: http.MethodGet, path: "/audits/" + pathID(id) + "/children", op: "Audits.Children",
	})
}

// UpdateParent sets the audit's parent (linking it into a multi-audit).
func (s *AuditsService) UpdateParent(ctx context.Context, id, parentID string) error {
	if id == "" || parentID == "" {
		return opEmptyID("Audits.UpdateParent")
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodPut, path: "/audits/" + pathID(id) + "/updateParent", body: map[string]string{"parentId": parentID}, op: "Audits.UpdateParent",
	})
}

// DeleteParent removes the audit's parent link.
func (s *AuditsService) DeleteParent(ctx context.Context, id string) error {
	if id == "" {
		return opEmptyID("Audits.DeleteParent")
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodDelete, path: "/audits/" + pathID(id) + "/deleteParent", op: "Audits.DeleteParent",
	})
}

// ToggleApproval toggles the current reviewer's approval on the audit.
func (s *AuditsService) ToggleApproval(ctx context.Context, id string) error {
	if id == "" {
		return opEmptyID("Audits.ToggleApproval")
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodPut, path: "/audits/" + pathID(id) + "/toggleApproval", op: "Audits.ToggleApproval",
	})
}

// UpdateReadyForReview moves the audit between EDIT and REVIEW states.
func (s *AuditsService) UpdateReadyForReview(ctx context.Context, id string, ready bool) error {
	if id == "" {
		return opEmptyID("Audits.UpdateReadyForReview")
	}
	state := "EDIT"
	if ready {
		state = "REVIEW"
	}
	return callNoContent(ctx, s.c, apiReq{
		method: http.MethodPut, path: "/audits/" + pathID(id) + "/updateReadyForReview", body: map[string]string{"state": state}, op: "Audits.UpdateReadyForReview",
	})
}

// Generate generates the audit's .docx report into memory.
func (s *AuditsService) Generate(ctx context.Context, id string) (*Report, error) {
	if id == "" {
		return nil, opEmptyID("Audits.Generate")
	}
	b, err := callRawBytes(ctx, s.c, apiReq{
		method: http.MethodGet, path: "/audits/" + pathID(id) + "/generate", op: "Audits.Generate",
	})
	if err != nil {
		return nil, err
	}
	return &Report{
		Filename:    "report-" + id + ".docx",
		ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		Data:        b,
	}, nil
}

// GenerateTo streams the audit's .docx report to w.
func (s *AuditsService) GenerateTo(ctx context.Context, id string, w io.Writer) error {
	if id == "" {
		return opEmptyID("Audits.GenerateTo")
	}
	return callRawTo(ctx, s.c, apiReq{
		method: http.MethodGet, path: "/audits/" + pathID(id) + "/generate", op: "Audits.GenerateTo",
	}, w)
}

// opEmptyID builds a uniform "empty id" error wrapping ErrEmptyID.
func opEmptyID(op string) error {
	return fmt.Errorf("pwndoc: %s: %w", op, ErrEmptyID)
}
