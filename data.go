package pwndoc

import (
	"context"
	"net/http"
)

// Language is a report language (e.g. {Locale:"en", Language:"English"}).
type Language struct {
	Locale   string `json:"locale"`
	Language string `json:"language"`
}

// AuditType is a kind of audit, linking templates per locale.
type AuditType struct {
	Name      string              `json:"name"`
	Templates []AuditTypeTemplate `json:"templates,omitempty"`
	Sections  []string            `json:"sections,omitempty"`
	Hidden    []string            `json:"hidden,omitempty"` // network|findings
	Stage     string              `json:"stage,omitempty"`  // default|multi|retest
}

// AuditTypeTemplate maps a template id to a locale.
type AuditTypeTemplate struct {
	Template string `json:"template"`
	Locale   string `json:"locale"`
}

// VulnerabilityType is a category of vulnerability for a locale.
type VulnerabilityType struct {
	Name   string `json:"name"`
	Locale string `json:"locale,omitempty"`
}

// VulnerabilityCategory groups findings/vulnerabilities and controls sorting.
type VulnerabilityCategory struct {
	Name      string `json:"name"`
	SortValue string `json:"sortValue,omitempty"`
	SortOrder string `json:"sortOrder,omitempty"` // asc|desc
	SortAuto  bool   `json:"sortAuto,omitempty"`
}

// CustomSection is a reusable report section definition.
type CustomSection struct {
	Field  string `json:"field"`
	Name   string `json:"name"`
	Locale string `json:"locale,omitempty"`
	Text   string `json:"text,omitempty"`
	Icon   string `json:"icon,omitempty"`
}

// CustomField defines a custom data field shown on findings, audits, sections
// or vulnerabilities.
type CustomField struct {
	ID          string   `json:"_id,omitempty"`
	FieldType   string   `json:"fieldType"` // text|checkbox|select|space|...
	Label       string   `json:"label"`
	Display     string   `json:"display,omitempty"` // finding|audit|section|vulnerability
	DisplaySub  string   `json:"displaySub,omitempty"`
	Size        int      `json:"size,omitempty"`
	Offset      int      `json:"offset,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Description string   `json:"description,omitempty"`
	Options     []string `json:"options,omitempty"`
	Position    int      `json:"position,omitempty"`
}

// CustomFieldValue is the per-document value of a custom field.
type CustomFieldValue struct {
	CustomField string `json:"customField,omitempty"`
	Text        any    `json:"text,omitempty"` // string or []string depending on fieldType
}

// DataService manages the shared catalogs under /api/data. Per the pwndoc
// convention, the PUT endpoints replace the whole array (the Set* methods);
// Create*/Delete* operate on a single entry. Mutating methods return the
// refreshed catalog.
type DataService struct{ c *Client }

// Roles returns the list of role names defined on the instance.
func (s *DataService) Roles(ctx context.Context) ([]string, error) {
	return call[[]string](ctx, s.c, apiReq{method: http.MethodGet, path: "/data/roles", op: "Data.Roles"})
}

// --- Languages ---

func (s *DataService) Languages(ctx context.Context) ([]Language, error) {
	return call[[]Language](ctx, s.c, apiReq{method: http.MethodGet, path: "/data/languages", op: "Data.Languages"})
}

func (s *DataService) CreateLanguage(ctx context.Context, l Language) ([]Language, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPost, path: "/data/languages", body: l, op: "Data.CreateLanguage"}); err != nil {
		return nil, err
	}
	return s.Languages(ctx)
}

func (s *DataService) SetLanguages(ctx context.Context, l []Language) ([]Language, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/data/languages", body: l, op: "Data.SetLanguages"}); err != nil {
		return nil, err
	}
	return s.Languages(ctx)
}

func (s *DataService) DeleteLanguage(ctx context.Context, locale string) error {
	if locale == "" {
		return opEmptyID("Data.DeleteLanguage")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/data/languages/" + pathID(locale), op: "Data.DeleteLanguage"})
}

// --- Audit types ---

func (s *DataService) AuditTypes(ctx context.Context) ([]AuditType, error) {
	return call[[]AuditType](ctx, s.c, apiReq{method: http.MethodGet, path: "/data/audit-types", op: "Data.AuditTypes"})
}

func (s *DataService) CreateAuditType(ctx context.Context, a AuditType) ([]AuditType, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPost, path: "/data/audit-types", body: a, op: "Data.CreateAuditType"}); err != nil {
		return nil, err
	}
	return s.AuditTypes(ctx)
}

func (s *DataService) SetAuditTypes(ctx context.Context, a []AuditType) ([]AuditType, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/data/audit-types", body: a, op: "Data.SetAuditTypes"}); err != nil {
		return nil, err
	}
	return s.AuditTypes(ctx)
}

func (s *DataService) DeleteAuditType(ctx context.Context, name string) error {
	if name == "" {
		return opEmptyID("Data.DeleteAuditType")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/data/audit-types/" + pathID(name), op: "Data.DeleteAuditType"})
}

// --- Vulnerability types ---

func (s *DataService) VulnerabilityTypes(ctx context.Context) ([]VulnerabilityType, error) {
	return call[[]VulnerabilityType](ctx, s.c, apiReq{method: http.MethodGet, path: "/data/vulnerability-types", op: "Data.VulnerabilityTypes"})
}

func (s *DataService) CreateVulnerabilityType(ctx context.Context, v VulnerabilityType) ([]VulnerabilityType, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPost, path: "/data/vulnerability-types", body: v, op: "Data.CreateVulnerabilityType"}); err != nil {
		return nil, err
	}
	return s.VulnerabilityTypes(ctx)
}

func (s *DataService) SetVulnerabilityTypes(ctx context.Context, v []VulnerabilityType) ([]VulnerabilityType, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/data/vulnerability-types", body: v, op: "Data.SetVulnerabilityTypes"}); err != nil {
		return nil, err
	}
	return s.VulnerabilityTypes(ctx)
}

func (s *DataService) DeleteVulnerabilityType(ctx context.Context, name string) error {
	if name == "" {
		return opEmptyID("Data.DeleteVulnerabilityType")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/data/vulnerability-types/" + pathID(name), op: "Data.DeleteVulnerabilityType"})
}

// --- Vulnerability categories ---

func (s *DataService) VulnerabilityCategories(ctx context.Context) ([]VulnerabilityCategory, error) {
	return call[[]VulnerabilityCategory](ctx, s.c, apiReq{method: http.MethodGet, path: "/data/vulnerability-categories", op: "Data.VulnerabilityCategories"})
}

func (s *DataService) CreateVulnerabilityCategory(ctx context.Context, v VulnerabilityCategory) ([]VulnerabilityCategory, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPost, path: "/data/vulnerability-categories", body: v, op: "Data.CreateVulnerabilityCategory"}); err != nil {
		return nil, err
	}
	return s.VulnerabilityCategories(ctx)
}

func (s *DataService) SetVulnerabilityCategories(ctx context.Context, v []VulnerabilityCategory) ([]VulnerabilityCategory, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/data/vulnerability-categories", body: v, op: "Data.SetVulnerabilityCategories"}); err != nil {
		return nil, err
	}
	return s.VulnerabilityCategories(ctx)
}

func (s *DataService) DeleteVulnerabilityCategory(ctx context.Context, name string) error {
	if name == "" {
		return opEmptyID("Data.DeleteVulnerabilityCategory")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/data/vulnerability-categories/" + pathID(name), op: "Data.DeleteVulnerabilityCategory"})
}

// --- Custom sections ---

func (s *DataService) Sections(ctx context.Context) ([]CustomSection, error) {
	return call[[]CustomSection](ctx, s.c, apiReq{method: http.MethodGet, path: "/data/sections", op: "Data.Sections"})
}

func (s *DataService) CreateSection(ctx context.Context, sec CustomSection) ([]CustomSection, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPost, path: "/data/sections", body: sec, op: "Data.CreateSection"}); err != nil {
		return nil, err
	}
	return s.Sections(ctx)
}

func (s *DataService) SetSections(ctx context.Context, secs []CustomSection) ([]CustomSection, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/data/sections", body: secs, op: "Data.SetSections"}); err != nil {
		return nil, err
	}
	return s.Sections(ctx)
}

func (s *DataService) DeleteSection(ctx context.Context, field, locale string) error {
	if field == "" || locale == "" {
		return opEmptyID("Data.DeleteSection")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/data/sections/" + pathID(field) + "/" + pathID(locale), op: "Data.DeleteSection"})
}

// --- Custom fields ---

func (s *DataService) CustomFields(ctx context.Context) ([]CustomField, error) {
	return call[[]CustomField](ctx, s.c, apiReq{method: http.MethodGet, path: "/data/custom-fields", op: "Data.CustomFields"})
}

func (s *DataService) CreateCustomField(ctx context.Context, f CustomField) ([]CustomField, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPost, path: "/data/custom-fields", body: f, op: "Data.CreateCustomField"}); err != nil {
		return nil, err
	}
	return s.CustomFields(ctx)
}

func (s *DataService) SetCustomFields(ctx context.Context, f []CustomField) ([]CustomField, error) {
	if err := callNoContent(ctx, s.c, apiReq{method: http.MethodPut, path: "/data/custom-fields", body: f, op: "Data.SetCustomFields"}); err != nil {
		return nil, err
	}
	return s.CustomFields(ctx)
}

func (s *DataService) DeleteCustomField(ctx context.Context, fieldID string) error {
	if fieldID == "" {
		return opEmptyID("Data.DeleteCustomField")
	}
	return callNoContent(ctx, s.c, apiReq{method: http.MethodDelete, path: "/data/custom-fields/" + pathID(fieldID), op: "Data.DeleteCustomField"})
}
