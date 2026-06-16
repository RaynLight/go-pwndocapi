package pwndoc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// nullServer returns a success envelope with a null payload for every request,
// which lets the thin service wrappers run end-to-end (decode is skipped for a
// null datas) without needing a real instance. It exercises the request plumbing
// and argument validation of every method.
func nullClient(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","datas":null}`))
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, WithToken("tok", "ref"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func ck(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: unexpected error: %v", name, err)
	}
}

func TestServiceWrappersSmoke(t *testing.T) {
	c := nullClient(t)
	ctx := context.Background()
	id := "deadbeefdeadbeefdeadbeef"

	// Companies
	_, err := c.Companies.List(ctx)
	ck(t, "Companies.List", err)
	_, err = c.Companies.Create(ctx, Company{Name: "Acme"})
	ck(t, "Companies.Create", err)
	_, err = c.Companies.Update(ctx, id, Company{Name: "Acme2"})
	ck(t, "Companies.Update", err)
	ck(t, "Companies.Delete", c.Companies.Delete(ctx, id))
	_, err = c.Companies.FindByName(ctx, "x")
	ck(t, "Companies.FindByName", err)
	_, err = c.Companies.EnsureByName(ctx, "x")
	ck(t, "Companies.EnsureByName", err)

	// Clients
	_, err = c.Clients.List(ctx)
	ck(t, "Clients.List", err)
	_, err = c.Clients.Create(ctx, Contact{Email: "a@b.c"})
	ck(t, "Clients.Create", err)
	_, err = c.Clients.Update(ctx, id, Contact{Email: "a@b.c"})
	ck(t, "Clients.Update", err)
	ck(t, "Clients.Delete", c.Clients.Delete(ctx, id))
	_, err = c.Clients.FindByEmail(ctx, "a@b.c")
	ck(t, "Clients.FindByEmail", err)

	// Users
	_, err = c.Users.List(ctx)
	ck(t, "Users.List", err)
	_, err = c.Users.Reviewers(ctx)
	ck(t, "Users.Reviewers", err)
	_, err = c.Users.Me(ctx)
	ck(t, "Users.Me", err)
	_, err = c.Users.Get(ctx, "alice")
	ck(t, "Users.Get", err)
	_, err = c.Users.Create(ctx, CreateUserParams{Username: "u", Password: "p", Firstname: "f", Lastname: "l"})
	ck(t, "Users.Create", err)
	_, err = c.Users.Update(ctx, id, UpdateUserParams{Role: String("admin")})
	ck(t, "Users.Update", err)
	_, err = c.Users.InitRequired(ctx)
	ck(t, "Users.InitRequired", err)
	_, err = c.Users.GetTOTP(ctx)
	ck(t, "Users.GetTOTP", err)
	ck(t, "Users.DisableTOTP", c.Users.DisableTOTP(ctx, TOTPDisableParams{Token: "1"}))

	// Data catalogs
	_, err = c.Data.Roles(ctx)
	ck(t, "Data.Roles", err)
	_, err = c.Data.Languages(ctx)
	ck(t, "Data.Languages", err)
	_, err = c.Data.CreateLanguage(ctx, Language{Locale: "en", Language: "English"})
	ck(t, "Data.CreateLanguage", err)
	_, err = c.Data.SetLanguages(ctx, []Language{{Locale: "en", Language: "English"}})
	ck(t, "Data.SetLanguages", err)
	ck(t, "Data.DeleteLanguage", c.Data.DeleteLanguage(ctx, "en"))
	_, err = c.Data.AuditTypes(ctx)
	ck(t, "Data.AuditTypes", err)
	_, err = c.Data.CreateAuditType(ctx, AuditType{Name: "PT"})
	ck(t, "Data.CreateAuditType", err)
	_, err = c.Data.SetAuditTypes(ctx, []AuditType{{Name: "PT"}})
	ck(t, "Data.SetAuditTypes", err)
	ck(t, "Data.DeleteAuditType", c.Data.DeleteAuditType(ctx, "PT"))
	_, err = c.Data.VulnerabilityTypes(ctx)
	ck(t, "Data.VulnerabilityTypes", err)
	_, err = c.Data.CreateVulnerabilityType(ctx, VulnerabilityType{Name: "Web", Locale: "en"})
	ck(t, "Data.CreateVulnerabilityType", err)
	_, err = c.Data.SetVulnerabilityTypes(ctx, nil)
	ck(t, "Data.SetVulnerabilityTypes", err)
	ck(t, "Data.DeleteVulnerabilityType", c.Data.DeleteVulnerabilityType(ctx, "Web"))
	_, err = c.Data.VulnerabilityCategories(ctx)
	ck(t, "Data.VulnerabilityCategories", err)
	_, err = c.Data.CreateVulnerabilityCategory(ctx, VulnerabilityCategory{Name: "Cat"})
	ck(t, "Data.CreateVulnerabilityCategory", err)
	_, err = c.Data.SetVulnerabilityCategories(ctx, nil)
	ck(t, "Data.SetVulnerabilityCategories", err)
	ck(t, "Data.DeleteVulnerabilityCategory", c.Data.DeleteVulnerabilityCategory(ctx, "Cat"))
	_, err = c.Data.Sections(ctx)
	ck(t, "Data.Sections", err)
	_, err = c.Data.CreateSection(ctx, CustomSection{Field: "f", Name: "n"})
	ck(t, "Data.CreateSection", err)
	_, err = c.Data.SetSections(ctx, nil)
	ck(t, "Data.SetSections", err)
	ck(t, "Data.DeleteSection", c.Data.DeleteSection(ctx, "f", "en"))
	_, err = c.Data.CustomFields(ctx)
	ck(t, "Data.CustomFields", err)
	_, err = c.Data.CreateCustomField(ctx, CustomField{FieldType: "text", Label: "L"})
	ck(t, "Data.CreateCustomField", err)
	_, err = c.Data.SetCustomFields(ctx, nil)
	ck(t, "Data.SetCustomFields", err)
	ck(t, "Data.DeleteCustomField", c.Data.DeleteCustomField(ctx, id))

	// Vulnerabilities
	_, err = c.Vulnerabilities.List(ctx)
	ck(t, "Vulnerabilities.List", err)
	_, err = c.Vulnerabilities.ListByLocale(ctx, "en")
	ck(t, "Vulnerabilities.ListByLocale", err)
	_, err = c.Vulnerabilities.Create(ctx, []Vulnerability{{Details: []VulnDetail{{Locale: "en", Title: "X"}}}})
	ck(t, "Vulnerabilities.Create", err)
	_, err = c.Vulnerabilities.Update(ctx, id, Vulnerability{})
	ck(t, "Vulnerabilities.Update", err)
	ck(t, "Vulnerabilities.Delete", c.Vulnerabilities.Delete(ctx, id))
	ck(t, "Vulnerabilities.DeleteAll", c.Vulnerabilities.DeleteAll(ctx))
	_, err = c.Vulnerabilities.Export(ctx)
	ck(t, "Vulnerabilities.Export", err)
	ck(t, "Vulnerabilities.Merge", c.Vulnerabilities.Merge(ctx, id, MergeParams{VulnID: id, Locale: "en"}))
	_, err = c.Vulnerabilities.CreateFromFinding(ctx, "en", Finding{Title: "X"})
	ck(t, "Vulnerabilities.CreateFromFinding", err)

	// Templates
	_, err = c.Templates.List(ctx)
	ck(t, "Templates.List", err)
	_, err = c.Templates.Create(ctx, CreateTemplateParams{Name: "T", File: "AAA=", Ext: "docx"})
	ck(t, "Templates.Create", err)
	_, err = c.Templates.Update(ctx, id, CreateTemplateParams{Name: "T2"})
	ck(t, "Templates.Update", err)
	ck(t, "Templates.Delete", c.Templates.Delete(ctx, id))
	_, err = c.Templates.Download(ctx, id)
	ck(t, "Templates.Download", err)

	// Settings
	_, err = c.Settings.Get(ctx)
	ck(t, "Settings.Get", err)
	_, err = c.Settings.GetPublic(ctx)
	ck(t, "Settings.GetPublic", err)
	_, err = c.Settings.Update(ctx, Settings{})
	ck(t, "Settings.Update", err)
	_, err = c.Settings.Export(ctx)
	ck(t, "Settings.Export", err)
	_, err = c.Settings.Captions(ctx)
	ck(t, "Settings.Captions", err)
	ck(t, "Settings.SetCaptions", c.Settings.SetCaptions(ctx, []string{"Figure"}))

	// Images
	_, err = c.Images.Upload(ctx, UploadImageParams{Value: "data:image/png;base64,AAA="})
	ck(t, "Images.Upload", err)
	_, err = c.Images.UploadBytes(ctx, []byte{1, 2, 3}, "image/png", "x.png", "")
	ck(t, "Images.UploadBytes", err)
	_, err = c.Images.Get(ctx, id)
	ck(t, "Images.Get", err)
	_, err = c.Images.Download(ctx, id)
	ck(t, "Images.Download", err)
	ck(t, "Images.Delete", c.Images.Delete(ctx, id))

	// Backups
	_, err = c.Backups.List(ctx)
	ck(t, "Backups.List", err)
	_, err = c.Backups.Status(ctx)
	ck(t, "Backups.Status", err)
	_, err = c.Backups.Create(ctx, CreateBackupParams{Name: "b"})
	ck(t, "Backups.Create", err)
	ck(t, "Backups.Restore", c.Backups.Restore(ctx, "slug", RestoreParams{}))
	ck(t, "Backups.Delete", c.Backups.Delete(ctx, "slug"))
	_, err = c.Backups.Download(ctx, "slug")
	ck(t, "Backups.Download", err)
	_, err = c.Backups.Upload(ctx, strings.NewReader("tar-bytes"), "b.tar")
	ck(t, "Backups.Upload", err)

	// Audits (broad)
	_, err = c.Audits.Create(ctx, CreateAuditParams{Name: "A", Language: "en", AuditType: "PT"})
	ck(t, "Audits.Create", err)
	_, err = c.Audits.List(ctx, nil)
	ck(t, "Audits.List", err)
	_, err = c.Audits.Get(ctx, id)
	ck(t, "Audits.Get", err)
	ck(t, "Audits.Delete", c.Audits.Delete(ctx, id))
	ck(t, "Audits.UpdateGeneral", c.Audits.UpdateGeneral(ctx, id, AuditGeneral{Name: String("x")}))
	_, err = c.Audits.GetNetwork(ctx, id)
	ck(t, "Audits.GetNetwork", err)
	ck(t, "Audits.UpdateNetwork", c.Audits.UpdateNetwork(ctx, id, AuditNetwork{}))
	_, err = c.Audits.GetSection(ctx, id, "sec")
	ck(t, "Audits.GetSection", err)
	ck(t, "Audits.UpdateSection", c.Audits.UpdateSection(ctx, id, "sec", SectionData{}))
	ck(t, "Audits.SortFindings", c.Audits.SortFindings(ctx, id, SortFindingsParams{}))
	ck(t, "Audits.MoveFinding", c.Audits.MoveFinding(ctx, id, 0, 1))
	_, err = c.Audits.AddComment(ctx, id, Comment{FindingID: "f", FieldName: "title", Author: "u"})
	ck(t, "Audits.AddComment", err)
	_, err = c.Audits.UpdateComment(ctx, id, "cmt", Comment{Text: "x"})
	ck(t, "Audits.UpdateComment", err)
	ck(t, "Audits.DeleteComment", c.Audits.DeleteComment(ctx, id, "cmt"))
	_, err = c.Audits.Children(ctx, id)
	ck(t, "Audits.Children", err)
	ck(t, "Audits.UpdateParent", c.Audits.UpdateParent(ctx, id, "parent"))
	ck(t, "Audits.DeleteParent", c.Audits.DeleteParent(ctx, id))
	ck(t, "Audits.ToggleApproval", c.Audits.ToggleApproval(ctx, id))
	ck(t, "Audits.UpdateReadyForReview", c.Audits.UpdateReadyForReview(ctx, id, true))
	_, err = c.Audits.Generate(ctx, id)
	ck(t, "Audits.Generate", err)

	// Findings
	_, err = c.Findings.List(ctx, id)
	ck(t, "Findings.List", err)
	_, err = c.Findings.Create(ctx, id, Finding{Title: "T"})
	ck(t, "Findings.Create", err)
	_, err = c.Findings.Get(ctx, id, "f")
	ck(t, "Findings.Get", err)
	_, err = c.Findings.Update(ctx, id, "f", Finding{Title: "T"})
	ck(t, "Findings.Update", err)
	ck(t, "Findings.Delete", c.Findings.Delete(ctx, id, "f"))

	// High-level
	ck(t, "SetCompany", c.SetCompany(ctx, id, "Acme"))
	ck(t, "SetClient", c.SetClient(ctx, id, "a@b.c"))
	ck(t, "SetScope", c.SetScope(ctx, id, "h1", "h2"))
	ck(t, "SetDates", c.SetDates(ctx, id, "2026-01-01", "2026-01-02"))
	_, err = c.QuickFinding(ctx, id, "Quick", PriorityMedium)
	ck(t, "QuickFinding", err)
	_, err = c.SetGlobalCaptionLabels(ctx, []string{"Figure"})
	ck(t, "SetGlobalCaptionLabels", err)
	_, err = c.AttachImageToFinding(ctx, id, "f", "testdata/sample.png", "cap")
	ck(t, "AttachImageToFinding", err)

	// File-based helpers
	_, err = c.Images.UploadFile(ctx, "testdata/sample.png", id)
	ck(t, "Images.UploadFile", err)
	out := filepath.Join(t.TempDir(), "r.docx")
	_, err = c.GenerateReport(ctx, id, out)
	ck(t, "GenerateReport", err)
}

func TestEmptyIDValidation(t *testing.T) {
	c := nullClient(t)
	ctx := context.Background()
	if err := c.Audits.Delete(ctx, ""); err == nil {
		t.Error("expected empty-id error for Audits.Delete")
	}
	if _, err := c.Findings.Get(ctx, "", "f"); err == nil {
		t.Error("expected empty-id error for Findings.Get")
	}
	if err := c.Images.Delete(ctx, ""); err == nil {
		t.Error("expected empty-id error for Images.Delete")
	}
}
