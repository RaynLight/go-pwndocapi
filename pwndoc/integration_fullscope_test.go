package pwndoc_test

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	pwndoc "github.com/RaynLight/go-pwndocapi/pwndoc"
)

// TestIntegrationFullScope exercises every feature the library is meant to
// support, end to end, against a live instance, and asserts that report
// generation SUCCEEDS using the library's own built-in template:
//
//   - upload a working report template (built in memory, no external file)
//   - create company + client (by name/email, auto-created)
//   - create an audit with name, language, template, company, client, dates, scope
//   - create a finding populating EVERY field: description, observation,
//     references, proof-of-concept with a captioned image, affected assets, the
//     full CVSS 3.1 vector (all metrics), remediation complexity, priority and
//     remediation steps — each rich-text field showing bold/italic/underline/
//     highlight/code/list formatting
//   - generate the .docx and verify the rendered document actually contains the
//     finding content and the embedded image
//
// Set PWNDOC_REPORT_OUT to also write the generated .docx to that path.
func TestIntegrationFullScope(t *testing.T) {
	c, ctx := integrationClient(t)
	suffix := fmt.Sprintf("fs%d", time.Now().UnixNano())

	langs, err := c.Data.Languages(ctx)
	if err != nil || len(langs) == 0 {
		t.Fatalf("need at least one language: %v", err)
	}
	auditTypes, err := c.Data.AuditTypes(ctx)
	if err != nil || len(auditTypes) == 0 {
		t.Fatalf("need at least one audit type: %v", err)
	}
	locale := langs[0].Locale
	auditType := auditTypes[0].Name

	// 1) Ensure a working template exists (created from the built-in template).
	templateName := "go-pwndocapi-default"
	tmpl, err := c.Templates.EnsureDefault(ctx, templateName)
	if err != nil {
		t.Fatalf("Templates.EnsureDefault: %v", err)
	}
	t.Logf("using template %q (id %s, ext %s)", tmpl.Name, tmpl.ID, tmpl.Ext)

	// 2) Build the engagement with all general fields. Company and client are
	// auto-created by name/email; the template is resolved by name.
	companyName := "Acme Corp " + suffix
	clientEmail := suffix + "@example.test"

	audit, err := c.NewPentest("Full Scope Engagement "+suffix, locale, auditType).
		Company(companyName).
		Client(clientEmail, "Dana", "Lee").
		TemplateByName(templateName).
		Scope("app.example.test", "api.example.test", "10.10.0.0/24").
		Dates("2026-06-15", "2026-06-22").
		Run(ctx)
	if err != nil {
		t.Fatalf("NewPentest.Run: %v", err)
	}
	t.Logf("created audit %s", audit.ID)

	var companyID, clientID string
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.Audits.Delete(cctx, audit.ID); err != nil {
			t.Logf("cleanup audit: %v", err)
		}
		if clientID != "" {
			_ = c.Clients.Delete(cctx, clientID)
		}
		if companyID != "" {
			_ = c.Companies.Delete(cctx, companyID)
		}
	})
	if comp, _ := c.Companies.FindByName(ctx, companyName); comp != nil {
		companyID = comp.ID
	}
	if ct, _ := c.Clients.FindByEmail(ctx, clientEmail); ct != nil {
		clientID = ct.ID
	}

	// Verify general info landed.
	if audit.Template == nil || audit.Template.ID != tmpl.ID {
		t.Errorf("audit template not set to %s: %+v", tmpl.ID, audit.Template)
	}
	if audit.Company == nil || !strings.EqualFold(audit.Company.Name, companyName) {
		t.Errorf("audit company not linked: %+v", audit.Company)
	}
	if audit.Client == nil {
		t.Errorf("audit client not linked")
	}
	if len(audit.Scope) != 3 {
		t.Errorf("expected 3 scope entries, got %d (%+v)", len(audit.Scope), audit.Scope)
	}
	if audit.DateStart != "2026-06-15" || audit.DateEnd != "2026-06-22" {
		t.Errorf("dates = %q..%q, want 2026-06-15..2026-06-22", audit.DateStart, audit.DateEnd)
	}

	// 3) Full CVSS 3.1 vector: base + temporal + environmental (all metrics).
	cv := pwndoc.CVSS31{
		AV: pwndoc.AVNetwork, AC: pwndoc.ACLow, PR: pwndoc.PRNone, UI: pwndoc.UINone,
		S: pwndoc.ScopeChanged, C: pwndoc.ImpactHigh, I: pwndoc.ImpactHigh, A: pwndoc.ImpactHigh,
		E: pwndoc.EFunctional, RL: pwndoc.RLOfficialFix, RC: pwndoc.RCConfirmed,
		CR: pwndoc.ReqHigh, IR: pwndoc.ReqHigh, AR: pwndoc.ReqMedium,
		MAV: pwndoc.ModAttackVector(pwndoc.AVNetwork), MAC: pwndoc.ModAttackComplexity(pwndoc.ACLow),
		MPR: pwndoc.ModPrivilegesRequired(pwndoc.PRNone), MUI: pwndoc.ModUserInteraction(pwndoc.UINone),
		MS: pwndoc.ModScope(pwndoc.ScopeChanged), MC: pwndoc.ModImpact(pwndoc.ImpactHigh),
		MI: pwndoc.ModImpact(pwndoc.ImpactHigh), MA: pwndoc.ModImpact(pwndoc.ImpactHigh),
	}
	if err := cv.Validate(); err != nil {
		t.Fatalf("CVSS31.Validate: %v", err)
	}
	t.Logf("CVSS vector: %s", cv.Vector())

	// 4) A finding that fills every field, with formatted rich text everywhere.
	title := "SQL Injection in login " + suffix
	caption := "Figure 1 - SQLi confirmed via sqlmap"
	reference := "https://owasp.org/Top10/A03_2021-Injection/"
	affectedHost := "app.example.test"

	imgBytes, err := os.ReadFile("testdata/sample.png")
	if err != nil {
		t.Fatalf("read sample image: %v", err)
	}

	description := pwndoc.NewRichText().
		Text("The login form is vulnerable to SQL injection via the username parameter.").
		Raw(pwndoc.FormattingShowcase()).
		String()
	observation := pwndoc.NewRichText().
		P("Observed during testing: the response time and error messages confirm " +
			pwndoc.Bold("injectable") + " behaviour.").
		String()
	remediation := pwndoc.NewRichText().
		H(5, "Remediation steps").
		Numbered(
			"Use parameterized queries / prepared statements.",
			"Apply strict input validation on "+pwndoc.Code("username")+".",
			"Deploy a WAF rule as defense in depth.",
		).
		String()
	affected := pwndoc.Bullets(
		pwndoc.Esc(affectedHost+" (10.10.0.10)"),
		pwndoc.Esc("api.example.test (10.10.0.11)"),
	)

	finding := pwndoc.Finding{
		Title:                 title,
		VulnType:              "Web Application",
		Category:              "Web",
		Description:           description,
		Observation:           observation,
		Remediation:           remediation,
		References:            []string{reference, "https://cwe.mitre.org/data/definitions/89.html"},
		Scope:                 affected, // "Affected assets" in pwndoc
		CVSSv3:                cv.Vector(),
		Priority:              pwndoc.PriorityHigh,
		RemediationComplexity: pwndoc.RemediationComplex,
		Status:                pwndoc.Ptr(pwndoc.FindingRedacting),
	}

	created, err := c.AddFindingWithImages(ctx, audit.ID, finding,
		pwndoc.FindingImageGroup{
			Text: pwndoc.Para("Proof of concept — the payload " +
				pwndoc.Code("' OR 1=1 -- -") + " bypasses authentication:"),
			Images: []pwndoc.ImageSpec{
				{Bytes: imgBytes, Mime: "image/png", Name: "poc.png", Caption: caption},
			},
		},
	)
	if err != nil {
		t.Fatalf("AddFindingWithImages: %v", err)
	}
	if created.ID == "" {
		t.Fatalf("created finding has no id")
	}
	t.Logf("created finding %s (identifier %d)", created.ID, created.Identifier)

	// Sanity: every field round-tripped.
	if !strings.Contains(created.POC, `alt="`+caption+`"`) {
		t.Errorf("POC missing captioned image; POC=%q", created.POC)
	}
	if created.CVSSv3 != cv.Vector() {
		t.Errorf("CVSSv3 = %q, want %q", created.CVSSv3, cv.Vector())
	}
	if !strings.Contains(created.Scope, affectedHost) {
		t.Errorf("affected assets missing host; Scope=%q", created.Scope)
	}
	if len(created.References) != 2 {
		t.Errorf("expected 2 references, got %v", created.References)
	}
	if created.RemediationComplexity != pwndoc.RemediationComplex {
		t.Errorf("remediationComplexity = %v", created.RemediationComplexity)
	}
	if created.Priority != pwndoc.PriorityHigh {
		t.Errorf("priority = %v", created.Priority)
	}

	// 5) Generate the report. With the library's own template this MUST succeed.
	report, err := c.Audits.Generate(ctx, audit.ID)
	if err != nil {
		t.Fatalf("Audits.Generate (with built-in template): %v", err)
	}
	if !bytes.HasPrefix(report.Data, []byte("PK")) {
		t.Fatalf("report is not a .docx zip (%d bytes)", len(report.Data))
	}
	t.Logf("generated report: %d bytes", len(report.Data))

	if out := os.Getenv("PWNDOC_REPORT_OUT"); out != "" {
		if werr := os.WriteFile(out, report.Data, 0o644); werr != nil {
			t.Logf("write report to %s: %v", out, werr)
		} else {
			t.Logf("wrote report to %s", out)
		}
	}

	// 6) Verify the rendered document actually contains the finding content and
	// the embedded image.
	docText, mediaCount := readDocx(t, report.Data)
	// Assert finding-specific content actually rendered. These tokens appear
	// ONLY in finding fields (not the audit scope), so they prove rich text,
	// lists, affected assets, CVSS decoding and references all rendered.
	wants := map[string]string{
		suffix:              "finding title",
		"10.10.0.10":        "affected assets (bullet list)",
		"Bullet two with":   "description bullet list",
		"Third step":        "description numbered list",
		"Deploy a WAF rule": "remediation numbered steps",
		"owasp.org":         "references",
		"CVSS:3.1/AV:N":     "CVSS vector",
		"Network":           "decoded CVSS metric (AV=Network)",
		"Figure 1 - SQLi":   "proof-of-concept image caption",
	}
	for want, what := range wants {
		if !strings.Contains(docText, want) {
			t.Errorf("rendered report missing %s (token %q)", what, want)
		}
	}
	if mediaCount == 0 {
		t.Errorf("rendered report contains no embedded image (expected the POC screenshot)")
	} else {
		t.Logf("rendered report embeds %d image(s)", mediaCount)
	}
}

var xmlTagRe = regexp.MustCompile(`<[^>]+>`)

// readDocx returns the visible text of word/document.xml (XML tags stripped)
// and the number of embedded media files in the .docx.
func readDocx(t *testing.T, data []byte) (string, int) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open report zip: %v", err)
	}
	var docText string
	media := 0
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "word/media/") {
			media++
			continue
		}
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open document.xml: %v", err)
			}
			b, _ := io.ReadAll(rc)
			rc.Close()
			docText = xmlTagRe.ReplaceAllString(string(b), "")
		}
	}
	if docText == "" {
		t.Fatalf("report has no word/document.xml")
	}
	return docText, media
}
