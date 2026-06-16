package pwndoc_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	pwndoc "github.com/RaynLight/go-pwndocapi/pwndoc"
)

// Integration tests run only when PWNDOC_URL is set; they exercise the library
// against a real pwndoc instance. Credentials and URL are read from the
// environment so nothing sensitive is ever committed:
//
//	PWNDOC_URL, PWNDOC_USER, PWNDOC_PASS, PWNDOC_TOTP (optional), PWNDOC_INSECURE
func integrationClient(t *testing.T) (*pwndoc.Client, context.Context) {
	t.Helper()
	base := os.Getenv("PWNDOC_URL")
	if base == "" {
		t.Skip("PWNDOC_URL not set; skipping integration test")
	}
	var opts []pwndoc.Option
	if os.Getenv("PWNDOC_INSECURE") == "1" {
		opts = append(opts, pwndoc.WithInsecureTLS())
	}
	c, err := pwndoc.New(base, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	if err := c.Login(ctx, os.Getenv("PWNDOC_USER"), os.Getenv("PWNDOC_PASS"), os.Getenv("PWNDOC_TOTP")); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return c, ctx
}

func TestIntegrationReadOnly(t *testing.T) {
	c, ctx := integrationClient(t)

	me, err := c.Users.Me(ctx)
	if err != nil {
		t.Fatalf("Users.Me: %v", err)
	}
	if me.Username == "" {
		t.Fatalf("Users.Me returned empty username")
	}
	t.Logf("authenticated as %q (role %q)", me.Username, me.Role)

	if _, err := c.Data.Languages(ctx); err != nil {
		t.Fatalf("Data.Languages: %v", err)
	}
	if _, err := c.Data.AuditTypes(ctx); err != nil {
		t.Fatalf("Data.AuditTypes: %v", err)
	}
	if _, err := c.Data.Roles(ctx); err != nil {
		t.Fatalf("Data.Roles: %v", err)
	}
	if _, err := c.Templates.List(ctx); err != nil {
		t.Fatalf("Templates.List: %v", err)
	}
	if _, err := c.Settings.Captions(ctx); err != nil {
		t.Fatalf("Settings.Captions: %v", err)
	}
}

func TestIntegrationFullLifecycle(t *testing.T) {
	c, ctx := integrationClient(t)
	suffix := fmt.Sprintf("gopwndoc-%d", time.Now().UnixNano())

	// Pick an available language and audit type from the instance.
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

	// Build a full engagement by name (company/client auto-created).
	companyName := "Acme " + suffix
	clientEmail := suffix + "@example.test"

	audit, err := c.NewPentest("Engagement "+suffix, locale, auditType).
		Company(companyName).
		Client(clientEmail, "Dana", "Lee").
		Scope("app.example.test", "10.10.0.0/24").
		Dates("2026-06-15", "2026-06-20").
		Run(ctx)
	if err != nil {
		t.Fatalf("NewPentest.Run: %v", err)
	}
	t.Logf("created audit %s", audit.ID)

	// Track everything for cleanup.
	var companyID, clientID, imageID string
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.Audits.Delete(cctx, audit.ID); err != nil {
			t.Logf("cleanup audit: %v", err)
		}
		if imageID != "" {
			_ = c.Images.Delete(cctx, imageID)
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
	if audit.Company == nil || !strings.EqualFold(audit.Company.Name, companyName) {
		t.Errorf("audit company not linked: %+v", audit.Company)
	}
	if audit.Client == nil {
		t.Errorf("audit client not linked")
	}
	if len(audit.Scope) != 2 {
		t.Errorf("expected 2 scope entries, got %d (%+v)", len(audit.Scope), audit.Scope)
	}
	if audit.DateStart != "2026-06-15" {
		t.Errorf("date_start = %q, want 2026-06-15", audit.DateStart)
	}

	// Upload an image and create a finding with an embedded captioned image.
	imgBytes, err := os.ReadFile("testdata/sample.png")
	if err != nil {
		t.Fatalf("read sample image: %v", err)
	}
	caption := "Figure 1 - login bypass"
	finding, err := c.AddFindingWithImages(ctx, audit.ID,
		pwndoc.Finding{
			Title:       "SQL Injection " + suffix,
			VulnType:    "Web",
			Description: "<p>Injectable login form.</p>",
			CVSSv3:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Priority:    pwndoc.PriorityHigh,
			References:  []string{"https://owasp.org/Top10/A03_2021-Injection/"},
		},
		pwndoc.FindingImageGroup{
			Text:   "<p>Proof of concept:</p>",
			Images: []pwndoc.ImageSpec{{Bytes: imgBytes, Mime: "image/png", Name: "poc.png", Caption: caption}},
		},
	)
	if err != nil {
		t.Fatalf("AddFindingWithImages: %v", err)
	}
	if finding.ID == "" {
		t.Fatalf("created finding has no id")
	}
	t.Logf("created finding %s (identifier %d)", finding.ID, finding.Identifier)

	// The POC HTML must contain an <img> whose alt is the caption.
	if !strings.Contains(finding.POC, `alt="`+caption+`"`) {
		t.Errorf("finding POC missing caption alt; POC=%q", finding.POC)
	}
	// Extract the embedded image id and confirm it is downloadable.
	if start := strings.Index(finding.POC, `src="`); start >= 0 {
		rest := finding.POC[start+len(`src="`):]
		if end := strings.IndexByte(rest, '"'); end >= 0 {
			imageID = rest[:end]
		}
	}
	if imageID == "" {
		t.Fatalf("could not extract embedded image id from POC: %q", finding.POC)
	}
	dl, err := c.Images.Download(ctx, imageID)
	if err != nil {
		t.Fatalf("Images.Download(%s): %v", imageID, err)
	}
	if !bytes.Equal(dl, imgBytes) {
		t.Errorf("downloaded image (%d bytes) != uploaded (%d bytes)", len(dl), len(imgBytes))
	}

	// Update the caption of the first figure.
	newCaption := "Figure 1 - authentication bypass"
	updated, err := c.SetFigureCaption(ctx, audit.ID, finding.ID, 0, newCaption)
	if err != nil {
		t.Fatalf("SetFigureCaption: %v", err)
	}
	if !strings.Contains(updated.POC, `alt="`+newCaption+`"`) {
		t.Errorf("updated caption not applied; POC=%q", updated.POC)
	}

	// Generate the .docx report. Report rendering depends on the instance having
	// a valid .docx template; a server-side 5xx (e.g. a broken template) is the
	// instance's problem, not the client's, so we tolerate it.
	report, err := c.Audits.Generate(ctx, audit.ID)
	switch {
	case err == nil:
		if len(report.Data) < 2 || !bytes.HasPrefix(report.Data, []byte("PK")) {
			t.Errorf("report does not look like a .docx (got %d bytes)", len(report.Data))
		} else {
			t.Logf("generated report: %d bytes", len(report.Data))
		}
	default:
		if ae, ok := pwndoc.AsAPIError(err); ok && ae.Server() {
			t.Logf("report generation returned a server error (instance template issue, not a client bug): %v", err)
		} else {
			t.Fatalf("Audits.Generate: %v", err)
		}
	}
}
