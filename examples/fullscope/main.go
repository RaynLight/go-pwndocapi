// Command fullscope is an end-to-end demonstration of go-pwndocapi that
// exercises EVERY feature: it uploads a working report template (built by the
// library, no external file), creates a company, client and audit with all
// general fields, adds a finding populating every field — description,
// observation, references, a proof-of-concept screenshot with a caption,
// affected assets, the full CVSS 3.1 vector, remediation difficulty/priority and
// remediation steps — with bold/italic/underline/highlight/code/list formatting
// in the rich-text fields, then generates the .docx report.
//
// Connection details come from the environment so no secrets live in source:
//
//	PWNDOC_URL=https://your-instance:8443
//	PWNDOC_USER=youruser
//	PWNDOC_PASS=yourpass
//	PWNDOC_INSECURE=1   # set when the instance uses a self-signed certificate
//
// Then:
//
//	go run ./examples/fullscope
package main

import (
	"context"
	"log"
	"os"
	"time"

	pwndoc "github.com/RaynLight/go-pwndocapi"
)

// A valid 1x1 PNG, used as the proof-of-concept screenshot.
var samplePNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
	0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x62, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
	0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
}

func main() {
	base := os.Getenv("PWNDOC_URL")
	if base == "" {
		log.Fatal("set PWNDOC_URL (and PWNDOC_USER / PWNDOC_PASS)")
	}

	var opts []pwndoc.Option
	if os.Getenv("PWNDOC_INSECURE") == "1" {
		opts = append(opts, pwndoc.WithInsecureTLS())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	c, err := pwndoc.Connect(ctx, base, os.Getenv("PWNDOC_USER"), os.Getenv("PWNDOC_PASS"), opts...)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}

	// 1) Ensure a working report template exists. EnsureDefault uploads the
	// library's built-in, generation-ready template if one with this name is
	// not already present.
	tmpl, err := c.Templates.EnsureDefault(ctx, "go-pwndocapi-default")
	if err != nil {
		log.Fatalf("ensure template: %v", err)
	}
	log.Printf("template ready: %q (%s)", tmpl.Name, tmpl.ID)

	// 2) Discover an available language and audit type.
	langs, err := c.Data.Languages(ctx)
	if err != nil || len(langs) == 0 {
		log.Fatalf("languages: %v", err)
	}
	types, err := c.Data.AuditTypes(ctx)
	if err != nil || len(types) == 0 {
		log.Fatalf("audit types: %v", err)
	}

	// 3) Build the engagement: name, language, template, company, client, scope,
	// dates. Company and client are auto-created by name/email.
	audit, err := c.NewPentest("Full Scope Demo", langs[0].Locale, types[0].Name).
		Company("Demo Corp").
		Client("ciso@demo.test", "Dana", "Lee").
		TemplateByName(tmpl.Name).
		Scope("app.demo.test", "api.demo.test", "10.0.0.0/24").
		Dates("2026-06-15", "2026-06-22").
		Run(ctx)
	if err != nil {
		log.Fatalf("create engagement: %v", err)
	}
	log.Printf("created audit %s", audit.ID)

	// 4) Build the full CVSS 3.1 vector (base + temporal + environmental).
	cvss := pwndoc.CVSS31{
		AV: pwndoc.AVNetwork, AC: pwndoc.ACLow, PR: pwndoc.PRNone, UI: pwndoc.UINone,
		S: pwndoc.ScopeChanged, C: pwndoc.ImpactHigh, I: pwndoc.ImpactHigh, A: pwndoc.ImpactHigh,
		E: pwndoc.EFunctional, RL: pwndoc.RLOfficialFix, RC: pwndoc.RCConfirmed,
		CR: pwndoc.ReqHigh, IR: pwndoc.ReqHigh, AR: pwndoc.ReqMedium,
	}
	if err := cvss.Validate(); err != nil {
		log.Fatalf("cvss: %v", err)
	}

	// 5) Compose the rich-text fields using the formatting helpers.
	description := pwndoc.NewRichText().
		Text("The login form concatenates the username parameter directly into a SQL query.").
		P("Severity drivers: "+pwndoc.Bold("unauthenticated")+", "+
			pwndoc.Highlight("trivially exploitable")+", "+pwndoc.Underline("full DB read/write")+".").
		Bullets("Confirmed on /api/login", "Confirmed on /api/search").
		Code("bash", "sqlmap -u 'https://app.demo.test/api/login' --data 'user=*&pass=x' --batch").
		String()

	remediation := pwndoc.NewRichText().
		H(5, "Remediation steps").
		Numbered(
			"Use parameterized queries / prepared statements.",
			"Validate and allow-list the "+pwndoc.Code("username")+" parameter.",
			"Add a WAF rule as defense in depth.",
		).
		String()

	// Affected assets supports HTML too (rendered via the {@affected} tag).
	affected := pwndoc.Bullets(
		pwndoc.Esc("app.demo.test (10.0.0.10)"),
		pwndoc.Esc("api.demo.test (10.0.0.11)"),
	)

	finding := pwndoc.Finding{
		Title:                 "SQL Injection in login form",
		VulnType:              "Web Application",
		Category:              "Web",
		Description:           description,
		Observation:           pwndoc.Para("Error-based and time-based payloads both succeed."),
		Remediation:           remediation,
		References:            []string{"https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/89.html"},
		Scope:                 affected, // "Affected assets"
		CVSSv3:                cvss.Vector(),
		Priority:              pwndoc.PriorityHigh,
		RemediationComplexity: pwndoc.RemediationComplex,
		Status:                pwndoc.Ptr(pwndoc.FindingRedacting),
	}

	created, err := c.AddFindingWithImages(ctx, audit.ID, finding,
		pwndoc.FindingImageGroup{
			Text: pwndoc.Para("Proof of concept — payload " + pwndoc.Code("' OR 1=1 -- -") + ":"),
			Images: []pwndoc.ImageSpec{
				{Bytes: samplePNG, Mime: "image/png", Name: "poc.png", Caption: "Figure 1 - authentication bypass"},
			},
		},
	)
	if err != nil {
		log.Fatalf("add finding: %v", err)
	}
	log.Printf("created finding %s (identifier %d), CVSS %s", created.ID, created.Identifier, created.CVSSv3)

	// 6) Generate the .docx report.
	n, err := c.GenerateReport(ctx, audit.ID, "out/fullscope-report.docx")
	if err != nil {
		log.Fatalf("generate report: %v", err)
	}
	log.Printf("wrote out/fullscope-report.docx (%d bytes)", n)
}
