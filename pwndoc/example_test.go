package pwndoc_test

import (
	"context"
	"fmt"
	"log"

	pwndoc "github.com/RaynLight/go-pwndocapi/pwndoc"
)

// Example shows the end-to-end happy path: connect, build an engagement by name,
// add a finding with a captioned screenshot, and generate the report.
func Example() {
	ctx := context.Background()

	c, err := pwndoc.Connect(ctx, "https://pwndoc.example.com:8443",
		"user", "password", pwndoc.WithInsecureTLS())
	if err != nil {
		log.Fatal(err)
	}

	audit, err := c.NewPentest("Acme Web App", "en", "Penetration Test").
		Company("Acme Corp").
		Client("ciso@acme.test", "Dana", "Lee").
		Scope("app.acme.test", "api.acme.test").
		Dates("2026-06-15", "2026-06-20").
		Run(ctx)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := c.AddFindingWithImages(ctx, audit.ID,
		pwndoc.Finding{
			Title:    "SQL Injection in login form",
			Priority: pwndoc.PriorityHigh,
			CVSSv3:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		},
		pwndoc.FindingImageGroup{
			Text:   "<p>Proof of concept:</p>",
			Images: []pwndoc.ImageSpec{{Path: "screenshots/sqli.png", Caption: "Figure 1 - SQLi"}},
		},
	); err != nil {
		log.Fatal(err)
	}

	if _, err := c.GenerateReport(ctx, audit.ID, "out/acme-report.docx"); err != nil {
		log.Fatal(err)
	}
}

// ExampleClient_AttachImageToFinding attaches a captioned screenshot to an
// existing finding's proof-of-concept field.
func ExampleClient_AttachImageToFinding() {
	ctx := context.Background()
	c, _ := pwndoc.Connect(ctx, "https://pwndoc.example.com:8443", "user", "pass", pwndoc.WithInsecureTLS())

	finding, err := c.AttachImageToFinding(ctx, "<auditID>", "<findingID>",
		"poc.png", "Figure 1 - exploited request")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(finding.Title)
}

// ExampleIsNotFound shows error classification.
func ExampleIsNotFound() {
	ctx := context.Background()
	c, _ := pwndoc.Connect(ctx, "https://pwndoc.example.com:8443", "user", "pass", pwndoc.WithInsecureTLS())

	_, err := c.Audits.Get(ctx, "does-not-exist")
	if pwndoc.IsNotFound(err) {
		fmt.Println("audit not found")
	}
}
