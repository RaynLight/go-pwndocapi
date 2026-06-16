# go-pwndocapi

An idiomatic, **zero-dependency** Go client for the [pwndoc](https://github.com/pwndoc/pwndoc)
pentest-reporting REST API.

It covers the **entire** pwndoc API surface — audits, findings, images, clients,
companies, users, the vulnerability template database, data catalogs, report
templates, settings and backups — and adds a high-level orchestration layer so
common workflows (start an engagement, add a finding with annotated screenshots,
generate the report) take only a handful of calls.

- **Stdlib only.** No third-party dependencies; just `import` and go.
- **Context-first.** Every call takes a `context.Context`.
- **Typed.** Models, enums (`Priority`, `RemediationComplexity`, ...) and a typed
  `*APIError` with classifiers (`IsNotFound`, `IsForbidden`, ...).
- **Cookie auth handled for you,** including transparent token refresh on 401.
- **Built for automation & AI agents:** discoverable services, name-based
  helpers (pass `"Acme Corp"`, not a Mongo id), and copy-paste examples.

---

## Install

```bash
go get github.com/RaynLight/go-pwndocapi/pwndoc
```

```go
import "github.com/RaynLight/go-pwndocapi/pwndoc"
```

The package is named `pwndoc`, so it is referenced as `pwndoc.Client`,
`pwndoc.Finding`, `pwndoc.CVSS31`, `pwndoc.Bold`, etc. Requires Go 1.22+.

---

## Quick start

```go
package main

import (
	"context"
	"log"

	"github.com/RaynLight/go-pwndocapi/pwndoc"
)

func main() {
	ctx := context.Background()

	// pwndoc instances often use a self-signed certificate -> WithInsecureTLS.
	c, err := pwndoc.Connect(ctx, "https://pwndoc.example.com:8443",
		"user", "password", pwndoc.WithInsecureTLS())
	if err != nil {
		log.Fatal(err)
	}

	// Start a whole engagement by NAME — company/client are auto-created,
	// scope/dates applied, in one call.
	audit, err := c.NewPentest("Acme Web App", "en", "Penetration Test").
		Company("Acme Corp").
		Client("ciso@acme.test", "Dana", "Lee").
		Scope("app.acme.test", "api.acme.test").
		Dates("2026-06-15", "2026-06-20").
		Run(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Add a finding with a captioned screenshot in one call.
	_, err = c.AddFindingWithImages(ctx, audit.ID,
		pwndoc.Finding{
			Title:       "SQL Injection in login form",
			VulnType:    "Web Application",
			Description: "<p>The login form is injectable.</p>",
			CVSSv3:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Priority:    pwndoc.PriorityHigh,
			References:  []string{"https://owasp.org/Top10/A03_2021-Injection/"},
		},
		pwndoc.FindingImageGroup{
			Text:   "<p>Proof of concept:</p>",
			Images: []pwndoc.ImageSpec{{Path: "screenshots/sqli.png", Caption: "Figure 1 - SQLi payload"}},
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Generate the .docx report to disk.
	if _, err := c.GenerateReport(ctx, audit.ID, "out/acme-report.docx"); err != nil {
		log.Fatal(err)
	}
}
```

---

## Authentication

pwndoc authenticates with a **session cookie** (`token=JWT <jwt>`), not a bearer
token. You usually do not need to think about this:

```go
// Option A: create + login in one step.
c, err := pwndoc.Connect(ctx, baseURL, user, pass)

// Option B: create, then log in (e.g. to set options first).
c, _ := pwndoc.New(baseURL, pwndoc.WithInsecureTLS())
err := c.Login(ctx, user, pass, "" /* TOTP token, or "" */)
```

- The client stores the access and refresh tokens and attaches them to every
  request, **transparently refreshing** an expired access token on a 401.
- `c.Logout(ctx)` invalidates the server session.
- Reuse a session across processes with `c.Tokens()` + `pwndoc.WithToken(...)`.

### Client options

| Option | Purpose |
| --- | --- |
| `WithInsecureTLS()` | Skip TLS verification (self-signed certs / labs). |
| `WithCABundle(pem)` | Trust a custom CA (safer than insecure). |
| `WithTLSConfig(cfg)` | Provide a base `*tls.Config`. |
| `WithTimeout(d)` | Per-request timeout (default 30s). |
| `WithUserAgent(s)` | Override the User-Agent. |
| `WithToken(a, r)` | Seed an existing access/refresh token. |
| `WithAutoRefresh(b)` | Toggle automatic 401 refresh (default on). |
| `WithRetries(n, base, max)` | Retry transient failures on idempotent calls. |
| `WithHTTPClient(hc)` / `WithHTTPDoer(d)` | Supply your own transport (e.g. for tests). |

---

## Resources (services)

Everything is grouped into services on the `*Client`. Type `c.` then a resource
to discover its verbs.

| Service | What it manages |
| --- | --- |
| `c.Audits` | Audits, findings (nested), sections, comments, scope/network, retests, review workflow, report generation |
| `c.Findings` | An audit's findings (`List`, `Create`, `Get`, `Update`, `Delete`, `CreateFromVulnerability`) |
| `c.Clients` | Client contacts (`Contact`) |
| `c.Companies` | Companies (`List/Create/Update/Delete`, `FindByName`, `EnsureByName`) |
| `c.Users` | Users, current profile, first-run init, TOTP |
| `c.Data` | Catalogs: languages, audit types, vulnerability types/categories, custom sections, custom fields, roles |
| `c.Vulnerabilities` | The reusable vulnerability template database |
| `c.Templates` | Word report templates (`Create`, `CreateFromFile`, `CreateDefault`, `EnsureDefault`, `FindByName`, `Download`) |
| `c.Settings` | Instance settings (`Get`, `Update`, `Captions`, `SetCaptions`) |
| `c.Images` | Image upload/download/delete (`Upload`, `UploadFile`, `UploadBytes`, `Download`) |
| `c.Backups` | Instance backups (`List`, `Create`, `Restore`, `Download`, `Upload`) |

Example low-level calls:

```go
audits, _ := c.Audits.List(ctx, nil)
audit,  _ := c.Audits.Get(ctx, "<auditID>")
langs,  _ := c.Data.Languages(ctx)
types,  _ := c.Data.AuditTypes(ctx)
comp,   _ := c.Companies.Create(ctx, pwndoc.Company{Name: "Acme Corp"})
me,     _ := c.Users.Me(ctx)
```

---

## High-level helpers (the "do everything" layer)

These live directly on `*Client` for quick discovery, and resolve human-readable
names to ids automatically.

```go
// Build a full engagement (company/client auto-created, users resolved by name).
audit, _ := c.NewPentest("Acme Web App", "en", "Penetration Test").
	Company("Acme Corp").
	Client("ciso@acme.test", "Dana", "Lee").
	Collaborators("alice", "bob").     // usernames or emails
	Reviewers("carol").
	Scope("app.acme.test", "10.0.0.0/24").
	Dates("2026-06-15", "2026-06-20").
	TemplateByName("go-pwndocapi-default").  // resolved/created at Run (or Template("<id>"))
	AddFinding(pwndoc.Finding{Title: "Missing security headers", Priority: pwndoc.PriorityLow}).
	Run(ctx)

// One-liners on an existing audit:
c.SetCompany(ctx, auditID, "Acme Corp")          // create/link by name
c.SetClient(ctx, auditID, "ciso@acme.test")      // create/link by email
c.SetScope(ctx, auditID, "host1", "host2")
c.SetDates(ctx, auditID, "2026-06-15", "2026-06-20")
c.SetAffectedAssets(ctx, auditID, findingID, pwndoc.Bullets("app.acme.test", "10.0.0.10"))
finding, _ := c.QuickFinding(ctx, auditID, "Quick win", pwndoc.PriorityMedium)

// Reports
report, _ := c.Audits.Generate(ctx, auditID)     // bytes in memory (report.Data)
n, _ := c.GenerateReport(ctx, auditID, "out/report.docx") // straight to disk
```

---

## Images & captions

pwndoc renders figures from `<img>` tags embedded in a finding's HTML fields: the
image `src` is an uploaded image's id and the **`alt` attribute is the caption**
the report shows. This library does that wiring for you.

```go
// Attach a captioned image to an existing finding's POC field.
finding, _ := c.AttachImageToFinding(ctx, auditID, findingID,
	"screenshots/poc.png", "Figure 1 - exploited request")

// Or pick the field (poc, description, observation, remediation):
c.AttachImageToField(ctx, auditID, findingID, pwndoc.FindingFieldDescription,
	"diagram.png", "Figure 2 - data flow")

// Create a finding with several captioned images at once:
c.AddFindingWithImages(ctx, auditID, pwndoc.Finding{Title: "RCE"},
	pwndoc.FindingImageGroup{
		Text: "<p>Step 1:</p>",
		Images: []pwndoc.ImageSpec{
			{Path: "step1.png", Caption: "Figure 1 - upload"},
			{Bytes: pngBytes, Mime: "image/png", Name: "step2.png", Caption: "Figure 2 - trigger"},
		},
	},
)

// Update the caption of the Nth figure (0-based) in a finding's POC:
c.SetFigureCaption(ctx, auditID, findingID, 0, "Figure 1 - revised")

// The figure label prefix ("Figure", "Table", ...) is a global setting:
c.Settings.SetCaptions(ctx, []string{"Figure", "Table"})
// or: c.SetGlobalCaptionLabels(ctx, []string{"Figure"})
```

You can also work with images directly:

```go
img, _ := c.Images.UploadFile(ctx, "poc.png", auditID) // -> img.ID
raw, _ := c.Images.Download(ctx, img.ID)                // decoded bytes
```

---

## Report templates & generation

A pwndoc report is a Word `.docx` filled from a template containing
[docxtemplater](https://docxtemplater.com) tags. The library ships a **complete,
generation-ready template built in memory** — no external file to hunt for — so
an instance with no working template can still produce reports:

```go
// Create-if-missing the built-in template, then generate.
tmpl, _ := c.Templates.EnsureDefault(ctx, "go-pwndocapi-default")
audit, _ := c.NewPentest("Engagement", "en", "Penetration Test").
	TemplateByName(tmpl.Name).
	Run(ctx)
// ... add findings ...
n, _ := c.GenerateReport(ctx, audit.ID, "out/report.docx") // writes the .docx
```

Other ways to get a template onto the instance:

```go
c.Templates.CreateDefault(ctx, "my-template")          // upload the built-in one
c.Templates.CreateFromFile(ctx, "Corporate", "tpl.docx") // upload your own .docx
raw, _ := pwndoc.MinimalReportTemplateDocx()           // the built-in template's bytes
```

The built-in template renders the full audit (name, type, dates, company,
client, scope) and, for every finding: identifier, title, vuln type, category,
priority, remediation complexity, the affected assets, the complete CVSS 3.1
breakdown (vector, base/temporal/environmental scores and every individual
metric), the rich-text Description / Observation / Proof-of-Concept (with
captioned images) / Remediation fields, and the references list.

> **Authoring your own template?** pwndoc's parser rejects Unicode "smart"
> quotes — a tag like `{#priority == '4'}` (curly quotes) raises a render
> `"Multi error"`. Use straight ASCII quotes. (The stock "PT Template" that ships
> with many instances trips on exactly this.)

---

## CVSS 3.1 scoring

`CVSS31` builds a full vector string (all base, temporal and environmental
metrics) for `Finding.CVSSv3`; pwndoc computes the scores and severities from it.
Metrics left empty or set to "Not Defined" are omitted.

```go
v := pwndoc.CVSS31{
	AV: pwndoc.AVNetwork, AC: pwndoc.ACLow, PR: pwndoc.PRNone, UI: pwndoc.UINone,
	S: pwndoc.ScopeChanged, C: pwndoc.ImpactHigh, I: pwndoc.ImpactHigh, A: pwndoc.ImpactHigh,
	// optional temporal + environmental:
	E: pwndoc.EFunctional, RL: pwndoc.RLOfficialFix, RC: pwndoc.RCConfirmed,
	CR: pwndoc.ReqHigh, IR: pwndoc.ReqHigh, AR: pwndoc.ReqMedium,
}
_ = v.Validate()                 // checks the 8 required base metrics
finding.CVSSv3 = v.Vector()      // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/..."
got, _ := pwndoc.ParseCVSS31(finding.CVSSv3) // parse back into a CVSS31
```

---

## Rich-text formatting

Finding prose (Description, Observation, Remediation, POC) and the affected-assets
field are HTML; pwndoc converts a known subset of tags to Word formatting. The
helpers emit exactly that subset, so what you write is what renders:

```go
html := pwndoc.NewRichText().
	H(4, "Finding detail").
	P("Styles: " + pwndoc.Bold("bold") + ", " + pwndoc.Italic("italic") + ", " +
		pwndoc.Underline("underline") + ", " + pwndoc.Strike("strikethrough") + ", " +
		pwndoc.Highlight("highlight") + ", " + pwndoc.Code("inline code") + ".").
	Bullets("First point", "Second point").
	Numbered("Step one", "Step two").
	Code("bash", "sqlmap -u https://target/login --batch").
	String()

finding.Description = html
// Or one call demonstrating every style:
finding.Observation = pwndoc.FormattingShowcase()
```

Inline: `Bold`, `Italic`, `Underline`, `Strike`, `Highlight`/`HighlightWith`,
`Code`, `Esc`. Blocks: `Para`, `Heading`, `Bullets`, `Numbered`, `CodeBlock`.
`Affected assets` is the finding's `Scope` field and also accepts this HTML.

---

## Error handling

Server-side failures are returned as `*APIError`. Classify them without
inspecting status codes by hand:

```go
audit, err := c.Audits.Get(ctx, id)
switch {
case err == nil:
	// ok
case pwndoc.IsNotFound(err):
	// 404
case pwndoc.IsForbidden(err):
	// 403
default:
	if ae, ok := pwndoc.AsAPIError(err); ok {
		log.Printf("pwndoc %d on %s: %s", ae.StatusCode, ae.Op, ae.Message)
	}
}
```

Classifiers: `IsNotFound`, `IsUnauthorized`, `IsForbidden`, `IsBadRequest`,
`IsConflict`, `IsServer`. Sentinels (`errors.Is`): `ErrNotAuthenticated`,
`ErrRefreshFailed`, `ErrNoTOTP`, `ErrEmptyID`.

---

## Enums & helpers

```go
pwndoc.PriorityLow / PriorityMedium / PriorityHigh / PriorityUrgent
pwndoc.RemediationEasy / RemediationMedium / RemediationComplex
pwndoc.FindingDone / FindingRedacting          // use Ptr(...) for Finding.Status
pwndoc.RetestOK / RetestKO / RetestUnknown / RetestPartial
pwndoc.AuditModeDefault / AuditModeMulti
```

Pointer helpers for tri-state fields: `pwndoc.Ptr(v)`, `pwndoc.String(s)`,
`pwndoc.Int(i)`, `pwndoc.Bool(b)`. (e.g. `Finding{Status: pwndoc.Ptr(pwndoc.FindingDone)}`.)

---

## Testing this library

Unit tests run anywhere (they use `httptest`, no instance required):

```bash
go test -race ./...
```

Integration tests run against a real pwndoc instance and are **skipped** unless
`PWNDOC_URL` is set. Credentials are read from the environment so nothing
sensitive is committed:

```bash
export PWNDOC_URL=https://your-instance:8443
export PWNDOC_USER=youruser
export PWNDOC_PASS=yourpass
export PWNDOC_INSECURE=1   # self-signed cert
go test -run Integration -v ./...
```

See [`.env.example`](.env.example) for the full list. **Never commit a filled-in
`.env`** — it is gitignored.

---

## Notes & caveats

- **Finding create/update** return only a status message in pwndoc, so the
  library re-reads the audit to give you the stored `Finding` (with its
  server-assigned `_id` and `identifier`).
- **`AuditGeneral.Scope` is `[]string`** (the server stores each as
  `{name, hosts}`); the structured host model is on `AuditNetwork`/`Audit.Scope`.
- **Report generation** needs a valid `.docx` template on the instance. Use the
  built-in one (`c.Templates.EnsureDefault`) if none works; a broken template
  surfaces as a `500` `*APIError` from `Audits.Generate`. Templates with Unicode
  smart quotes fail to render — see [Report templates](#report-templates--generation).
- **Affected assets** is the finding's `Scope` field (rendered via the report's
  `{@affected}` tag); it accepts the rich-text HTML helpers.

---

## License

[MIT](LICENSE)
