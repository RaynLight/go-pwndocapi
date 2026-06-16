package pwndoc_test

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"

	pwndoc "github.com/RaynLight/go-pwndocapi"
)

func TestCVSS31Vector(t *testing.T) {
	base := pwndoc.CVSS31{
		AV: pwndoc.AVNetwork, AC: pwndoc.ACLow, PR: pwndoc.PRNone, UI: pwndoc.UINone,
		S: pwndoc.ScopeUnchanged, C: pwndoc.ImpactHigh, I: pwndoc.ImpactHigh, A: pwndoc.ImpactHigh,
	}
	if got, want := base.Vector(), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"; got != want {
		t.Errorf("base vector = %q, want %q", got, want)
	}
	if err := base.Validate(); err != nil {
		t.Errorf("Validate(base) = %v, want nil", err)
	}

	// Not-Defined / empty optional metrics must be omitted.
	base.E = pwndoc.ENotDefined
	base.CR = "" // unset
	if strings.Contains(base.Vector(), "/E:") || strings.Contains(base.Vector(), "/CR:") {
		t.Errorf("Not-Defined metrics leaked into vector: %s", base.Vector())
	}

	// Full vector with temporal + environmental.
	full := base
	full.E = pwndoc.EFunctional
	full.RL = pwndoc.RLOfficialFix
	full.RC = pwndoc.RCConfirmed
	full.CR = pwndoc.ReqHigh
	full.MAV = pwndoc.ModAttackVector(pwndoc.AVNetwork)
	v := full.Vector()
	for _, want := range []string{"/E:F", "/RL:O", "/RC:C", "/CR:H", "/MAV:N"} {
		if !strings.Contains(v, want) {
			t.Errorf("full vector %q missing %q", v, want)
		}
	}
}

func TestCVSS31ValidateAndParse(t *testing.T) {
	if err := (pwndoc.CVSS31{AV: pwndoc.AVNetwork}).Validate(); err == nil {
		t.Error("Validate should fail when base metrics are missing")
	}

	in := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H"
	parsed, err := pwndoc.ParseCVSS31(in)
	if err != nil {
		t.Fatalf("ParseCVSS31: %v", err)
	}
	if got := parsed.Vector(); got != in {
		t.Errorf("round-trip = %q, want %q", got, in)
	}
	if parsed.AV != pwndoc.AVNetwork || parsed.S != pwndoc.ScopeChanged || parsed.MA != pwndoc.ModImpact("H") {
		t.Errorf("parsed metrics wrong: %+v", parsed)
	}
}

func TestRichTextHelpers(t *testing.T) {
	cases := map[string]string{
		pwndoc.Bold("x"):      "<strong>x</strong>",
		pwndoc.Italic("x"):    "<em>x</em>",
		pwndoc.Underline("x"): "<u>x</u>",
		pwndoc.Strike("x"):    "<s>x</s>",
		pwndoc.Code("x"):      "<code>x</code>",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}

	// Escaping.
	if got := pwndoc.Bold("a<b>&c"); got != "<strong>a&lt;b&gt;&amp;c</strong>" {
		t.Errorf("Bold did not escape: %q", got)
	}

	// Highlight MUST carry a style attribute (pwndoc dereferences it).
	h := pwndoc.Highlight("warn")
	if !strings.Contains(h, "style=") || !strings.Contains(h, "data-color=") {
		t.Errorf("Highlight missing style/data-color: %q", h)
	}

	// List items must be wrapped in <p> so pwndoc emits their text.
	if got := pwndoc.Bullets("one", "two"); got != "<ul><li><p>one</p></li><li><p>two</p></li></ul>" {
		t.Errorf("Bullets = %q", got)
	}
	if got := pwndoc.Numbered("one"); got != "<ol><li><p>one</p></li></ol>" {
		t.Errorf("Numbered = %q", got)
	}

	show := pwndoc.FormattingShowcase()
	for _, want := range []string{"<strong>", "<em>", "<u>", "<s>", "<mark", "<code>", "<ul>", "<ol>", "<pre>"} {
		if !strings.Contains(show, want) {
			t.Errorf("FormattingShowcase missing %q", want)
		}
	}
}

func TestMinimalReportTemplateDocx(t *testing.T) {
	doc, err := pwndoc.MinimalReportTemplateDocx()
	if err != nil {
		t.Fatalf("MinimalReportTemplateDocx: %v", err)
	}
	if !bytes.HasPrefix(doc, []byte("PK")) {
		t.Fatalf("not a zip")
	}
	zr, err := zip.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	parts := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		parts[f.Name] = string(b)
	}
	for _, want := range []string{
		"[Content_Types].xml", "_rels/.rels", "word/document.xml",
		"word/styles.xml", "word/numbering.xml", "word/_rels/document.xml.rels",
	} {
		if _, ok := parts[want]; !ok {
			t.Errorf("template missing part %q", want)
		}
	}

	body := parts["word/document.xml"]
	// Every part must be well-formed XML.
	for name, content := range parts {
		if strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".rels") {
			if err := xml.Unmarshal([]byte(content), new(struct {
				XMLName xml.Name
			})); err != nil {
				t.Errorf("part %q is not well-formed XML: %v", name, err)
			}
		}
	}

	// The body must contain the key docxtemplater tags...
	for _, want := range []string{
		"{name}", "{auditType}", "{company.name}", "{#scope}", "{#findings}",
		"{@affected | convertHTML}", "{#description}", "{@text | convertHTML}",
		"{%image}", "{caption}", "{#references}",
		"{#cvss}", "{vectorString}", "{#cvssObj}", "{AV}",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("template body missing tag %q", want)
		}
	}

	// ...and must NOT contain Unicode smart quotes, which break pwndoc's parser.
	if strings.ContainsAny(body, "‘’“”") {
		t.Error("template body contains smart quotes (would cause a render 'Multi error')")
	}

	// The <w:document> root MUST declare the drawing namespaces; the image
	// module injects wp:/a:/pic:/r: markup, and without these declarations the
	// rendered document.xml is malformed and Word refuses to open the report.
	for _, ns := range []string{"xmlns:w=", "xmlns:r=", "xmlns:wp=", "xmlns:a=", "xmlns:pic="} {
		if !strings.Contains(body, ns) {
			t.Errorf("template <w:document> root missing namespace declaration %q", ns)
		}
	}
}
