package pwndoc

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"strings"
)

// This file builds a valid, minimal pwndoc report template (.docx) entirely in
// memory — no external file needed. A pwndoc template is a Word document
// containing docxtemplater tags that the report generator fills in. The tags
// and their exact syntax are dictated by pwndoc's report-generator/ html2ooxml
// pipeline; this template uses only documented, verified tags so report
// generation succeeds out of the box.
//
// What it renders:
//   - Audit: name, type, dates, language, company, client, scope list
//   - Each finding: identifier, title, vuln type, category, priority,
//     remediation complexity, the full CVSS 3.1 vector + base/temporal/
//     environmental scores + every individual metric, affected assets, and the
//     rich-text Description / Observation / Proof-of-Concept (with images and
//     captions) / Remediation fields, plus the references list.
//
// IMPORTANT for template authors: pwndoc's template parser rejects "smart"
// (curly) quotes — the stock "PT Template" shipped with many instances fails
// to render ("Multi error") precisely because its conditional tags use
// U+2018/U+2019 quotes. Every tag here uses straight ASCII quotes.

// reportFieldBlock emits the standard rich-text loop pwndoc expects for an HTML
// field: text paragraphs interleaved with images and their captions. field is
// the data key (e.g. "description", "poc").
func reportFieldBlock(field string) []reportPara {
	return []reportPara{
		{text: "{#" + field + "}"},
		{text: "{@text | convertHTML}"},
		{text: "{#images}"},
		{text: "{%image}"},
		{text: "{caption}", italic: true},
		{text: "{/images}"},
		{text: "{/" + field + "}"},
	}
}

type reportPara struct {
	text   string
	bold   bool
	italic bool
}

// reportBodyParagraphs is the ordered list of paragraphs that make up the
// template body, expressed as plain text + simple styling. Keeping it as data
// keeps the docxtemplater tags readable and auditable.
func reportBodyParagraphs() []reportPara {
	ps := []reportPara{
		{text: "Penetration Test Report", bold: true},
		{text: "{name}", bold: true},
		{text: "Audit type: {auditType}"},
		{text: "Engagement dates: {date_start} to {date_end}"},
		{text: "Language: {language}"},
		{text: "Company: {company.name}"},
		{text: "Client: {client.firstname} {client.lastname} ({client.email})"},
		{text: "Client title: {client.title}    Phone: {client.phone}"},
		{text: ""},
		{text: "Scope", bold: true},
		{text: "{#scope}"},
		{text: "  - {name}"},
		{text: "{/scope}"},
		{text: ""},
		{text: "Findings", bold: true},
		{text: "{#findings}"},
		{text: "=========================================="},
		{text: "{identifier}  {title}", bold: true},
		{text: "Vulnerability type: {vulnType}"},
		{text: "Category: {category}"},
		{text: "Priority: {priority}    Remediation complexity: {remediationComplexity}"},
		// CVSS scores (only present when the finding has a CVSS 3.1 vector).
		{text: "{#cvss}"},
		{text: "CVSS 3.1 vector: {vectorString}"},
		{text: "CVSS base: {baseMetricScore} ({baseSeverity})"},
		{text: "CVSS temporal: {temporalMetricScore} ({temporalSeverity})"},
		{text: "CVSS environmental: {environmentalMetricScore} ({environmentalSeverity})"},
		{text: "{/cvss}"},
		// Every individual CVSS 3.1 metric, decoded to words.
		{text: "{#cvssObj}"},
		{text: "CVSS base metrics: AV={AV}  AC={AC}  PR={PR}  UI={UI}  S={S}  C={C}  I={I}  A={A}"},
		{text: "CVSS temporal: E={E}  RL={RL}  RC={RC}"},
		{text: "CVSS environmental: CR={CR}  IR={IR}  AR={AR}  MAV={MAV}  MAC={MAC}  MPR={MPR}  MUI={MUI}  MS={MS}  MC={MC}  MI={MI}  MA={MA}"},
		{text: "{/cvssObj}"},
		{text: ""},
		{text: "Affected assets:", bold: true},
		{text: "{@affected | convertHTML}"},
		{text: "Description:", bold: true},
	}
	ps = append(ps, reportFieldBlock("description")...)
	ps = append(ps, reportPara{text: "Observation:", bold: true})
	ps = append(ps, reportFieldBlock("observation")...)
	ps = append(ps, reportPara{text: "Proof of Concept:", bold: true})
	ps = append(ps, reportFieldBlock("poc")...)
	ps = append(ps, reportPara{text: "Remediation:", bold: true})
	ps = append(ps, reportFieldBlock("remediation")...)
	ps = append(ps,
		reportPara{text: "References:", bold: true},
		reportPara{text: "{#references}"},
		reportPara{text: "  - {.}"},
		reportPara{text: "{/references}"},
		reportPara{text: "{/findings}"},
	)
	return ps
}

func reportParagraphXML(p reportPara) string {
	var rpr string
	if p.bold || p.italic {
		var b strings.Builder
		b.WriteString("<w:rPr>")
		if p.bold {
			b.WriteString("<w:b/>")
		}
		if p.italic {
			b.WriteString("<w:i/>")
		}
		b.WriteString("</w:rPr>")
		rpr = b.String()
	}
	// Note: paragraph text is template-tag content with no XML-special
	// characters, so it is emitted verbatim (escaping { } is unnecessary and
	// would corrupt the tags). xml:space="preserve" keeps the spaces inside
	// tags like "{@text | convertHTML}".
	return "<w:p><w:r>" + rpr + `<w:t xml:space="preserve">` + p.text + "</w:t></w:r></w:p>"
}

// reportDocumentOpen is the <w:document> root with the FULL namespace set a Word
// document declares. This is essential: pwndoc's image module injects drawing
// markup using the wp:, a:, pic: and r: prefixes, so they must be declared on
// the root or the rendered document.xml becomes malformed and Word refuses to
// open it ("Word experienced an error trying to open the file").
const reportDocumentOpen = `<w:document ` +
	`xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" ` +
	`xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" ` +
	`xmlns:o="urn:schemas-microsoft-com:office:office" ` +
	`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ` +
	`xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" ` +
	`xmlns:v="urn:schemas-microsoft-com:vml" ` +
	`xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" ` +
	`xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" ` +
	`xmlns:w10="urn:schemas-microsoft-com:office:word" ` +
	`xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" ` +
	`xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" ` +
	`xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" ` +
	`xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" ` +
	`xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" ` +
	`xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" ` +
	`xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" ` +
	`xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture" ` +
	`mc:Ignorable="w14 wp14">`

func reportDocumentXML() string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(reportDocumentOpen)
	b.WriteString("<w:body>")
	for _, p := range reportBodyParagraphs() {
		b.WriteString(reportParagraphXML(p))
	}
	b.WriteString(`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>`)
	b.WriteString("</w:body></w:document>")
	return b.String()
}

const reportContentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Default Extension="png" ContentType="image/png"/>` +
	`<Default Extension="jpeg" ContentType="image/jpeg"/>` +
	`<Default Extension="jpg" ContentType="image/jpeg"/>` +
	`<Default Extension="gif" ContentType="image/gif"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>` +
	`<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>` +
	`</Types>`

const reportRootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
	`</Relationships>`

const reportDocumentRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
	`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>` +
	`</Relationships>`

// reportNumberingXML defines the list numbering the HTML-to-Word converter
// references: numId 1 is the bullet list (used by <ul>) and numId 2 is the
// ordered list (used by <ol>). Without these definitions, list paragraphs lose
// their bullets/numbers.
func reportNumberingXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:abstractNum w:abstractNumId="1"><w:multiLevelType w:val="hybridMultilevel"/>` +
		numberingLevels("bullet") +
		`</w:abstractNum>` +
		`<w:abstractNum w:abstractNumId="2"><w:multiLevelType w:val="multilevel"/>` +
		numberingLevels("decimal") +
		`</w:abstractNum>` +
		`<w:num w:numId="1"><w:abstractNumId w:val="1"/></w:num>` +
		`<w:num w:numId="2"><w:abstractNumId w:val="2"/></w:num>` +
		`</w:numbering>`
}

// numberingLevels emits 9 indentation levels for either a bullet or decimal
// list. Bullet levels use the Symbol bullet glyph; decimal levels number as
// "%n." per level.
func numberingLevels(kind string) string {
	var b strings.Builder
	for i := 0; i < 9; i++ {
		left := 720 * (i + 1)
		b.WriteString(`<w:lvl w:ilvl="` + strconv.Itoa(i) + `">`)
		b.WriteString(`<w:start w:val="1"/>`)
		if kind == "bullet" {
			b.WriteString(`<w:numFmt w:val="bullet"/><w:lvlText w:val="&#61623;"/>`)
		} else {
			b.WriteString(`<w:numFmt w:val="decimal"/><w:lvlText w:val="%` + strconv.Itoa(i+1) + `."/>`)
		}
		b.WriteString(`<w:lvlJc w:val="left"/>`)
		b.WriteString(`<w:pPr><w:ind w:left="` + strconv.Itoa(left) + `" w:hanging="360"/></w:pPr>`)
		if kind == "bullet" {
			b.WriteString(`<w:rPr><w:rFonts w:ascii="Symbol" w:hAnsi="Symbol" w:hint="default"/></w:rPr>`)
		}
		b.WriteString(`</w:lvl>`)
	}
	return b.String()
}

// Minimal styles: Normal + Heading1..6 so html2ooxml headings render reasonably.
func reportStylesXML() string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">`)
	b.WriteString(`<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>`)
	b.WriteString(`<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>`)
	sizes := []string{"36", "32", "28", "26", "24", "22"}
	for i, sz := range sizes {
		id := "Heading" + string(rune('1'+i))
		b.WriteString(`<w:style w:type="paragraph" w:styleId="` + id + `"><w:name w:val="heading ` + string(rune('1'+i)) + `"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="60"/></w:pPr><w:rPr><w:b/><w:sz w:val="` + sz + `"/></w:rPr></w:style>`)
	}
	// Styles referenced by the HTML-to-Word converter: Code (code block),
	// CodeChar (inline code run), Caption (figure legend), ListParagraph (lists).
	b.WriteString(`<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/><w:pPr><w:shd w:val="clear" w:color="auto" w:fill="F4F4F4"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="20"/></w:rPr></w:style>`)
	b.WriteString(`<w:style w:type="character" w:styleId="CodeChar"><w:name w:val="Code Char"/><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="20"/></w:rPr></w:style>`)
	b.WriteString(`<w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="caption"/><w:basedOn w:val="Normal"/><w:pPr><w:jc w:val="center"/></w:pPr><w:rPr><w:i/><w:sz w:val="18"/></w:rPr></w:style>`)
	b.WriteString(`<w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="720"/></w:pPr></w:style>`)
	b.WriteString(`</w:styles>`)
	return b.String()
}

// MinimalReportTemplateDocx builds a complete, valid pwndoc report template as a
// .docx byte slice, in memory. Upload it with Templates.Create / CreateDefault
// (or write it to disk) and assign it to an audit to generate reports without
// hunting for a working template.
//
// The template intentionally favors correctness and coverage over visual
// polish: it lays every audit and finding field out as plain labelled
// paragraphs, including images with captions and the full CVSS 3.1 breakdown.
func MinimalReportTemplateDocx() ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	files := []struct {
		name, body string
	}{
		{"[Content_Types].xml", reportContentTypesXML},
		{"_rels/.rels", reportRootRelsXML},
		{"word/_rels/document.xml.rels", reportDocumentRelsXML},
		{"word/document.xml", reportDocumentXML()},
		{"word/styles.xml", reportStylesXML()},
		{"word/numbering.xml", reportNumberingXML()},
	}
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CreateDefault uploads the built-in minimal report template (see
// MinimalReportTemplateDocx) under the given name and returns the stored
// template. This is the one-call way to give an instance a working report
// template.
func (s *TemplatesService) CreateDefault(ctx context.Context, name string) (*Template, error) {
	doc, err := MinimalReportTemplateDocx()
	if err != nil {
		return nil, err
	}
	return s.Create(ctx, CreateTemplateParams{
		Name: name,
		Ext:  "docx",
		File: base64.StdEncoding.EncodeToString(doc),
	})
}
