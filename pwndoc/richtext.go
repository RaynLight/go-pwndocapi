package pwndoc

import (
	"html"
	"strconv"
	"strings"
)

// Rich-text helpers.
//
// pwndoc stores a finding's prose fields (Description, Observation, Remediation,
// POC) and the affected-assets field as HTML, then converts a known subset of
// tags into Word formatting at report-generation time (its html2ooxml filter).
// These helpers emit exactly that supported subset, so what you write is what
// renders in the .docx:
//
//	Inline : Bold/Strong, Italic/Em, Underline, Strike, Highlight, Code
//	Blocks : Paragraph, Heading (h1-h6), Bullets (ul), Numbered (ol), CodeBlock (pre)
//	Misc   : LineBreak (br)
//
// Text arguments are HTML-escaped, so arbitrary strings (payloads with < > &)
// are safe. Helpers that take "htmlContent" do NOT escape, so you can nest the
// inline helpers; use Esc for literal text inside those.

// Esc HTML-escapes a string for safe inclusion as rich-text content.
func Esc(s string) string { return html.EscapeString(s) }

// Bold wraps text in <strong> (renders bold).
func Bold(text string) string { return "<strong>" + html.EscapeString(text) + "</strong>" }

// Italic wraps text in <em> (renders italic).
func Italic(text string) string { return "<em>" + html.EscapeString(text) + "</em>" }

// Underline wraps text in <u>.
func Underline(text string) string { return "<u>" + html.EscapeString(text) + "</u>" }

// Strike wraps text in <s> (strikethrough).
func Strike(text string) string { return "<s>" + html.EscapeString(text) + "</s>" }

// Highlight wraps text in a yellow <mark>.
func Highlight(text string) string { return HighlightWith(text, "#ffff25") }

// HighlightWith wraps text in a <mark> with the given background color (hex,
// e.g. "#ffff25"). pwndoc maps a fixed palette of hex codes to Word highlight
// colors and falls back to yellow for anything else; recognized values include
// "#ffff25" (yellow), "#8f0000" (dark red), "#8e0075" (dark magenta),
// "#817d0c" (dark yellow), "#807d78" (dark gray), "#c4c1bb" (light gray) and
// "#000000" (black). The style attribute is always emitted because pwndoc's
// converter dereferences it unconditionally.
func HighlightWith(text, hexColor string) string {
	if hexColor == "" {
		hexColor = "#ffff25"
	}
	esc := html.EscapeString(hexColor)
	return `<mark data-color="` + esc + `" style="background-color:` + esc + `">` +
		html.EscapeString(text) + `</mark>`
}

// Code wraps text in inline <code>.
func Code(text string) string { return "<code>" + html.EscapeString(text) + "</code>" }

// CodeBlock wraps text in a <pre><code class="language-<lang>"> block; pwndoc
// applies syntax highlighting using the language hint (e.g. "bash", "http",
// "json"). Pass an empty lang for plain preformatted text.
func CodeBlock(lang, text string) string {
	cls := ""
	if lang != "" {
		cls = ` class="language-` + html.EscapeString(lang) + `"`
	}
	return "<pre><code" + cls + ">" + html.EscapeString(text) + "</code></pre>"
}

// Para wraps inline HTML content in a <p>. Content is NOT escaped so the inline
// helpers can be nested; use Esc for literal text. (Named Para to avoid
// colliding with the Paragraph report-model type in findings.go.)
func Para(htmlContent string) string { return "<p>" + htmlContent + "</p>" }

// Heading wraps text in <h1>..<h6>; level is clamped to 1..6.
func Heading(level int, text string) string {
	if level < 1 {
		level = 1
	}
	if level > 6 {
		level = 6
	}
	tag := "h" + strconv.Itoa(level)
	return "<" + tag + ">" + html.EscapeString(text) + "</" + tag + ">"
}

// LineBreak is a <br>.
const LineBreak = "<br>"

// Bullets renders an unordered (<ul>) list. Each item is inline HTML (use Esc
// for literal text).
func Bullets(items ...string) string { return htmlList("ul", items) }

// Numbered renders an ordered (<ol>) list. Each item is inline HTML.
func Numbered(items ...string) string { return htmlList("ol", items) }

func htmlList(tag string, items []string) string {
	var b strings.Builder
	b.WriteString("<" + tag + ">")
	for _, it := range items {
		// Each item's content is wrapped in <p> because pwndoc's HTML->Word
		// converter only emits text for block elements; a bare <li>text</li>
		// produces no paragraph and the text is silently dropped.
		b.WriteString("<li><p>" + it + "</p></li>")
	}
	b.WriteString("</" + tag + ">")
	return b.String()
}

// Link renders an anchor. NOTE: pwndoc's HTML-to-Word converter renders the
// link text as plain text (it does not emit a clickable Word hyperlink for
// <a>). Provided for editor round-tripping; for clickable references use the
// finding References list instead.
func Link(href, text string) string {
	return `<a href="` + html.EscapeString(href) + `">` + html.EscapeString(text) + `</a>`
}

// RichText accumulates HTML rich-text content fluently. The zero value is ready
// to use; call String for the HTML.
//
//	html := pwndoc.NewRichText().
//	    H(3, "Summary").
//	    Text("The endpoint is vulnerable to SQL injection.").
//	    P("Affected parameter: " + pwndoc.Code("id")).
//	    Bullets("Confirmed on /api/users", "Confirmed on /api/orders").
//	    Code("bash", "sqlmap -u https://target/api/users?id=1").
//	    String()
type RichText struct{ b strings.Builder }

// NewRichText returns an empty RichText builder.
func NewRichText() *RichText { return &RichText{} }

// Raw appends pre-built HTML verbatim.
func (r *RichText) Raw(htmlContent string) *RichText { r.b.WriteString(htmlContent); return r }

// P appends a paragraph of inline HTML content (not escaped).
func (r *RichText) P(htmlContent string) *RichText { r.b.WriteString(Para(htmlContent)); return r }

// Text appends a paragraph of plain text (escaped).
func (r *RichText) Text(s string) *RichText { r.b.WriteString(Para(Esc(s))); return r }

// H appends a heading (level 1..6).
func (r *RichText) H(level int, s string) *RichText { r.b.WriteString(Heading(level, s)); return r }

// Bullets appends an unordered list.
func (r *RichText) Bullets(items ...string) *RichText { r.b.WriteString(Bullets(items...)); return r }

// Numbered appends an ordered list.
func (r *RichText) Numbered(items ...string) *RichText { r.b.WriteString(Numbered(items...)); return r }

// Code appends a syntax-highlighted code block.
func (r *RichText) Code(lang, s string) *RichText { r.b.WriteString(CodeBlock(lang, s)); return r }

// String returns the accumulated HTML.
func (r *RichText) String() string { return r.b.String() }

// FormattingShowcase returns rich-text HTML demonstrating every formatting style
// pwndoc renders in the .docx — bold, italic, underline, strikethrough,
// highlight (multiple colors), inline code, a syntax-highlighted code block, a
// heading, and both list types. Drop it into any finding HTML field
// (Description, Observation, Remediation, POC) or the affected-assets field.
func FormattingShowcase() string {
	return NewRichText().
		H(4, "Formatting examples").
		P("Inline styles: "+Bold("bold")+", "+Italic("italic")+", "+
			Underline("underline")+", "+Strike("strikethrough")+", "+
			Highlight("highlighted")+", and "+Code("inline code")+".").
		P("Highlight colors: "+HighlightWith("yellow", "#ffff25")+" "+
			HighlightWith("dark red", "#8f0000")+" "+HighlightWith("dark gray", "#807d78")+".").
		Bullets("Bullet one", "Bullet two with "+Bold("emphasis"), "Bullet three with "+Code("code()")).
		Numbered("First step", "Second step", "Third step").
		Code("bash", "curl -sk 'https://target/api/login' -d 'user=admin&pass=admin'").
		String()
}
