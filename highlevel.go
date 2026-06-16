package pwndoc

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

// FindingField names a finding's rich-text (HTML) field. Images are embedded
// into one of these fields.
type FindingField string

const (
	FindingFieldPOC         FindingField = "poc"
	FindingFieldDescription FindingField = "description"
	FindingFieldObservation FindingField = "observation"
	FindingFieldRemediation FindingField = "remediation"
)

// imgTag builds the <img> element pwndoc understands: the src is the uploaded
// image's id and the alt is the caption (which the report generator renders as
// the figure caption). The caption is HTML-escaped.
func imgTag(imageID, caption string) string {
	return fmt.Sprintf(`<img src="%s" alt="%s">`, imageID, html.EscapeString(caption))
}

// appendImageHTML returns a copy of f with an image paragraph appended to the
// given rich-text field.
func appendImageHTML(f Finding, field FindingField, imageID, caption string) Finding {
	block := "<p>" + imgTag(imageID, caption) + "</p>"
	switch field {
	case FindingFieldDescription:
		f.Description += block
	case FindingFieldObservation:
		f.Observation += block
	case FindingFieldRemediation:
		f.Remediation += block
	default:
		f.POC += block
	}
	return f
}

// AttachImageToFinding uploads a local image and appends it, with the given
// caption, to the finding's proof-of-concept (POC) field. One call performs:
// upload -> get finding -> append <img> (immutable copy) -> update.
func (c *Client) AttachImageToFinding(ctx context.Context, auditID, findingID, imagePath, caption string) (*Finding, error) {
	return c.AttachImageToField(ctx, auditID, findingID, FindingFieldPOC, imagePath, caption)
}

// AttachImageToField uploads a local image and appends it, with the given
// caption, to the chosen rich-text field of the finding.
func (c *Client) AttachImageToField(ctx context.Context, auditID, findingID string, field FindingField, imagePath, caption string) (*Finding, error) {
	img, err := c.Images.UploadFile(ctx, imagePath, auditID)
	if err != nil {
		return nil, err
	}
	f, err := c.Findings.Get(ctx, auditID, findingID)
	if err != nil {
		return nil, err
	}
	updated := appendImageHTML(*f, field, img.ID, caption)
	return c.Findings.Update(ctx, auditID, findingID, updated)
}

var imgTagRe = regexp.MustCompile(`(?i)<img\b[^>]*>`)
var imgAltRe = regexp.MustCompile(`(?i)\salt="(?:[^"\\]|\\.)*"`)

// SetFigureCaption updates the caption (alt text) of the imageIndex-th image
// (0-based) in the finding's POC field.
func (c *Client) SetFigureCaption(ctx context.Context, auditID, findingID string, imageIndex int, caption string) (*Finding, error) {
	f, err := c.Findings.Get(ctx, auditID, findingID)
	if err != nil {
		return nil, err
	}
	updatedPOC, ok := setNthImgAlt(f.POC, imageIndex, caption)
	if !ok {
		return nil, fmt.Errorf("pwndoc: SetFigureCaption: no image at index %d in finding POC", imageIndex)
	}
	upd := *f
	upd.POC = updatedPOC
	return c.Findings.Update(ctx, auditID, findingID, upd)
}

func setNthImgAlt(htmlStr string, n int, caption string) (string, bool) {
	if n < 0 {
		return htmlStr, false
	}
	idx := -1
	var out strings.Builder
	last := 0
	found := false
	for _, loc := range imgTagRe.FindAllStringIndex(htmlStr, -1) {
		idx++
		if idx != n {
			continue
		}
		out.WriteString(htmlStr[last:loc[0]])
		out.WriteString(setImgAlt(htmlStr[loc[0]:loc[1]], caption))
		last = loc[1]
		found = true
		break
	}
	out.WriteString(htmlStr[last:])
	return out.String(), found
}

func setImgAlt(tag, caption string) string {
	alt := ` alt="` + html.EscapeString(caption) + `"`
	if imgAltRe.MatchString(tag) {
		return imgAltRe.ReplaceAllLiteralString(tag, alt)
	}
	if strings.HasSuffix(tag, "/>") {
		return tag[:len(tag)-2] + alt + "/>"
	}
	return tag[:len(tag)-1] + alt + ">"
}

// SetGlobalCaptionLabels sets the instance figure caption labels
// (settings.report.public.captions, e.g. ["Figure", "Table"]), preserving all
// other settings.
func (c *Client) SetGlobalCaptionLabels(ctx context.Context, labels []string) (*Settings, error) {
	cur, err := c.Settings.Get(ctx)
	if err != nil {
		return nil, err
	}
	cur.Report.Public.Captions = labels
	return c.Settings.Update(ctx, *cur)
}

// ImageSpec describes one image (and its caption) to attach to a finding. Set
// exactly one of Path, Reader or Bytes; Mime is required with Reader/Bytes and
// inferred for Path.
type ImageSpec struct {
	Path    string
	Reader  io.Reader
	Bytes   []byte
	Mime    string
	Name    string
	Caption string
}

// FindingImageGroup ties a block of (HTML) text to a set of images. Each group
// is appended to the finding's POC field as the images are uploaded.
type FindingImageGroup struct {
	Text   string
	Images []ImageSpec
}

// AddFindingWithImages creates a finding and uploads+embeds all images with
// their captions into the finding's POC field, in one call.
func (c *Client) AddFindingWithImages(ctx context.Context, auditID string, f Finding, groups ...FindingImageGroup) (*Finding, error) {
	var b strings.Builder
	b.WriteString(f.POC)
	for gi, g := range groups {
		if g.Text != "" {
			b.WriteString(g.Text)
		}
		for ii, spec := range g.Images {
			img, err := c.uploadSpec(ctx, auditID, spec)
			if err != nil {
				return nil, fmt.Errorf("pwndoc: AddFindingWithImages: group %d image %d: %w", gi, ii, err)
			}
			b.WriteString("<p>")
			b.WriteString(imgTag(img.ID, spec.Caption))
			b.WriteString("</p>")
		}
	}
	f.POC = b.String()
	return c.Findings.Create(ctx, auditID, f)
}

func (c *Client) uploadSpec(ctx context.Context, auditID string, s ImageSpec) (*Image, error) {
	switch {
	case s.Path != "":
		return c.Images.UploadFile(ctx, s.Path, auditID)
	case s.Reader != nil:
		return c.Images.UploadReader(ctx, s.Reader, s.Name, s.Mime, auditID)
	case len(s.Bytes) > 0:
		return c.Images.UploadBytes(ctx, s.Bytes, s.Mime, s.Name, auditID)
	default:
		return nil, errors.New("pwndoc: ImageSpec needs Path, Reader, or Bytes")
	}
}

// QuickFinding is the minimal-args fast path: create a finding with just a title
// and priority.
func (c *Client) QuickFinding(ctx context.Context, auditID, title string, priority Priority) (*Finding, error) {
	return c.Findings.Create(ctx, auditID, Finding{
		Title:    title,
		Priority: priority,
		Status:   Ptr(FindingRedacting),
	})
}

// SetCompany sets (creating if needed) the audit's company by name.
func (c *Client) SetCompany(ctx context.Context, auditID, name string) error {
	ref, err := c.resolveCompany(ctx, name)
	if err != nil {
		return err
	}
	return c.Audits.UpdateGeneral(ctx, auditID, AuditGeneral{Company: ref})
}

// SetClient sets (creating if needed) the audit's client contact by email.
func (c *Client) SetClient(ctx context.Context, auditID, email string) error {
	contact, err := c.resolveContact(ctx, email, "", "", nil)
	if err != nil {
		return err
	}
	return c.Audits.UpdateGeneral(ctx, auditID, AuditGeneral{Client: contact})
}

// SetScope replaces the audit scope with the given host strings.
func (c *Client) SetScope(ctx context.Context, auditID string, hosts ...string) error {
	return c.Audits.UpdateGeneral(ctx, auditID, AuditGeneral{Scope: hosts})
}

// SetDates sets the engagement start and end dates (ISO yyyy-mm-dd).
func (c *Client) SetDates(ctx context.Context, auditID, start, end string) error {
	return c.Audits.UpdateGeneral(ctx, auditID, AuditGeneral{
		DateStart: String(start), DateEnd: String(end),
	})
}

// GenerateReport generates the .docx report and writes it to outPath, creating
// parent directories as needed. It returns the number of bytes written.
func (c *Client) GenerateReport(ctx context.Context, auditID, outPath string) (int64, error) {
	if dir := filepath.Dir(outPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, fmt.Errorf("pwndoc: GenerateReport: %w", err)
		}
	}
	f, err := os.Create(outPath)
	if err != nil {
		return 0, fmt.Errorf("pwndoc: GenerateReport: %w", err)
	}
	defer f.Close()
	cw := &countingWriter{w: f}
	if err := c.Audits.GenerateTo(ctx, auditID, cw); err != nil {
		return cw.n, err
	}
	return cw.n, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}

// PentestBuilder fluently assembles and creates an audit with a company,
// client, scope, dates, collaborators, reviewers and template — all by
// human-readable name. Names are resolved to ids (auto-creating company and
// client when missing) when Run is called.
type PentestBuilder struct {
	c             *Client
	create        CreateAuditParams
	companyName   string
	clientEmail   string
	clientFirst   string
	clientLast    string
	collaborators []string
	reviewers     []string
	general       AuditGeneral
	queued        []Finding
}

// NewPentest starts a builder. name, language and auditType are required.
func (c *Client) NewPentest(name, language, auditType string) *PentestBuilder {
	return &PentestBuilder{
		c:      c,
		create: CreateAuditParams{Name: name, Language: language, AuditType: auditType},
	}
}

// Multi marks the audit as a multi-audit.
func (b *PentestBuilder) Multi() *PentestBuilder { b.create.Type = AuditModeMulti; return b }

// Parent links this audit under the given parent audit id.
func (b *PentestBuilder) Parent(id string) *PentestBuilder { b.create.ParentID = id; return b }

// Company sets the company by name (resolved/created at Run).
func (b *PentestBuilder) Company(name string) *PentestBuilder { b.companyName = name; return b }

// Client sets the client contact by email (resolved/created at Run).
func (b *PentestBuilder) Client(email, firstname, lastname string) *PentestBuilder {
	b.clientEmail, b.clientFirst, b.clientLast = email, firstname, lastname
	return b
}

// Scope appends scope host entries.
func (b *PentestBuilder) Scope(hosts ...string) *PentestBuilder {
	b.general.Scope = append(b.general.Scope, hosts...)
	return b
}

// Dates sets the engagement start and end dates (ISO yyyy-mm-dd).
func (b *PentestBuilder) Dates(start, end string) *PentestBuilder {
	b.general.DateStart, b.general.DateEnd = String(start), String(end)
	return b
}

// Collaborators adds collaborators by username (or email), resolved at Run.
func (b *PentestBuilder) Collaborators(usernames ...string) *PentestBuilder {
	b.collaborators = append(b.collaborators, usernames...)
	return b
}

// Reviewers adds reviewers by username (or email), resolved at Run.
func (b *PentestBuilder) Reviewers(usernames ...string) *PentestBuilder {
	b.reviewers = append(b.reviewers, usernames...)
	return b
}

// Template sets the report template id.
func (b *PentestBuilder) Template(id string) *PentestBuilder {
	b.general.Template = String(id)
	return b
}

// AddFinding queues a finding to be created once the audit exists.
func (b *PentestBuilder) AddFinding(f Finding) *PentestBuilder {
	b.queued = append(b.queued, f)
	return b
}

// Run creates the audit, resolves all names to ids (auto-creating company and
// client when missing), applies the general settings, and flushes queued
// findings. It returns the freshly fetched, fully-populated audit.
func (b *PentestBuilder) Run(ctx context.Context) (*Audit, error) {
	a, err := b.c.Audits.Create(ctx, b.create)
	if err != nil {
		return nil, err
	}

	var companyRef *CompanyRef
	if b.companyName != "" {
		if companyRef, err = b.c.resolveCompany(ctx, b.companyName); err != nil {
			return a, err
		}
		b.general.Company = companyRef
	}
	if b.clientEmail != "" {
		contact, cerr := b.c.resolveContact(ctx, b.clientEmail, b.clientFirst, b.clientLast, companyRef)
		if cerr != nil {
			return a, cerr
		}
		b.general.Client = contact
	}
	if len(b.collaborators) > 0 {
		if b.general.Collaborators, err = b.c.resolveUsers(ctx, b.collaborators); err != nil {
			return a, err
		}
	}
	if len(b.reviewers) > 0 {
		if b.general.Reviewers, err = b.c.resolveUsers(ctx, b.reviewers); err != nil {
			return a, err
		}
	}

	if !isZeroGeneral(b.general) {
		if err := b.c.Audits.UpdateGeneral(ctx, a.ID, b.general); err != nil {
			return a, fmt.Errorf("pwndoc: created audit %s but failed to set general info: %w", a.ID, err)
		}
	}
	for i, f := range b.queued {
		if _, err := b.c.Findings.Create(ctx, a.ID, f); err != nil {
			return a, fmt.Errorf("pwndoc: created audit %s but finding %d (%q) failed: %w", a.ID, i, f.Title, err)
		}
	}
	if full, gerr := b.c.Audits.Get(ctx, a.ID); gerr == nil {
		a = full
	}
	return a, nil
}

func isZeroGeneral(g AuditGeneral) bool {
	return reflect.DeepEqual(g, AuditGeneral{})
}
