package pwndoc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestImgTagEscapesCaption(t *testing.T) {
	got := imgTag("abc123", `a "quote" & <tag>`)
	want := `<img src="abc123" alt="a &#34;quote&#34; &amp; &lt;tag&gt;">`
	if got != want {
		t.Errorf("imgTag = %q, want %q", got, want)
	}
}

func TestAppendImageHTMLImmutable(t *testing.T) {
	orig := Finding{POC: "<p>x</p>"}
	updated := appendImageHTML(orig, FindingFieldPOC, "id1", "cap")
	if orig.POC != "<p>x</p>" {
		t.Errorf("original mutated: %q", orig.POC)
	}
	if !strings.HasPrefix(updated.POC, "<p>x</p>") || !strings.Contains(updated.POC, `src="id1"`) {
		t.Errorf("updated POC = %q", updated.POC)
	}

	d := appendImageHTML(Finding{}, FindingFieldDescription, "id2", "c")
	if !strings.Contains(d.Description, `src="id2"`) || d.POC != "" {
		t.Errorf("description field routing wrong: %+v", d)
	}
}

func TestSetNthImgAlt(t *testing.T) {
	in := `<p><img src="a"></p><p><img src="b" alt="old"></p>`
	// index 1 has an existing alt -> replace
	out, ok := setNthImgAlt(in, 1, "new")
	if !ok || !strings.Contains(out, `<img src="b" alt="new">`) {
		t.Errorf("replace alt: ok=%v out=%q", ok, out)
	}
	// index 0 has no alt -> insert
	out0, ok0 := setNthImgAlt(in, 0, "first")
	if !ok0 || !strings.Contains(out0, `alt="first"`) {
		t.Errorf("insert alt: ok=%v out=%q", ok0, out0)
	}
	// out of range
	if _, ok := setNthImgAlt(in, 5, "x"); ok {
		t.Error("expected ok=false for out-of-range index")
	}
}

func TestDataURIAndDetectMime(t *testing.T) {
	uri := DataURI("image/png", []byte("hello"))
	if !strings.HasPrefix(uri, "data:image/png;base64,") {
		t.Errorf("DataURI = %q", uri)
	}
	if mt := detectMime("shot.png", nil); mt != "image/png" {
		t.Errorf("detectMime(.png) = %q", mt)
	}
	if mt := detectMime("shot.jpg", nil); mt != "image/jpeg" {
		t.Errorf("detectMime(.jpg) = %q", mt)
	}
	// no extension -> content sniff (GIF magic)
	gif := []byte("GIF89a\x00\x00")
	if mt := detectMime("noext", gif); mt != "image/gif" {
		t.Errorf("detectMime(sniff) = %q", mt)
	}
}

func TestEnums(t *testing.T) {
	if PriorityHigh.String() != "High" || !PriorityHigh.Valid() {
		t.Error("PriorityHigh")
	}
	if Priority(9).Valid() {
		t.Error("Priority(9) should be invalid")
	}
	if RemediationComplex.String() != "Complex" || !RemediationComplex.Valid() {
		t.Error("RemediationComplex")
	}
	if FindingDone.String() != "Done" || !FindingDone.Valid() {
		t.Error("FindingDone")
	}
	if !RetestPartial.Valid() || RetestStatus("nope").Valid() {
		t.Error("RetestStatus validity")
	}
}

func TestFindingStatusPointerMarshals(t *testing.T) {
	// Status pointer with value 0 (Done) must NOT be dropped.
	f := Finding{Title: "x", Status: Ptr(FindingDone)}
	b, _ := json.Marshal(f)
	if !strings.Contains(string(b), `"status":0`) {
		t.Errorf("status 0 dropped: %s", b)
	}
	// nil status is omitted.
	b2, _ := json.Marshal(Finding{Title: "x"})
	if strings.Contains(string(b2), "status") {
		t.Errorf("nil status should be omitted: %s", b2)
	}
}

func TestCompanyRefUnmarshalStringOrObject(t *testing.T) {
	var r1 CompanyRef
	if err := json.Unmarshal([]byte(`"abc123"`), &r1); err != nil || r1.ID != "abc123" {
		t.Errorf("string id: %+v err=%v", r1, err)
	}
	var r2 CompanyRef
	if err := json.Unmarshal([]byte(`{"name":"Acme"}`), &r2); err != nil || r2.Name != "Acme" {
		t.Errorf("object: %+v err=%v", r2, err)
	}
	var c Contact
	if err := json.Unmarshal([]byte(`{"_id":"c1","email":"x@y.z","company":"comp1"}`), &c); err != nil {
		t.Fatalf("contact unmarshal: %v", err)
	}
	if c.Company == nil || c.Company.ID != "comp1" {
		t.Errorf("contact company = %+v", c.Company)
	}
}

func TestSettingsRoundTripPreservesUnknownKeys(t *testing.T) {
	raw := `{"report":{"enabled":true,"public":{"captions":["Figure"],"highlightWarning":true},"private":{"imageBorder":false}},"reviews":{"enabled":false}}`
	var s Settings
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(s.Report.Public.Captions) != 1 || s.Report.Public.Captions[0] != "Figure" {
		t.Errorf("captions = %+v", s.Report.Public.Captions)
	}
	s.Report.Public.Captions = []string{"Figure", "Table"}
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	_ = json.Unmarshal(out, &back)
	report := back["report"].(map[string]any)
	public := report["public"].(map[string]any)
	// captions updated
	caps := public["captions"].([]any)
	if len(caps) != 2 {
		t.Errorf("captions not updated: %v", caps)
	}
	// unknown key preserved
	if public["highlightWarning"] != true {
		t.Errorf("highlightWarning not preserved: %v", public["highlightWarning"])
	}
	if report["enabled"] != true {
		t.Errorf("report.enabled not preserved")
	}
	if _, ok := report["private"]; !ok {
		t.Errorf("report.private not preserved")
	}
}

func TestIsZeroGeneral(t *testing.T) {
	if !isZeroGeneral(AuditGeneral{}) {
		t.Error("empty AuditGeneral should be zero")
	}
	if isZeroGeneral(AuditGeneral{Name: String("x")}) {
		t.Error("non-empty AuditGeneral should not be zero")
	}
}

func TestDecodeEnvelopeNonJSON(t *testing.T) {
	_, err := decodeEnvelope[map[string]any]([]byte("<html>502 Bad Gateway</html>"), 502)
	if err == nil {
		t.Fatal("expected error for non-JSON body")
	}
	ae, ok := AsAPIError(err)
	if !ok || ae.StatusCode != 502 || !strings.Contains(ae.Message, "Bad Gateway") {
		t.Errorf("APIError = %+v", ae)
	}
}
