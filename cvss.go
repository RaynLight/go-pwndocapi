package pwndoc

import (
	"fmt"
	"strings"
)

// CVSS 3.1 metric values. Each metric is a small typed string so editor
// autocompletion offers only the legal values. The single-letter codes match
// the CVSS v3.1 specification and are what pwndoc's scoring engine
// (ae-cvss-calculator) expects inside a vector string.
//
// "Not Defined" (X) is the implicit default for every optional metric: leave a
// field empty (or set it to its X constant) and CVSS31.Vector omits it.

// AttackVector (AV) — base metric. Required.
type AttackVector string

const (
	AVNetwork  AttackVector = "N" // Network
	AVAdjacent AttackVector = "A" // Adjacent network
	AVLocal    AttackVector = "L" // Local
	AVPhysical AttackVector = "P" // Physical
)

// AttackComplexity (AC) — base metric. Required.
type AttackComplexity string

const (
	ACLow  AttackComplexity = "L"
	ACHigh AttackComplexity = "H"
)

// PrivilegesRequired (PR) — base metric. Required.
type PrivilegesRequired string

const (
	PRNone PrivilegesRequired = "N"
	PRLow  PrivilegesRequired = "L"
	PRHigh PrivilegesRequired = "H"
)

// UserInteraction (UI) — base metric. Required.
type UserInteraction string

const (
	UINone     UserInteraction = "N"
	UIRequired UserInteraction = "R"
)

// CVSSScope (S) — base metric. Required. ("Scope" is named CVSSScope to avoid
// colliding with audit scope.)
type CVSSScope string

const (
	ScopeUnchanged CVSSScope = "U"
	ScopeChanged   CVSSScope = "C"
)

// Impact is the value type shared by the Confidentiality (C), Integrity (I) and
// Availability (A) base metrics. All three are required.
type Impact string

const (
	ImpactNone Impact = "N"
	ImpactLow  Impact = "L"
	ImpactHigh Impact = "H"
)

// ExploitCodeMaturity (E) — temporal metric. Optional.
type ExploitCodeMaturity string

const (
	ENotDefined     ExploitCodeMaturity = "X"
	EUnproven       ExploitCodeMaturity = "U"
	EProofOfConcept ExploitCodeMaturity = "P"
	EFunctional     ExploitCodeMaturity = "F"
	EHigh           ExploitCodeMaturity = "H"
)

// RemediationLevel (RL) — temporal metric. Optional.
type RemediationLevel string

const (
	RLNotDefined   RemediationLevel = "X"
	RLOfficialFix  RemediationLevel = "O"
	RLTemporaryFix RemediationLevel = "T"
	RLWorkaround   RemediationLevel = "W"
	RLUnavailable  RemediationLevel = "U"
)

// ReportConfidence (RC) — temporal metric. Optional.
type ReportConfidence string

const (
	RCNotDefined ReportConfidence = "X"
	RCUnknown    ReportConfidence = "U"
	RCReasonable ReportConfidence = "R"
	RCConfirmed  ReportConfidence = "C"
)

// SecurityRequirement is the value type shared by the Confidentiality (CR),
// Integrity (IR) and Availability (AR) environmental requirement metrics.
type SecurityRequirement string

const (
	ReqNotDefined SecurityRequirement = "X"
	ReqLow        SecurityRequirement = "L"
	ReqMedium     SecurityRequirement = "M"
	ReqHigh       SecurityRequirement = "H"
)

// Modified base metrics (environmental). Each accepts the same values as its
// base metric plus "X" (Not Defined). They are typed as strings so any of the
// matching base constants can be assigned, e.g. MAV: string(AVNetwork).
type (
	ModAttackVector       string // MAV: X|N|A|L|P
	ModAttackComplexity   string // MAC: X|L|H
	ModPrivilegesRequired string // MPR: X|N|L|H
	ModUserInteraction    string // MUI: X|N|R
	ModScope              string // MS:  X|U|C
	ModImpact             string // MC/MI/MA: X|N|L|H
)

// NotDefined is the universal "X" value for any modified/environmental metric.
const NotDefined = "X"

// CVSS31 holds every CVSS v3.1 metric. The eight base metrics are required to
// form a valid vector; temporal and environmental metrics are optional and are
// omitted from the vector string when empty or "X" (Not Defined).
//
// Build a vector and attach it to a finding:
//
//	v := pwndoc.CVSS31{
//	    AV: pwndoc.AVNetwork, AC: pwndoc.ACLow, PR: pwndoc.PRNone, UI: pwndoc.UINone,
//	    S: pwndoc.ScopeUnchanged, C: pwndoc.ImpactHigh, I: pwndoc.ImpactHigh, A: pwndoc.ImpactHigh,
//	}
//	finding.CVSSv3 = v.Vector() // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
//
// pwndoc computes the base/temporal/environmental scores and severities from
// this string at report-generation time.
type CVSS31 struct {
	// Base (required)
	AV AttackVector
	AC AttackComplexity
	PR PrivilegesRequired
	UI UserInteraction
	S  CVSSScope
	C  Impact
	I  Impact
	A  Impact

	// Temporal (optional)
	E  ExploitCodeMaturity
	RL RemediationLevel
	RC ReportConfidence

	// Environmental — security requirements (optional)
	CR SecurityRequirement
	IR SecurityRequirement
	AR SecurityRequirement

	// Environmental — modified base (optional)
	MAV ModAttackVector
	MAC ModAttackComplexity
	MPR ModPrivilegesRequired
	MUI ModUserInteraction
	MS  ModScope
	MC  ModImpact
	MI  ModImpact
	MA  ModImpact
}

// cvssOrder is the canonical metric ordering used in a CVSS v3.1 vector string.
var cvssOrder = []string{
	"AV", "AC", "PR", "UI", "S", "C", "I", "A",
	"E", "RL", "RC",
	"CR", "IR", "AR",
	"MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
}

func (c CVSS31) metricMap() map[string]string {
	return map[string]string{
		"AV": string(c.AV), "AC": string(c.AC), "PR": string(c.PR), "UI": string(c.UI),
		"S": string(c.S), "C": string(c.C), "I": string(c.I), "A": string(c.A),
		"E": string(c.E), "RL": string(c.RL), "RC": string(c.RC),
		"CR": string(c.CR), "IR": string(c.IR), "AR": string(c.AR),
		"MAV": string(c.MAV), "MAC": string(c.MAC), "MPR": string(c.MPR),
		"MUI": string(c.MUI), "MS": string(c.MS), "MC": string(c.MC),
		"MI": string(c.MI), "MA": string(c.MA),
	}
}

// Vector returns the CVSS v3.1 vector string (prefixed "CVSS:3.1/"), including
// every set metric in canonical order and omitting any that are empty or "X".
// It does not validate; use Validate to check base-metric completeness.
func (c CVSS31) Vector() string {
	m := c.metricMap()
	var b strings.Builder
	b.WriteString("CVSS:3.1")
	for _, k := range cvssOrder {
		v := strings.TrimSpace(m[k])
		if v == "" || v == NotDefined {
			continue
		}
		b.WriteByte('/')
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(v)
	}
	return b.String()
}

// String is an alias for Vector.
func (c CVSS31) String() string { return c.Vector() }

// baseMetrics lists the required metrics and the legal value set for each.
var baseMetrics = []struct {
	key    string
	values map[string]bool
}{
	{"AV", set("N", "A", "L", "P")},
	{"AC", set("L", "H")},
	{"PR", set("N", "L", "H")},
	{"UI", set("N", "R")},
	{"S", set("U", "C")},
	{"C", set("N", "L", "H")},
	{"I", set("N", "L", "H")},
	{"A", set("N", "L", "H")},
}

// Validate reports an error if any of the eight required base metrics is unset
// or holds an illegal value.
func (c CVSS31) Validate() error {
	m := c.metricMap()
	var missing []string
	for _, bm := range baseMetrics {
		v := strings.TrimSpace(m[bm.key])
		if v == "" {
			missing = append(missing, bm.key)
			continue
		}
		if !bm.values[v] {
			return fmt.Errorf("pwndoc: CVSS31: illegal value %q for base metric %s", v, bm.key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("pwndoc: CVSS31: missing required base metric(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

// ParseCVSS31 parses a CVSS v3.1 vector string into a CVSS31. The leading
// "CVSS:3.1/" prefix is optional. A "CVSS:3.0/" prefix is rejected (the scoring
// guidance differs between versions). Unknown metric keys are ignored.
func ParseCVSS31(vector string) (CVSS31, error) {
	var c CVSS31
	vector = strings.TrimSpace(vector)
	if vector == "" {
		return c, fmt.Errorf("pwndoc: ParseCVSS31: empty vector")
	}
	parts := strings.Split(vector, "/")
	assign := map[string]func(string){
		"AV":  func(v string) { c.AV = AttackVector(v) },
		"AC":  func(v string) { c.AC = AttackComplexity(v) },
		"PR":  func(v string) { c.PR = PrivilegesRequired(v) },
		"UI":  func(v string) { c.UI = UserInteraction(v) },
		"S":   func(v string) { c.S = CVSSScope(v) },
		"C":   func(v string) { c.C = Impact(v) },
		"I":   func(v string) { c.I = Impact(v) },
		"A":   func(v string) { c.A = Impact(v) },
		"E":   func(v string) { c.E = ExploitCodeMaturity(v) },
		"RL":  func(v string) { c.RL = RemediationLevel(v) },
		"RC":  func(v string) { c.RC = ReportConfidence(v) },
		"CR":  func(v string) { c.CR = SecurityRequirement(v) },
		"IR":  func(v string) { c.IR = SecurityRequirement(v) },
		"AR":  func(v string) { c.AR = SecurityRequirement(v) },
		"MAV": func(v string) { c.MAV = ModAttackVector(v) },
		"MAC": func(v string) { c.MAC = ModAttackComplexity(v) },
		"MPR": func(v string) { c.MPR = ModPrivilegesRequired(v) },
		"MUI": func(v string) { c.MUI = ModUserInteraction(v) },
		"MS":  func(v string) { c.MS = ModScope(v) },
		"MC":  func(v string) { c.MC = ModImpact(v) },
		"MI":  func(v string) { c.MI = ModImpact(v) },
		"MA":  func(v string) { c.MA = ModImpact(v) },
	}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.EqualFold(p, "CVSS:3.0") {
			// Refuse to silently coerce a v3.0 vector to v3.1: the scoring
			// guidance differs, so re-labelling it could change the score.
			return c, fmt.Errorf("pwndoc: ParseCVSS31: got a CVSS v3.0 vector, want v3.1")
		}
		if p == "" || strings.EqualFold(p, "CVSS:3.1") {
			continue
		}
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			return c, fmt.Errorf("pwndoc: ParseCVSS31: malformed metric %q", p)
		}
		if fn, ok := assign[strings.ToUpper(kv[0])]; ok {
			fn(strings.TrimSpace(kv[1]))
		}
	}
	return c, nil
}

func set(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}
