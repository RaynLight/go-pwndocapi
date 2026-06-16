package pwndoc

import "fmt"

// RemediationComplexity rates how hard a finding is to fix: 1=Easy, 2=Medium,
// 3=Complex.
type RemediationComplexity int

const (
	RemediationEasy    RemediationComplexity = 1
	RemediationMedium  RemediationComplexity = 2
	RemediationComplex RemediationComplexity = 3
)

// String returns a human-readable label.
func (r RemediationComplexity) String() string {
	switch r {
	case RemediationEasy:
		return "Easy"
	case RemediationMedium:
		return "Medium"
	case RemediationComplex:
		return "Complex"
	default:
		return fmt.Sprintf("RemediationComplexity(%d)", int(r))
	}
}

// Valid reports whether r is a known value.
func (r RemediationComplexity) Valid() bool { return r >= 1 && r <= 3 }

// Priority rates a finding's urgency: 1=Low, 2=Medium, 3=High, 4=Urgent.
type Priority int

const (
	PriorityLow    Priority = 1
	PriorityMedium Priority = 2
	PriorityHigh   Priority = 3
	PriorityUrgent Priority = 4
)

// String returns a human-readable label.
func (p Priority) String() string {
	switch p {
	case PriorityLow:
		return "Low"
	case PriorityMedium:
		return "Medium"
	case PriorityHigh:
		return "High"
	case PriorityUrgent:
		return "Urgent"
	default:
		return fmt.Sprintf("Priority(%d)", int(p))
	}
}

// Valid reports whether p is a known value.
func (p Priority) Valid() bool { return p >= 1 && p <= 4 }

// FindingStatus is a finding's editorial state: 0=Done, 1=Redacting. It is used
// via *FindingStatus on the wire so that 0 (Done) is not dropped by omitempty.
type FindingStatus int

const (
	FindingDone      FindingStatus = 0
	FindingRedacting FindingStatus = 1
)

// String returns a human-readable label.
func (s FindingStatus) String() string {
	switch s {
	case FindingDone:
		return "Done"
	case FindingRedacting:
		return "Redacting"
	default:
		return fmt.Sprintf("FindingStatus(%d)", int(s))
	}
}

// Valid reports whether s is a known value.
func (s FindingStatus) Valid() bool { return s == 0 || s == 1 }

// RetestStatus is the outcome of a retest: ok|ko|unknown|partial.
type RetestStatus string

const (
	RetestOK      RetestStatus = "ok"
	RetestKO      RetestStatus = "ko"
	RetestUnknown RetestStatus = "unknown"
	RetestPartial RetestStatus = "partial"
)

// Valid reports whether r is a known value.
func (r RetestStatus) Valid() bool {
	switch r {
	case RetestOK, RetestKO, RetestUnknown, RetestPartial:
		return true
	}
	return false
}

// AuditMode distinguishes a standalone audit from a multi-audit: default|multi.
type AuditMode string

const (
	AuditModeDefault AuditMode = "default"
	AuditModeMulti   AuditMode = "multi"
)
