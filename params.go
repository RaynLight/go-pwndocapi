package pwndoc

// Ptr returns a pointer to v. Use it for the tri-state pointer fields in update
// params where the zero value (0, "", false) is a meaningful value that must
// not be dropped by omitempty.
func Ptr[T any](v T) *T { return &v }

// String returns a pointer to s. Convenience alias for Ptr[string].
func String(s string) *string { return &s }

// Int returns a pointer to i. Convenience alias for Ptr[int].
func Int(i int) *int { return &i }

// Bool returns a pointer to b. Convenience alias for Ptr[bool].
func Bool(b bool) *bool { return &b }
