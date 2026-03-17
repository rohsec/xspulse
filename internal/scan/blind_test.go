package scan

import "testing"

func TestBuildBlindPayloadAddsCallbackURLAndMarker(t *testing.T) {
	payload := BuildBlindPayload("https://bx.example/callback", "q")
	if payload == "" {
		t.Fatalf("expected payload")
	}
	if want := "https://bx.example/callback"; !contains(payload, want) {
		t.Fatalf("expected callback URL in payload: %q", payload)
	}
	if !contains(payload, "q") {
		t.Fatalf("expected parameter marker in payload: %q", payload)
	}
}

func TestBuildBlindPayloadReturnsEmptyWithoutCallback(t *testing.T) {
	if got := BuildBlindPayload("", "q"); got != "" {
		t.Fatalf("expected empty payload, got %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > len(sub) && (func() bool { return stringIndex(s, sub) >= 0 })()))
}
func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
