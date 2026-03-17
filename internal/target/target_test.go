package target

import "testing"

func TestParseUsesDataForGETWhenURLHasNoQuery(t *testing.T) {
	tgt, err := Parse("https://example.com/search", "GET", "q=test&lang=en")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(tgt.Parameters) != 2 {
		t.Fatalf("expected GET params from data, got %#v", tgt.Parameters)
	}
	if tgt.Parameters[0].Name != "lang" || tgt.Parameters[1].Name != "q" {
		t.Fatalf("unexpected params: %#v", tgt.Parameters)
	}
}
