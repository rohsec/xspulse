package analyze

import (
	"testing"

	"github.com/rohsec/xspulse/internal/model"
)

func TestFindReflectionsCapturesAttributeMetadata(t *testing.T) {
	body := []byte(`<html><body><a href="__XSPULSE_MARKER__">x</a><input __XSPULSE_MARKER__="1"></body></html>`)
	refs := FindReflections(body, "__XSPULSE_MARKER__")
	if len(refs) < 2 {
		t.Fatalf("expected at least 2 reflections, got %#v", refs)
	}

	var hrefFound, nameFound bool
	for _, ref := range refs {
		if ref.Context != model.ContextAttribute {
			continue
		}
		if ref.Attribute == "href" {
			hrefFound = true
			if ref.AttributeType != model.AttributeTypeValue {
				t.Fatalf("expected href reflection to be value type, got %s", ref.AttributeType)
			}
			if ref.Quote != `"` {
				t.Fatalf("expected href reflection quote to be double quote, got %q", ref.Quote)
			}
		}
		if ref.Attribute == "__xspulse_marker__" {
			nameFound = true
			if ref.AttributeType != model.AttributeTypeName {
				t.Fatalf("expected attribute-name reflection, got %s", ref.AttributeType)
			}
		}
	}
	if !hrefFound || !nameFound {
		t.Fatalf("missing expected attribute reflections: %#v", refs)
	}
}

func TestFindReflectionsMarksScriptURLAttributes(t *testing.T) {
	body := []byte(`<html><body><script src="__XSPULSE_MARKER__"></script></body></html>`)
	refs := FindReflections(body, "__XSPULSE_MARKER__")
	if len(refs) == 0 {
		t.Fatalf("expected reflections")
	}
	if !refs[0].ScriptURL {
		t.Fatalf("expected script URL attribute to be marked, got %#v", refs[0])
	}
}
