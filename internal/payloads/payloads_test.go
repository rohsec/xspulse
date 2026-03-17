package payloads

import (
	"testing"

	"github.com/rohsec/xspulse/internal/model"
)

func TestGeneratePrefersScriptBreakoutPayloads(t *testing.T) {
	refs := []model.Reflection{{
		Context:   model.ContextScript,
		Tag:       "script",
		Quote:     "'",
		ScriptURL: false,
	}}

	got := Generate(refs, model.EncodingNone)
	if len(got) == 0 {
		t.Fatalf("expected payloads")
	}
	if got[0] != `</script><svg/onload=confirm()>` {
		t.Fatalf("expected script breakout payload first, got %q", got[0])
	}
}

func TestGenerateAddsJavascriptAndEventPayloadsForHrefAttribute(t *testing.T) {
	refs := []model.Reflection{{
		Context:       model.ContextAttribute,
		Tag:           "a",
		Attribute:     "href",
		Quote:         `"`,
		AttributeType: model.AttributeTypeValue,
	}}

	got := Generate(refs, model.EncodingNone)
	if len(got) < 2 {
		t.Fatalf("expected multiple payloads, got %d", len(got))
	}
	if got[0] != `javascript:confirm()` {
		t.Fatalf("expected javascript URI payload first, got %q", got[0])
	}
	foundEvent := false
	for _, payload := range got {
		if payload == `"><svg/onload=confirm()>` {
			foundEvent = true
			break
		}
	}
	if !foundEvent {
		t.Fatalf("expected event breakout payload in generated set: %#v", got)
	}
}

func TestGenerateSupportsUnquotedAttributeBreakouts(t *testing.T) {
	refs := []model.Reflection{{
		Context:       model.ContextAttribute,
		Tag:           "input",
		Attribute:     "value",
		Quote:         "",
		AttributeType: model.AttributeTypeValue,
	}}

	got := Generate(refs, model.EncodingNone)
	want := ` autofocus onfocus=confirm() x=`
	for _, payload := range got {
		if payload == want {
			return
		}
	}
	t.Fatalf("expected unquoted attribute breakout payload %q in %#v", want, got)
}
