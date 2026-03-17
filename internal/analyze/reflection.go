package analyze

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/net/html"

	"github.com/rynosec/xspulse/internal/model"
)

func FindReflections(body []byte, marker string) []model.Reflection {
	var findings []model.Reflection
	findings = append(findings, commentReflections(string(body), marker)...)

	z := html.NewTokenizer(bytes.NewReader(body))
	inScript := false
	currentTag := ""

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return dedupeReflections(findings)
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			currentTag = strings.ToLower(tok.Data)
			rawToken := string(z.Raw())
			if currentTag == "script" {
				inScript = true
			}
			for _, attr := range tok.Attr {
				attrName := strings.ToLower(attr.Key)
				quote := quoteForAttribute(rawToken, attr.Key)
				if strings.Contains(attr.Val, marker) {
					findings = append(findings, model.Reflection{
						Marker: marker, Context: model.ContextAttribute,
						Tag: currentTag, Attribute: attrName, AttributeType: model.AttributeTypeValue, Quote: quote,
						ScriptURL: currentTag == "script" && attrName == "src", Snippet: clip(attr.Val),
					})
				}
				if strings.Contains(strings.ToLower(attr.Key), strings.ToLower(marker)) {
					findings = append(findings, model.Reflection{
						Marker: marker, Context: model.ContextAttribute,
						Tag: currentTag, Attribute: attrName, AttributeType: model.AttributeTypeName, Quote: quote,
						Snippet: clip(rawToken),
					})
				}
			}
		case html.EndTagToken:
			tok := z.Token()
			if strings.EqualFold(tok.Data, "script") {
				inScript = false
			}
		case html.TextToken:
			text := string(z.Text())
			if !strings.Contains(text, marker) {
				continue
			}
			if inScript {
				findings = append(findings, model.Reflection{Marker: marker, Context: model.ContextScript, Tag: currentTag, Snippet: clip(text)})
			} else {
				findings = append(findings, model.Reflection{Marker: marker, Context: model.ContextHTML, Tag: currentTag, Snippet: clip(text)})
			}
		}
	}
}

func commentReflections(body, marker string) []model.Reflection {
	out := []model.Reflection{}
	start := 0
	for {
		i := strings.Index(body[start:], "<!--")
		if i < 0 {
			break
		}
		i += start
		j := strings.Index(body[i+4:], "-->")
		if j < 0 {
			break
		}
		j += i + 4
		seg := body[i : j+3]
		if strings.Contains(seg, marker) {
			out = append(out, model.Reflection{Marker: marker, Context: model.ContextComment, Snippet: clip(seg)})
		}
		start = j + 3
	}
	return out
}

func guessQuote(v string) string {
	switch {
	case strings.Contains(v, "\""):
		return "\""
	case strings.Contains(v, "'"):
		return "'"
	default:
		return ""
	}
}

func quoteForAttribute(rawToken, attrName string) string {
	needle := strings.ToLower(attrName) + "="
	idx := strings.Index(strings.ToLower(rawToken), needle)
	if idx < 0 {
		return ""
	}
	rest := rawToken[idx+len(needle):]
	if len(rest) == 0 {
		return ""
	}
	switch rest[0] {
	case '\'', '"':
		return string(rest[0])
	default:
		return ""
	}
}

func clip(v string) string {
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, "\n", " ")
	v = strings.ReplaceAll(v, "\r", " ")
	if len(v) > 140 {
		return v[:140] + "..."
	}
	return v
}

func ScorePayloadReflections(body []byte, payload string, refs []model.Reflection) int {
	if len(refs) == 0 {
		return 0
	}
	score := 0
	lcBody := strings.ToLower(string(body))
	lcPayload := strings.ToLower(payload)
	if strings.Contains(lcBody, lcPayload) {
		score += 70
	}
	switch {
	case strings.Contains(lcBody, strings.ToLower(fmt.Sprintf("\"%s", payload))):
		score += 10
	case strings.Contains(lcBody, strings.ToLower(fmt.Sprintf("'%s", payload))):
		score += 10
	}
	for _, r := range refs {
		switch r.Context {
		case model.ContextScript:
			if strings.Contains(payload, "</script>") || strings.Contains(payload, "confirm") || strings.Contains(payload, "prompt") {
				score += 15
			}
		case model.ContextAttribute:
			if strings.Contains(payload, "onfocus") || strings.Contains(payload, "javascript:") || strings.Contains(payload, "onpointerenter") {
				score += 15
			}
		case model.ContextHTML, model.ContextComment:
			if strings.Contains(payload, "<svg") || strings.Contains(payload, "<img") || strings.Contains(payload, "<details") {
				score += 15
			}
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func dedupeReflections(in []model.Reflection) []model.Reflection {
	seen := map[string]bool{}
	out := make([]model.Reflection, 0, len(in))
	for _, r := range in {
		key := fmt.Sprintf("%s|%s|%s|%s|%s|%s", r.Context, r.Tag, r.Attribute, r.Quote, r.Snippet, r.Marker)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}
