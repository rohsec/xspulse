package analyze

import (
	"regexp"
	"strings"

	"github.com/rynosec/xspulse/internal/model"
)

var domSources = regexp.MustCompile(`(?i)\b(document\.(URL|documentURI|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|localStorage|sessionStorage)\b`)
var domSinks = regexp.MustCompile(`(?i)\b(eval|Function|setTimeout|setInterval|document\.(write|writeln)|innerHTML|outerHTML|insertAdjacentHTML|location\s*=|location\.assign|location\.replace)\b`)
var inlineScript = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)

func AnalyzeDOM(url string, body []byte) []model.DOMIssue {
	matches := inlineScript.FindAllSubmatch(body, -1)
	issues := []model.DOMIssue{}
	for _, m := range matches {
		block := string(m[1])
		lines := strings.Split(block, "\n")
		tainted := false
		lastSource := ""
		for i, line := range lines {
			src := domSources.FindString(line)
			if src != "" {
				tainted = true
				lastSource = src
			}
			sink := domSinks.FindString(line)
			if sink != "" && tainted {
				issues = append(issues, model.DOMIssue{URL: url, Line: i + 1, Kind: "source-to-sink", Source: lastSource, Sink: sink, CodeLine: strings.TrimSpace(line)})
			} else if sink != "" {
				issues = append(issues, model.DOMIssue{URL: url, Line: i + 1, Kind: "sink", Sink: sink, CodeLine: strings.TrimSpace(line)})
			} else if src != "" {
				issues = append(issues, model.DOMIssue{URL: url, Line: i + 1, Kind: "source", Source: src, CodeLine: strings.TrimSpace(line)})
			}
		}
	}
	return issues
}
