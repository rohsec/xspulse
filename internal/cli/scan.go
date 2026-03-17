package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/rynosec/xspulse/internal/scan"
)

func RunScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.Usage = func() { PrintCommandHelp("scan") }
	c := commonFlags{}
	minConfidence := fs.Int("min-confidence", 70, "minimum confidence threshold")
	skipWAF := fs.Bool("skip-waf", false, "skip WAF detection")
	addCommonFlags(fs, &c)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ensureURL(c.URL); err != nil {
		return err
	}
	client, err := buildHTTPClient(c)
	if err != nil {
		return err
	}
	result, err := scan.Run(context.Background(), client, c.URL, c.Method, c.Data, scan.Options{Encoding: encoderKind(c.Encode), MinConfidence: *minConfidence, IncludeWAF: !*skipWAF, BlindCallback: c.BlindCallback})
	if err != nil {
		return err
	}

	if c.JSONOutput {
		return printAsJSONorText(true, "", result)
	}

	var b strings.Builder
	b.WriteString(headingText("[scan]") + "\n")
	b.WriteString(fmt.Sprintf("%s %s\n", strongText("target:"), result.URL))
	b.WriteString(fmt.Sprintf("%s %s\n", strongText("method:"), result.Method))
	if result.WAF != nil {
		if result.WAF.Detected {
			b.WriteString(fmt.Sprintf("%s %s %s\n", strongText("waf:"), badText("detected"), warnText(fmt.Sprintf("(%s, score=%.2f)", result.WAF.Name, result.WAF.Score))))
		} else {
			b.WriteString(fmt.Sprintf("%s %s\n", strongText("waf:"), okText("not detected")))
		}
	}
	if len(result.DOM) > 0 {
		b.WriteString(fmt.Sprintf("%s %s\n", strongText("dom-signals:"), warnText(fmt.Sprintf("%d", len(result.DOM)))))
	}
	if len(result.JSLibraries) > 0 {
		b.WriteString(fmt.Sprintf("%s %s\n", strongText("js-libraries:"), infoText(fmt.Sprintf("%d", len(result.JSLibraries)))))
	}
	if len(result.BlindPayloads) > 0 {
		b.WriteString(fmt.Sprintf("%s %s\n", strongText("blind-payloads:"), accentText(fmt.Sprintf("%d", len(result.BlindPayloads)))))
	}
	if len(result.Findings) == 0 {
		if result.Reflected {
			b.WriteString(warnText("reflections found, but no strong payload candidates crossed threshold") + "\n")
		} else {
			b.WriteString(subtleText("no reflected parameters detected") + "\n")
		}
		return printAsJSONorText(false, b.String(), nil)
	}
	for i, f := range result.Findings {
		sev := severityText(fmt.Sprintf("confidence=%d", f.Confidence), f.Confidence)
		b.WriteString(fmt.Sprintf("\n%s %s %s\n", accentText(fmt.Sprintf("[%d]", i+1)), strongText("param="+f.Parameter), sev))
		b.WriteString(fmt.Sprintf("%s %s\n", strongText("payload:"), badText(f.Payload)))
		for _, r := range f.Reflections {
			b.WriteString(fmt.Sprintf("  - %s=%s %s=%s %s=%s %s=%q\n", infoText("context"), string(r.Context), subtleText("tag"), r.Tag, subtleText("attr"), r.Attribute, subtleText("snippet"), r.Snippet))
		}
	}
	return printAsJSONorText(false, b.String(), nil)
}
