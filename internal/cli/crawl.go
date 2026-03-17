package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/rynosec/xspulse/internal/crawl"
	"github.com/rynosec/xspulse/internal/model"
	"github.com/rynosec/xspulse/internal/scan"
)

func RunCrawl(args []string) error {
	fs := flag.NewFlagSet("crawl", flag.ContinueOnError)
	fs.Usage = func() { PrintCommandHelp("crawl") }
	c := commonFlags{}
	depth := fs.Int("depth", 2, "crawl depth")
	doScan := fs.Bool("scan", false, "scan discovered forms")
	minConfidence := fs.Int("min-confidence", 70, "scan threshold for --scan")
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
	result, err := crawl.Run(context.Background(), client, c.URL, crawl.Options{Depth: *depth, Concurrency: c.Concurrency})
	if err != nil {
		return err
	}

	shouldScan := *doScan || c.BlindCallback != ""
	scans := []scan.Result{}
	if shouldScan {
		for _, form := range result.Forms {
			if len(form.Inputs) == 0 {
				continue
			}
			pairs := make([]string, 0, len(form.Inputs))
			for _, in := range form.Inputs {
				pairs = append(pairs, fmt.Sprintf("%s=%s", in.Name, in.Value))
			}
			sr, err := scan.Run(context.Background(), client, form.Action, form.Method, strings.Join(pairs, "&"), scan.Options{Encoding: model.EncodingNone, MinConfidence: *minConfidence, IncludeWAF: false, BlindCallback: c.BlindCallback})
			if err == nil {
				scans = append(scans, sr)
			}
		}
	}

	if c.JSONOutput {
		if shouldScan {
			return printAsJSONorText(true, "", map[string]any{"crawl": result, "scans": scans})
		}
		return printAsJSONorText(true, "", result)
	}

	var b strings.Builder
	b.WriteString(headingText("[crawl]") + "\n")
	b.WriteString(fmt.Sprintf("%s %s\n", strongText("seed:"), result.Seed))
	b.WriteString(fmt.Sprintf("%s %s\n", strongText("pages:"), infoText(fmt.Sprintf("%d", len(result.Pages)))))
	b.WriteString(fmt.Sprintf("%s %s\n", strongText("links:"), infoText(fmt.Sprintf("%d", len(result.Links)))))
	b.WriteString(fmt.Sprintf("%s %s\n", strongText("forms:"), infoText(fmt.Sprintf("%d", len(result.Forms)))))
	b.WriteString(fmt.Sprintf("%s %s\n", strongText("scripts:"), infoText(fmt.Sprintf("%d", len(result.Scripts)))))
	if len(result.JSLibraries) > 0 {
		b.WriteString(fmt.Sprintf("%s %s\n", strongText("js-libraries:"), warnText(fmt.Sprintf("%d", len(result.JSLibraries)))))
	}
	for _, page := range result.Pages {
		b.WriteString(fmt.Sprintf("  %s %s\n", subtleText("page:"), page))
	}
	if shouldScan {
		b.WriteString(fmt.Sprintf("%s %s\n", strongText("scanned_forms:"), accentText(fmt.Sprintf("%d", len(scans)))))
	}
	return printAsJSONorText(false, b.String(), nil)
}
