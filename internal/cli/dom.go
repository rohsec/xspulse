package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/rynosec/xspulse/internal/analyze"
)

func RunDOM(args []string) error {
	fs := flag.NewFlagSet("dom", flag.ContinueOnError)
	fs.Usage = func() { PrintCommandHelp("dom") }
	c := commonFlags{}
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
	resp, err := client.Do(context.Background(), "GET", c.URL, "", "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	issues := analyze.AnalyzeDOM(c.URL, raw)
	if c.JSONOutput {
		return printAsJSONorText(true, "", issues)
	}
	var b strings.Builder
	b.WriteString(headingText("[dom]") + "\n")
	if len(issues) == 0 {
		b.WriteString(subtleText("no DOM XSS signals found") + "\n")
	} else {
		for _, issue := range issues {
			b.WriteString(fmt.Sprintf("%s=%d %s=%s %s=%s %s=%s %s=%s\n", strongText("line"), issue.Line, infoText("kind"), warnText(issue.Kind), subtleText("source"), issue.Source, subtleText("sink"), issue.Sink, subtleText("code"), issue.CodeLine))
		}
	}
	return printAsJSONorText(false, b.String(), nil)
}
