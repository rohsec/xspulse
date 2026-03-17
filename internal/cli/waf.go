package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/rynosec/xspulse/internal/waf"
)

func RunWAF(args []string) error {
	fs := flag.NewFlagSet("waf", flag.ContinueOnError)
	fs.Usage = func() { PrintCommandHelp("waf") }
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
	result, err := waf.Detect(context.Background(), client, c.URL)
	if err != nil {
		return err
	}
	if c.JSONOutput {
		return printAsJSONorText(true, "", result)
	}
	var b strings.Builder
	b.WriteString(headingText("[waf]") + "\n")
	if result.Detected {
		b.WriteString(fmt.Sprintf("%s %s %s\n", badText("detected:"), strongText(result.Name), warnText(fmt.Sprintf("(score=%.2f status=%d evidence=%s)", result.Score, result.Status, result.Evidence))))
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n", okText("not detected"), subtleText(fmt.Sprintf("(status=%d)", result.Status))))
	}
	return printAsJSONorText(false, b.String(), nil)
}
