package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/rohsec/xspulse/internal/payloads"
	"github.com/rohsec/xspulse/internal/target"
)

func RunFuzz(args []string) error {
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	fs.Usage = func() { PrintCommandHelp("fuzz") }
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
	tgt, err := target.Parse(c.URL, c.Method, c.Data)
	if err != nil {
		return err
	}

	type row struct {
		Parameter string `json:"parameter"`
		Payload   string `json:"payload"`
		Outcome   string `json:"outcome"`
		Status    int    `json:"status"`
	}
	results := []row{}
	fuzzes := payloads.Fuzz(encoderKind(c.Encode))
	for _, p := range tgt.Parameters {
		for _, fv := range fuzzes {
			requestURL, body, _ := tgt.CloneWith(p.Name, fv)
			resp, err := client.Do(context.Background(), tgt.Method, requestURL, body, "application/x-www-form-urlencoded")
			if err != nil {
				continue
			}
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			bodyText := string(raw)
			outcome := "filtered"
			if resp.StatusCode >= 400 {
				outcome = "blocked"
			} else if strings.Contains(bodyText, fv) {
				outcome = "reflected"
			}
			results = append(results, row{Parameter: p.Name, Payload: fv, Outcome: outcome, Status: resp.StatusCode})
		}
	}
	if c.JSONOutput {
		return printAsJSONorText(true, "", results)
	}
	var b strings.Builder
	b.WriteString(headingText("[fuzz]") + "\n")
	for _, r := range results {
		outcome := subtleText(r.Outcome)
		switch r.Outcome {
		case "reflected":
			outcome = okText(r.Outcome)
		case "blocked":
			outcome = badText(r.Outcome)
		case "filtered":
			outcome = warnText(r.Outcome)
		}
		b.WriteString(fmt.Sprintf("%s=%s %s=%d %s=%s %s=%s\n", strongText("param"), r.Parameter, strongText("status"), r.Status, strongText("outcome"), outcome, strongText("payload"), r.Payload))
	}
	return printAsJSONorText(false, b.String(), nil)
}
