package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rohsec/xspulse/internal/target"
)

func RunBruteforce(args []string) error {
	fs := flag.NewFlagSet("bruteforce", flag.ContinueOnError)
	fs.Usage = func() { PrintCommandHelp("bruteforce") }
	c := commonFlags{}
	payloadFile := fs.String("p", "", "payload file")
	fs.StringVar(payloadFile, "payloads", "", "payload file")
	addCommonFlags(fs, &c)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := ensureURL(c.URL); err != nil {
		return err
	}
	if strings.TrimSpace(*payloadFile) == "" {
		return fmt.Errorf("payload file is required")
	}
	client, err := buildHTTPClient(c)
	if err != nil {
		return err
	}
	tgt, err := target.Parse(c.URL, c.Method, c.Data)
	if err != nil {
		return err
	}
	payloads, err := readPayloads(*payloadFile)
	if err != nil {
		return err
	}

	type hit struct {
		Parameter string `json:"parameter"`
		Payload   string `json:"payload"`
		Reflected bool   `json:"reflected"`
		Status    int    `json:"status"`
	}
	hits := []hit{}
	for _, p := range tgt.Parameters {
		for _, payload := range payloads {
			reqURL, body, _ := tgt.CloneWith(p.Name, payload)
			resp, err := client.Do(context.Background(), tgt.Method, reqURL, body, "application/x-www-form-urlencoded")
			if err != nil {
				continue
			}
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			hits = append(hits, hit{Parameter: p.Name, Payload: payload, Reflected: strings.Contains(string(raw), payload), Status: resp.StatusCode})
		}
	}
	if c.JSONOutput {
		return printAsJSONorText(true, "", hits)
	}
	var b strings.Builder
	b.WriteString(headingText("[bruteforce]") + "\n")
	reflectedCount := 0
	for _, h := range hits {
		if h.Reflected {
			reflectedCount++
			b.WriteString(fmt.Sprintf("%s=%s %s=%d %s %s=%s\n", strongText("param"), h.Parameter, strongText("status"), h.Status, okText("reflected"), strongText("payload"), badText(h.Payload)))
		}
	}
	if reflectedCount == 0 {
		b.WriteString(subtleText("no reflected payloads found") + "\n")
	}
	return printAsJSONorText(false, b.String(), nil)
}

func readPayloads(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, s.Err()
}
