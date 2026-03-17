package scan

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/rynosec/xspulse/internal/analyze"
	"github.com/rynosec/xspulse/internal/httpx"
	"github.com/rynosec/xspulse/internal/model"
	"github.com/rynosec/xspulse/internal/payloads"
	"github.com/rynosec/xspulse/internal/target"
	"github.com/rynosec/xspulse/internal/waf"
)

const Marker = "__XSPULSE_MARKER__"

type Options struct {
	Encoding      model.EncodingKind
	MinConfidence int
	IncludeWAF    bool
	BlindCallback string
}

type Result struct {
	URL           string                  `json:"url"`
	Method        string                  `json:"method"`
	WAF           *model.WAFResult        `json:"waf,omitempty"`
	Findings      []model.Finding         `json:"findings"`
	DOM           []model.DOMIssue        `json:"dom,omitempty"`
	JSLibraries   []model.JSLibrary       `json:"js_libraries,omitempty"`
	BlindPayloads []model.BlindXSSPayload `json:"blind_payloads,omitempty"`
	Reflected     bool                    `json:"reflected"`
	Parameters    []model.Parameter       `json:"parameters"`
}

func Run(ctx context.Context, c *httpx.Client, rawURL, method, data string, opts Options) (Result, error) {
	tgt, err := target.Parse(rawURL, method, data)
	if err != nil {
		return Result{}, err
	}
	res := Result{URL: tgt.URL.String(), Method: tgt.Method, Parameters: tgt.Parameters, Findings: []model.Finding{}}

	baseResp, err := c.Do(ctx, tgt.Method, tgt.URL.String(), tgt.RawData, "application/x-www-form-urlencoded")
	if err == nil {
		raw, _ := io.ReadAll(io.LimitReader(baseResp.Body, 2<<20))
		baseResp.Body.Close()
		res.DOM = analyze.AnalyzeDOM(tgt.URL.String(), raw)
		res.JSLibraries = analyze.DetectJSLibraries(tgt.URL.String(), raw)
	}

	if opts.IncludeWAF {
		wafResult, err := waf.Detect(ctx, c, tgt.URL.String())
		if err == nil {
			res.WAF = &wafResult
		}
	}

	for _, param := range tgt.Parameters {
		if blind := BuildBlindPayload(opts.BlindCallback, param.Name); blind != "" {
			blindURL, blindBody, err := tgt.CloneWith(param.Name, blind)
			if err == nil {
				blindResp, blindErr := c.Do(ctx, tgt.Method, blindURL, blindBody, "application/x-www-form-urlencoded")
				if blindResp != nil && blindResp.Body != nil {
					blindResp.Body.Close()
				}
				res.BlindPayloads = append(res.BlindPayloads, model.BlindXSSPayload{URL: blindURL, Method: tgt.Method, Parameter: param.Name, Payload: blind, Sent: blindErr == nil})
			}
		}
		injected := payloads.Encode(opts.Encoding, Marker)
		requestURL, body, err := tgt.CloneWith(param.Name, injected)
		if err != nil {
			return res, err
		}
		resp, err := c.Do(ctx, tgt.Method, requestURL, body, "application/x-www-form-urlencoded")
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		refs := analyze.FindReflections(raw, Marker)
		if len(refs) == 0 {
			continue
		}
		res.Reflected = true
		candidates := payloads.Generate(refs, opts.Encoding)
		for _, candidate := range candidates {
			testURL, testBody, err := tgt.CloneWith(param.Name, candidate)
			if err != nil {
				continue
			}
			testResp, err := c.Do(ctx, tgt.Method, testURL, testBody, "application/x-www-form-urlencoded")
			if err != nil {
				continue
			}
			testRaw, _ := io.ReadAll(io.LimitReader(testResp.Body, 2<<20))
			testResp.Body.Close()
			score := analyze.ScorePayloadReflections(testRaw, candidate, refs)
			if score < opts.MinConfidence {
				continue
			}
			notes := []string{fmt.Sprintf("generated from %d reflection context(s)", len(refs))}
			if strings.Contains(candidate, "javascript:") {
				notes = append(notes, "javascript URI payload")
			}
			res.Findings = append(res.Findings, model.Finding{
				URL: requestURL, Method: tgt.Method, Parameter: param.Name, Payload: candidate, Confidence: score, Reflections: refs, Notes: notes,
			})
			if score >= 95 {
				break
			}
		}
	}
	return res, nil
}
