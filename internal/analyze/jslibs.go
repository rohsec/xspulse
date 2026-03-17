package analyze

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"

	"github.com/rohsec/xspulse/internal/model"
)

type jsSignature struct {
	Name        string
	URLPattern  *regexp.Regexp
	TextPattern *regexp.Regexp
	MinSafe     string
	Severity    string
	Notes       string
}

var jsSignatures = []jsSignature{
	{
		Name:        "jquery",
		URLPattern:  regexp.MustCompile(`(?i)jquery[-.]v?(\d+(?:\.\d+){0,2})`),
		TextPattern: regexp.MustCompile(`(?i)jquery\s+v?(\d+(?:\.\d+){0,2})`),
		MinSafe:     "3.5.0",
		Severity:    "medium",
		Notes:       "Older jQuery branches are commonly associated with XSS-prone usage and legacy vulnerabilities.",
	},
	{
		Name:        "vue",
		URLPattern:  regexp.MustCompile(`(?i)vue(?:\.runtime(?:\.min)?)?[-.]v?(\d+(?:\.\d+){0,2})`),
		TextPattern: regexp.MustCompile(`(?i)vue(?:\.js)?\s+v?(\d+(?:\.\d+){0,2})`),
		MinSafe:     "3.0.0",
		Severity:    "info",
		Notes:       "Legacy Vue 2.x may be worth reviewing depending on application usage and sanitization assumptions.",
	},
	{
		Name:        "angularjs",
		URLPattern:  regexp.MustCompile(`(?i)angular(?:\.min)?[-.]v?(\d+(?:\.\d+){0,2})`),
		TextPattern: regexp.MustCompile(`(?i)angularjs\s+v?(\d+(?:\.\d+){0,2})`),
		MinSafe:     "1.8.3",
		Severity:    "medium",
		Notes:       "AngularJS is end-of-life and often security-relevant in older frontends.",
	},
}

func DetectJSLibraries(pageURL string, body []byte) []model.JSLibrary {
	results := []model.JSLibrary{}
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return dedupeJSLibraries(results)
		case html.StartTagToken:
			tok := z.Token()
			if !strings.EqualFold(tok.Data, "script") {
				continue
			}
			for _, attr := range tok.Attr {
				if strings.EqualFold(attr.Key, "src") {
					results = append(results, detectLibraryFromString(pageURL, attr.Val)...)
				}
			}
		case html.TextToken:
			text := string(z.Text())
			if strings.TrimSpace(text) == "" {
				continue
			}
			results = append(results, detectLibraryFromText(pageURL, text)...)
		}
	}
}

func detectLibraryFromString(pageURL, candidate string) []model.JSLibrary {
	libs := []model.JSLibrary{}
	for _, sig := range jsSignatures {
		if sig.URLPattern == nil {
			continue
		}
		m := sig.URLPattern.FindStringSubmatch(candidate)
		if len(m) < 2 {
			continue
		}
		version := m[1]
		libs = append(libs, model.JSLibrary{
			Name:     sig.Name,
			Version:  version,
			URL:      candidate,
			Source:   pageURL,
			Outdated: versionLess(version, sig.MinSafe),
			Severity: sig.Severity,
			Notes:    sig.Notes,
		})
	}
	return libs
}

func detectLibraryFromText(pageURL, text string) []model.JSLibrary {
	libs := []model.JSLibrary{}
	for _, sig := range jsSignatures {
		if sig.TextPattern == nil {
			continue
		}
		m := sig.TextPattern.FindStringSubmatch(text)
		if len(m) < 2 {
			continue
		}
		version := m[1]
		libs = append(libs, model.JSLibrary{
			Name:     sig.Name,
			Version:  version,
			Source:   pageURL,
			Outdated: versionLess(version, sig.MinSafe),
			Severity: sig.Severity,
			Notes:    sig.Notes,
		})
	}
	return libs
}

func dedupeJSLibraries(in []model.JSLibrary) []model.JSLibrary {
	seen := map[string]bool{}
	out := make([]model.JSLibrary, 0, len(in))
	for _, lib := range in {
		key := fmt.Sprintf("%s|%s|%s|%s", lib.Name, lib.Version, lib.URL, lib.Source)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, lib)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func versionLess(have, min string) bool {
	parse := func(v string) []int {
		parts := strings.Split(v, ".")
		out := make([]int, 3)
		for i := 0; i < len(parts) && i < 3; i++ {
			fmt.Sscanf(parts[i], "%d", &out[i])
		}
		return out
	}
	a := parse(have)
	b := parse(min)
	for i := 0; i < 3; i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}
