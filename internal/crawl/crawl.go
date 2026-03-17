package crawl

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"

	"golang.org/x/net/html"

	"github.com/rohsec/xspulse/internal/analyze"
	"github.com/rohsec/xspulse/internal/httpx"
	"github.com/rohsec/xspulse/internal/model"
)

type Options struct {
	Depth       int
	Concurrency int
}

func Run(ctx context.Context, c *httpx.Client, seed string, opts Options) (model.CrawlResult, error) {
	if opts.Depth <= 0 {
		opts.Depth = 1
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}

	seedURL, err := url.Parse(seed)
	if err != nil {
		return model.CrawlResult{}, err
	}
	if seedURL.Scheme == "" {
		seedURL, err = url.Parse("https://" + seed)
		if err != nil {
			return model.CrawlResult{}, err
		}
	}

	current := []string{seedURL.String()}
	seen := map[string]bool{seedURL.String(): true}
	allPages := []string{}
	allLinks := map[string]bool{}
	allScripts := map[string]bool{}
	allJSLibraries := []model.JSLibrary{}
	formsMu := sync.Mutex{}
	var forms []model.Form

	for level := 0; level < opts.Depth; level++ {
		nextSet := map[string]bool{}
		var mu sync.Mutex
		jobs := make(chan string)
		wg := sync.WaitGroup{}
		worker := func() {
			defer wg.Done()
			for pageURL := range jobs {
				resp, err := c.Do(ctx, "GET", pageURL, "", "")
				if err != nil {
					continue
				}
				raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
				resp.Body.Close()
				links, pageForms, scripts := parsePage(pageURL, raw)
				jslibs := analyze.DetectJSLibraries(pageURL, raw)

				mu.Lock()
				allPages = append(allPages, pageURL)
				for _, l := range links {
					if sameHost(seedURL, l) {
						allLinks[l] = true
						if !seen[l] {
							nextSet[l] = true
							seen[l] = true
						}
					}
				}
				for _, s := range scripts {
					allScripts[s] = true
				}
				allJSLibraries = append(allJSLibraries, jslibs...)
				mu.Unlock()

				if len(pageForms) > 0 {
					formsMu.Lock()
					forms = append(forms, pageForms...)
					formsMu.Unlock()
				}
			}
		}
		for i := 0; i < opts.Concurrency; i++ {
			wg.Add(1)
			go worker()
		}
		go func() {
			defer close(jobs)
			for _, u := range current {
				jobs <- u
			}
		}()
		wg.Wait()
		current = current[:0]
		for u := range nextSet {
			current = append(current, u)
		}
		sort.Strings(current)
	}

	pages := uniqueSorted(allPages)
	links := mapKeys(allLinks)
	scripts := mapKeys(allScripts)
	return model.CrawlResult{Seed: seedURL.String(), Pages: pages, Links: links, Forms: forms, Scripts: scripts, JSLibraries: dedupeCrawlJSLibraries(allJSLibraries)}, nil
}

func parsePage(base string, raw []byte) ([]string, []model.Form, []string) {
	links := []string{}
	forms := syntheticFormsFromURL(base)
	scripts := []string{}
	root, err := html.Parse(bytes.NewReader(raw))
	if err != nil {
		return uniqueSorted(links), dedupeForms(forms), uniqueSorted(scripts)
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "a":
				if href := getAttr(n, "href"); href != "" {
					if abs := resolveURL(base, href); abs != "" {
						links = append(links, abs)
					}
				}
			case "script":
				if src := getAttr(n, "src"); src != "" {
					if abs := resolveURL(base, src); abs != "" {
						scripts = append(scripts, abs)
					}
				}
			case "form":
				f := model.Form{Action: resolveURL(base, getAttr(n, "action")), Method: strings.ToUpper(defaultString(getAttr(n, "method"), "GET")), Source: canonicalizeURL(base)}
				if f.Action == "" {
					f.Action = canonicalizeURL(base)
				}
				var formWalk func(*html.Node)
				formWalk = func(cur *html.Node) {
					if cur.Type == html.ElementNode {
						name := getAttr(cur, "name")
						if name != "" && (cur.Data == "input" || cur.Data == "textarea" || cur.Data == "select") {
							f.Inputs = append(f.Inputs, model.Parameter{Name: name, Value: getAttr(cur, "value")})
						}
					}
					for c := cur.FirstChild; c != nil; c = c.NextSibling {
						formWalk(c)
					}
				}
				formWalk(n)
				forms = append(forms, f)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return uniqueSorted(links), dedupeForms(forms), uniqueSorted(scripts)
}

func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func resolveURL(base, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "#") {
		return ""
	}
	bu, err := url.Parse(base)
	if err != nil {
		return ""
	}
	hu, err := url.Parse(href)
	if err != nil {
		return ""
	}
	ru := bu.ResolveReference(hu)
	ru.Fragment = ""
	if ru.Path == "" {
		ru.Path = "/"
	}
	ru.Path = path.Clean(ru.Path)
	return canonicalizeParsedURL(ru).String()
}

func sameHost(seed *url.URL, other string) bool {
	u, err := url.Parse(other)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), seed.Hostname())
}

func uniqueSorted(vals []string) []string {
	m := map[string]bool{}
	for _, v := range vals {
		if v != "" {
			m[v] = true
		}
	}
	return mapKeys(m)
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func defaultString(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func syntheticFormsFromURL(pageURL string) []model.Form {
	u, err := url.Parse(pageURL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	canonical := canonicalizeParsedURL(u)
	query := canonical.Query()
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	inputs := make([]model.Parameter, 0, len(keys))
	for _, key := range keys {
		inputs = append(inputs, model.Parameter{Name: key, Value: query.Get(key)})
	}
	baseCopy := *canonical
	baseCopy.RawQuery = ""
	return []model.Form{{
		Action: canonicalizeParsedURL(&baseCopy).String(),
		Method: "GET",
		Inputs: inputs,
		Source: canonical.String(),
	}}
}

func dedupeForms(forms []model.Form) []model.Form {
	seen := map[string]bool{}
	out := make([]model.Form, 0, len(forms))
	for _, f := range forms {
		f.Action = canonicalizeURL(f.Action)
		f.Method = strings.ToUpper(defaultString(f.Method, "GET"))
		f.Source = canonicalizeURL(f.Source)
		sort.SliceStable(f.Inputs, func(i, j int) bool {
			if f.Inputs[i].Name == f.Inputs[j].Name {
				return f.Inputs[i].Value < f.Inputs[j].Value
			}
			return f.Inputs[i].Name < f.Inputs[j].Name
		})
		sigParts := []string{f.Method, f.Action}
		for _, input := range f.Inputs {
			sigParts = append(sigParts, input.Name+"="+input.Value)
		}
		sig := strings.Join(sigParts, "|")
		if seen[sig] {
			continue
		}
		seen[sig] = true
		out = append(out, f)
	}
	return out
}

func canonicalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return canonicalizeParsedURL(u).String()
}

func canonicalizeParsedURL(u *url.URL) *url.URL {
	clone := *u
	clone.Fragment = ""
	if clone.Path == "" {
		clone.Path = "/"
	}
	clone.Path = path.Clean(clone.Path)
	if clone.RawQuery != "" {
		q := clone.Query()
		clone.RawQuery = q.Encode()
	}
	return &clone
}

func dedupeCrawlJSLibraries(in []model.JSLibrary) []model.JSLibrary {
	seen := map[string]bool{}
	out := make([]model.JSLibrary, 0, len(in))
	for _, lib := range in {
		key := lib.Name + "|" + lib.Version + "|" + lib.URL + "|" + lib.Source
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
