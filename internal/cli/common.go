package cli

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rohsec/xspulse/internal/httpx"
	"github.com/rohsec/xspulse/internal/model"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
)

type commonFlags struct {
	URL           string
	Data          string
	Method        string
	Timeout       time.Duration
	Delay         time.Duration
	Concurrency   int
	Headers       headerList
	Proxy         string
	Insecure      bool
	JSONOutput    bool
	Encode        string
	UserAgent     string
	BlindCallback string
}

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func addCommonFlags(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.URL, "u", "", "target URL")
	fs.StringVar(&c.URL, "url", "", "target URL")
	fs.StringVar(&c.Data, "data", "", "POST body or query-style body")
	fs.StringVar(&c.Method, "X", "GET", "HTTP method")
	fs.StringVar(&c.Method, "method", "GET", "HTTP method")
	fs.DurationVar(&c.Timeout, "timeout", 10*time.Second, "request timeout")
	fs.DurationVar(&c.Delay, "delay", 0, "delay between requests")
	fs.IntVar(&c.Concurrency, "c", 10, "concurrency")
	fs.IntVar(&c.Concurrency, "concurrency", 10, "concurrency")
	fs.Var(&c.Headers, "H", "custom header (repeatable, Key: Value)")
	fs.Var(&c.Headers, "header", "custom header (repeatable, Key: Value)")
	fs.StringVar(&c.Proxy, "proxy", "", "HTTP(S) proxy URL")
	fs.BoolVar(&c.Insecure, "k", false, "skip TLS verification")
	fs.BoolVar(&c.Insecure, "insecure", false, "skip TLS verification")
	fs.BoolVar(&c.JSONOutput, "json", false, "JSON output")
	fs.StringVar(&c.Encode, "encode", "none", "payload encoding: none|url|base64")
	fs.StringVar(&c.UserAgent, "ua", "random", "user-agent: random|default|custom string")
	fs.StringVar(&c.BlindCallback, "blind-callback", "", "blind XSS callback URL")
}

func buildHTTPClient(c commonFlags) (*httpx.Client, error) {
	headers := make(http.Header)
	for _, hv := range c.Headers {
		parts := strings.SplitN(hv, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header: %s", hv)
		}
		headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	return httpx.New(httpx.Options{
		Timeout:     c.Timeout,
		Delay:       c.Delay,
		Proxy:       c.Proxy,
		InsecureTLS: c.Insecure,
		Headers:     headers,
		UserAgent:   c.UserAgent,
	})
}

func ensureURL(u string) error {
	if strings.TrimSpace(u) == "" {
		return fmt.Errorf("target URL is required")
	}
	return nil
}

func encoderKind(v string) model.EncodingKind {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "url":
		return model.EncodingURL
	case "base64":
		return model.EncodingBase64
	default:
		return model.EncodingNone
	}
}

func printAsJSONorText(asJSON bool, text string, payload any) error {
	if !asJSON {
		fmt.Print(text)
		return nil
	}
	return model.PrintJSON(os.Stdout, payload)
}

func colorEnabled() bool {
	return os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}

func style(text string, codes ...string) string {
	if !colorEnabled() || text == "" {
		return text
	}
	return strings.Join(codes, "") + text + ansiReset
}

func okText(text string) string      { return style(text, ansiGreen) }
func warnText(text string) string    { return style(text, ansiYellow) }
func badText(text string) string     { return style(text, ansiRed) }
func infoText(text string) string    { return style(text, ansiCyan) }
func accentText(text string) string  { return style(text, ansiBlue, ansiBold) }
func headingText(text string) string { return style(text, ansiBold, ansiCyan) }
func subtleText(text string) string  { return style(text, ansiDim) }
func strongText(text string) string  { return style(text, ansiBold) }
func severityText(label string, score int) string {
	if score >= 95 {
		return badText(label)
	}
	if score >= 80 {
		return warnText(label)
	}
	return okText(label)
}

func commonFlagsHelp() string {
	return `Common flags:
  -u, --url <url>              Target URL
  -X, --method <method>        HTTP method (default: GET)
  --data <body>                POST body or query-style data
  -H, --header <k:v>           Custom header, repeatable
  --proxy <url>                HTTP(S) proxy URL
  -k, --insecure               Skip TLS verification
  --timeout <duration>         Request timeout (default: 10s)
  --delay <duration>           Delay between requests
  -c, --concurrency <n>        Worker concurrency where applicable
  --encode <kind>              Payload encoding: none|url|base64
  --ua <mode|string>           User-Agent: random|default|custom
  --json                       Output JSON
  --blind-callback <url>       Blind XSS callback URL`
}

func PrintCommandHelp(command string) {
	switch command {
	case "scan":
		fmt.Printf(`XSPulse scan - reflected XSS analysis

Usage:
  xspulse scan -u <url> [flags]

What it does:
  - Detects reflected parameters
  - Classifies HTML/attribute/script/comment contexts
  - Generates ranked context-aware payloads
  - Reports DOM signals and JS library detections
  - Optionally sends blind XSS callback payloads

Extra flags:
  --min-confidence <n>         Minimum payload confidence (default: 70)
  --skip-waf                   Skip WAF fingerprinting

%s

Examples:
  xspulse scan -u 'https://target.tld/search?q=test'
  xspulse scan -u 'https://target.tld/login' --data 'user=a&pass=b' -X POST
  xspulse scan -u 'https://target.tld/search?q=test' --blind-callback 'https://bx.example/cb'
`, commonFlagsHelp())
	case "crawl":
		fmt.Printf(`XSPulse crawl - crawl, enumerate, and optionally scan forms/endpoints

Usage:
  xspulse crawl -u <url> [flags]

What it does:
  - Crawls in-scope pages
  - Canonicalizes duplicate links
  - Extracts forms and synthetic GET forms
  - Deduplicates equivalent forms
  - Detects JS libraries across crawled pages
  - Optionally scans discovered forms and endpoints

Extra flags:
  --depth <n>                  Crawl depth (default: 2)
  --scan                       Scan discovered forms/endpoints after crawling
  --min-confidence <n>         Scan threshold when --scan is used (default: 70)

%s

Examples:
  xspulse crawl -u 'https://target.tld' --depth 2
  xspulse crawl -u 'https://target.tld' --depth 2 --scan
  xspulse crawl -u 'https://target.tld' --blind-callback 'https://bx.example/cb' --json
`, commonFlagsHelp())
	case "fuzz":
		fmt.Printf(`XSPulse fuzz - replay breaker payloads against parameters

Usage:
  xspulse fuzz -u <url> [flags]

What it does:
  - Sends a built-in set of fuzz/breaker payloads
  - Reports reflected, filtered, or blocked outcomes per parameter

%s

Examples:
  xspulse fuzz -u 'https://target.tld/search?q=test'
  xspulse fuzz -u 'https://target.tld/login' --data 'q=test' -X POST
`, commonFlagsHelp())
	case "bruteforce":
		fmt.Printf(`XSPulse bruteforce - replay payloads from a file

Usage:
  xspulse bruteforce -u <url> -p <payload-file> [flags]

What it does:
  - Loads payloads from a file
  - Sends each payload to each parameter
  - Reports direct reflection hits

Extra flags:
  -p, --payloads <file>        Payload file (required)

%s

Examples:
  xspulse bruteforce -u 'https://target.tld/search?q=test' -p payloads.txt
`, commonFlagsHelp())
	case "dom":
		fmt.Printf(`XSPulse dom - heuristic DOM XSS source/sink analysis

Usage:
  xspulse dom -u <url> [flags]

What it does:
  - Fetches the target page
  - Finds inline script source/sink patterns suggestive of DOM XSS

%s

Examples:
  xspulse dom -u 'https://target.tld/app'
`, commonFlagsHelp())
	case "waf":
		fmt.Printf(`XSPulse waf - lightweight WAF fingerprinting

Usage:
  xspulse waf -u <url> [flags]

What it does:
  - Sends a noisy probe request
  - Matches headers/body/status against built-in WAF fingerprints

%s

Examples:
  xspulse waf -u 'https://target.tld'
`, commonFlagsHelp())
	default:
		PrintRootHelp()
	}
}

func PrintRootHelp() {
	fmt.Println(`XSPulse - fast Go XSS assessment toolkit

Usage:
  xspulse <command> [flags]
  xspulse help <command>

Subcommands:
  scan        Context-aware reflected XSS scan with payload ranking
  crawl       Crawl, dedupe, enumerate forms, and optionally scan them
  fuzz        Fuzz parameters with built-in breaker payloads
  bruteforce  Replay payloads from a file against parameters
  dom         Heuristic DOM XSS source/sink analysis
  waf         Fingerprint common WAFs with a probe request
  version     Show version
  help        Show root help or subcommand help

Feature summary:
  - Reflected XSS scanning with context classification
  - Blind XSS callback payload injection
  - DOM XSS heuristics
  - RetireJS-style JS library/version detection
  - WAF fingerprinting
  - Crawl canonicalization + synthetic GET-form extraction + form dedupe
  - Fuzzing and bruteforce modes
  - JSON and terminal output

Quick examples:
  xspulse scan -u 'https://target.tld/search?q=test'
  xspulse scan -u 'https://target.tld/login' --data 'user=a&pass=b' -X POST
  xspulse scan -u 'https://target.tld/search?q=test' --blind-callback 'https://bx.example/cb'
  xspulse crawl -u 'https://target.tld' --depth 2 --scan
  xspulse fuzz -u 'https://target.tld/search?q=test'
  xspulse bruteforce -u 'https://target.tld/search?q=test' -p payloads.txt
  xspulse dom -u 'https://target.tld/app'
  xspulse waf -u 'https://target.tld'

For detailed command help:
  xspulse help scan
  xspulse help crawl
  xspulse help fuzz
  xspulse help bruteforce
  xspulse help dom
  xspulse help waf`)
}
