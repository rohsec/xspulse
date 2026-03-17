# XSPulse

XSPulse is a fast Go-based XSS assessment toolkit created by RYNO.
It was built as a modern, cleaner, and more maintainable alternative to slower Python-heavy workflows, with a focus on practical bug bounty recon and XSS testing.

Created by RYNO (x.com/rohsec)

## What XSPulse does

XSPulse currently supports:

- Reflected XSS scanning with context-aware payload ranking
- Blind XSS callback payload injection
- Heuristic DOM XSS detection
- RetireJS-style JavaScript library/version fingerprinting
- WAF fingerprinting
- Crawling with:
  - canonical link normalization
  - synthetic GET-form extraction
  - form deduplication
- Parameter fuzzing with built-in breaker payloads
- Bruteforce replay from payload files
- JSON and terminal-friendly output

## Installation

Requirements:
- Go 1.26+ recommended

Local build:

```bash
cd ~/Tools/CustomTools/xspulse
go build -o xspulse ./cmd/xspulse
```

Direct install with `go install`:

```bash
go install -v github.com/rohsec/xspulse/cmd/xspulse@latest
```

Optional install into PATH after local build:

```bash
sudo cp xspulse /usr/local/bin/
```

## CLI overview

```text
xspulse <command> [flags]
xspulse help <command>
```

Commands:

- scan        Context-aware reflected XSS scan with payload ranking
- crawl       Crawl, dedupe, enumerate forms, and optionally scan them
- fuzz        Fuzz parameters with built-in breaker payloads
- bruteforce  Replay payloads from a file against parameters
- dom         Heuristic DOM XSS source/sink analysis
- waf         Fingerprint common WAFs with a probe request
- version     Show version
- help        Show root help or subcommand help

## Common flags

These are accepted by most subcommands:

```text
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
--blind-callback <url>       Blind XSS callback URL
```

## Subcommands

### 1. scan

Reflected XSS analysis against a single target.

What it does:
- detects reflected parameters
- classifies HTML/attribute/script/comment reflection contexts
- generates ranked payloads
- reports DOM signals
- reports JS library detections
- optionally sends blind XSS callback payloads

Usage:

```bash
xspulse scan -u <url> [flags]
```

Extra flags:

```text
--min-confidence <n>         Minimum payload confidence (default: 70)
--skip-waf                   Skip WAF fingerprinting
```

Examples:

```bash
./xspulse scan -u 'https://target.tld/search?q=test'
./xspulse scan -u 'https://target.tld/login' --data 'user=test&pass=test' -X POST
./xspulse scan -u 'https://target.tld/search?q=test' --blind-callback 'https://bx.example/callback'
./xspulse scan -u 'https://target.tld/search?q=test' --json
```

### 2. crawl

Crawls pages, extracts forms/endpoints, deduplicates them, and optionally scans them.

What it does:
- crawls in-scope pages
- normalizes duplicate links
- extracts HTML forms
- creates synthetic GET forms from query-string endpoints
- deduplicates equivalent forms
- collects JS library detections
- optionally scans discovered targets

Usage:

```bash
xspulse crawl -u <url> [flags]
```

Extra flags:

```text
--depth <n>                  Crawl depth (default: 2)
--scan                       Scan discovered forms/endpoints after crawling
--min-confidence <n>         Scan threshold when --scan is used (default: 70)
```

Examples:

```bash
./xspulse crawl -u 'https://target.tld' --depth 2
./xspulse crawl -u 'https://target.tld' --depth 2 --scan
./xspulse crawl -u 'https://target.tld' --blind-callback 'https://bx.example/callback' --json
```

### 3. fuzz

Replays built-in breaker payloads across parameters and reports whether they are reflected, filtered, or blocked.

Usage:

```bash
xspulse fuzz -u <url> [flags]
```

Examples:

```bash
./xspulse fuzz -u 'https://target.tld/search?q=test'
./xspulse fuzz -u 'https://target.tld/login' --data 'q=test' -X POST
```

### 4. bruteforce

Replays payloads from a file against discovered parameters.

Usage:

```bash
xspulse bruteforce -u <url> -p <payload-file> [flags]
```

Extra flags:

```text
-p, --payloads <file>        Payload file (required)
```

Examples:

```bash
./xspulse bruteforce -u 'https://target.tld/search?q=test' -p payloads.txt
```

### 5. dom

Runs heuristic DOM XSS source/sink analysis against a page.

Usage:

```bash
xspulse dom -u <url> [flags]
```

Examples:

```bash
./xspulse dom -u 'https://target.tld/app'
```

### 6. waf

Sends a probe request and tries to fingerprint common WAF behavior.

Usage:

```bash
xspulse waf -u <url> [flags]
```

Examples:

```bash
./xspulse waf -u 'https://target.tld'
```

## Output

XSPulse supports:
- readable terminal output
- JSON output via `--json`

Useful JSON sections include:
- `findings`
- `blind_payloads`
- `js_libraries`
- `dom`
- `waf`
- `forms`
- `links`
- `pages`

## Example workflows

Basic reflected XSS scan:

```bash
./xspulse scan -u 'https://target.tld/search?q=test'
```

POST scan:

```bash
./xspulse scan -u 'https://target.tld/login' --data 'username=test&password=test' -X POST
```

Blind XSS placement:

```bash
./xspulse scan -u 'https://target.tld/feedback?q=test' --blind-callback 'https://bx.example/callback'
```

Crawl and scan discovered targets:

```bash
./xspulse crawl -u 'https://target.tld' --depth 2 --scan
```

Identify old frontend libraries:

```bash
./xspulse scan -u 'https://target.tld' --json
```

## Current detection notes

JS library detection is currently lightweight and best-effort.
At the moment it fingerprints:
- script URLs
- inline version banners/comments

Blind XSS currently focuses on request parameter injection with callback payload generation.
Future updates can expand this to headers, cookies, and path-oriented injection profiles.

## Development

Project path:

```bash
~/Tools/CustomTools/xspulse
```

Run tests:

```bash
go test ./...
```

Rebuild:

```bash
go build -o xspulse ./cmd/xspulse
```

## Disclaimer

Use only on systems you are authorized to test.
You are responsible for complying with program scope, law, and disclosure requirements.
