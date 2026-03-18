package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rohsec/xspulse/internal/cli"
)

func printBanner() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		fmt.Print(`
 __  ____________       __         
 \ \/ / __/ __/ /  __ _/ /__ ___ __
  \  /\ \/ _// _ \/  ' / (_-</ -_) \
  /_/___/___/ .__/_/_/_/___/\__/\___/
           /_/                       

 Created by ROHIT (https://rohsec.com)
`)
		return
	}

	cyan := "\033[36m"
	magenta := "\033[35m"
	bold := "\033[1m"
	dim := "\033[2m"
	reset := "\033[0m"

	fmt.Printf(`
%s%s __  ____________       __         
 \ \/ / __/ __/ /  __ _/ /__ ___ __
  \  /\ \/ _// _ \/  ' / (_-</ -_) \\
  /_/___/___/ .__/_/_/_/___/\__/\___/
           /_/                       %s

%sCreated by ROHIT%s %s(https://rohsec.com)%s

`, bold, cyan, reset, magenta, reset, dim, reset)
}

func main() {
	printBanner()
	if len(os.Args) < 2 {
		cli.PrintRootHelp()
		os.Exit(1)
	}

	cmd := strings.ToLower(os.Args[1])
	args := os.Args[2:]

	var err error
	switch cmd {
	case "scan":
		err = cli.RunScan(args)
	case "crawl":
		err = cli.RunCrawl(args)
	case "fuzz":
		err = cli.RunFuzz(args)
	case "bruteforce":
		err = cli.RunBruteforce(args)
	case "dom":
		err = cli.RunDOM(args)
	case "waf":
		err = cli.RunWAF(args)
	case "version", "-v", "--version":
		fmt.Println("xspulse v0.1.0")
		return
	case "help", "-h", "--help":
		if len(args) > 0 {
			cli.PrintCommandHelp(strings.ToLower(args[0]))
			return
		}
		cli.PrintRootHelp()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		cli.PrintRootHelp()
		os.Exit(1)
	}

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
