package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/breachoperators/sharehunter/internal/auth"
	"github.com/breachoperators/sharehunter/internal/detection"
	"github.com/breachoperators/sharehunter/internal/enumeration"
	"github.com/breachoperators/sharehunter/internal/reporting"
	"github.com/breachoperators/sharehunter/internal/scanner"
	"github.com/breachoperators/sharehunter/internal/smb"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 || os.Args[1] == "--help" || os.Args[1] == "-h" {
		usage()
		return
	}
	switch os.Args[1] {
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "[!]", err)
			os.Exit(1)
		}
	case "report":
		if err := runReport(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "[!]", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}
func usage() {
	fmt.Printf(`ShareHunter v%s — Network Share Secret Discovery
Created by z3r0 from Cyanre

Usage:
  sharehunter scan --target 10.0.0.10 [options]
  sharehunter report --input findings.json --format html --output report.html

Run 'sharehunter scan --help' for scan options.
`, version)
}
func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	target := fs.String("target", "", "Authorized SMB server (host or IP)")
	targets := fs.String("targets", "", "Text file containing authorized SMB servers, one per line")
	user := fs.String("username", "", "SMB username")
	domain := fs.String("domain", "", "SMB domain/workgroup")
	password := fs.String("password", "", "Password (prefer interactive prompt; avoid shell history)")
	authMode := fs.String("auth", "auto", "auto, none, or password")
	maxDepth := fs.Int("max-depth", 12, "Maximum directory depth")
	maxSize := fs.Int64("max-size", 4<<20, "Maximum file size in bytes")
	workers := fs.Int("workers", 8, "Concurrent file inspections")
	timeout := fs.Duration("timeout", 8*time.Second, "SMB connection timeout")
	extensions := fs.String("extensions", "", "Comma-separated extension allowlist; default uses built-in list")
	keywords := fs.String("keywords", "config/keywords.txt", "Optional custom keyword file")
	output := fs.String("output", "sharehunter-findings.json", "JSON findings output")
	_ = fs.Bool("no-color", false, "Disable terminal colors")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" && *targets == "" {
		return errors.New("--target or --targets is required; only scan systems you are authorized to assess")
	}
	if *workers < 1 || *workers > 256 {
		return errors.New("--workers must be between 1 and 256")
	}
	if *maxDepth < 0 || *maxDepth > 128 {
		return errors.New("--max-depth must be between 0 and 128")
	}
	if *maxSize < 1 {
		return errors.New("--max-size must be positive")
	}
	hosts := []string{}
	if *target != "" {
		hosts = append(hosts, *target)
	}
	if *targets != "" {
		b, e := os.ReadFile(*targets)
		if e != nil {
			return e
		}
		for _, s := range strings.Split(string(b), "\n") {
			s = strings.TrimSpace(s)
			if s != "" && !strings.HasPrefix(s, "#") {
				hosts = append(hosts, s)
			}
		}
	}
	cred := auth.Credentials{Username: *user, Domain: *domain, Password: *password, Mode: *authMode}
	if cred.Mode == "auto" {
		if cred.Username != "" {
			cred.Mode = "password"
		} else {
			cred.Mode = "none"
		}
	}
	if cred.Mode == "password" && cred.Username == "" {
		return errors.New("--username is required for authenticated mode")
	}
	if cred.Mode == "password" && cred.Password == "" {
		p, e := auth.ReadPassword("SMB password: ")
		if e != nil {
			return e
		}
		cred.Password = p
	}
	cfg := detection.DefaultConfig()
	if *keywords != "" {
		if _, e := os.Stat(*keywords); e == nil {
			if e = cfg.LoadKeywords(*keywords); e != nil {
				return e
			}
		}
	}
	if *extensions != "" {
		cfg.Extensions = map[string]bool{}
		for _, x := range strings.Split(*extensions, ",") {
			cfg.Extensions[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(x, ".")))] = true
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	started := time.Now()
	all := reporting.Assessment{Tool: "ShareHunter", Version: version, At: started, AuthMode: cred.Mode, Targets: hosts}
	fmt.Printf("\nShareHunter v%s | Created by z3r0 from Cyanre\nAuthorized SMB assessment only\n", version)
	for _, host := range hosts {
		fmt.Printf("\n[*] Connecting to %s:445\n", host)
		session, err := smb.Connect(ctx, host, cred, *timeout)
		if err != nil {
			fmt.Printf("[!] %s: %v\n", host, err)
			all.Errors = append(all.Errors, host+": "+err.Error())
			continue
		}
		shares, err := session.Shares()
		if err != nil {
			fmt.Printf("[!] Share enumeration: %v\n", err)
			session.Close()
			continue
		}
		fmt.Printf("[+] Discovered %d share(s)\n", len(shares))
		for _, share := range shares {
			if strings.HasSuffix(share, "$") && share != "IPC$" { /* administrative shares are not excluded; server ACLs remain authoritative */
			}
			mounted, err := session.Mount(share)
			if err != nil {
				continue
			}
			root := mounted.WithContext(ctx).DirFS(".")
			files, dirs, errs := enumeration.Walk(ctx, root, enumeration.Options{MaxDepth: *maxDepth, MaxFiles: 1000000})
			all.Directories += dirs
			all.Errors = append(all.Errors, errs...)
			fmt.Printf("[+] %-24s %d files / %d directories\n", share, len(files), dirs)
			results, inspected := scanner.Inspect(ctx, root, files, scanner.Options{Workers: *workers, MaxBytes: *maxSize, Config: cfg, Target: host, Share: share})
			all.FilesInspected += inspected
			all.Findings = append(all.Findings, results...)
			session.Unmount(mounted)
		}
		session.Close()
	}
	all.Duration = time.Since(started).String()
	all.Summary = reporting.Summarize(all.Findings)
	if err := reporting.WriteJSON(*output, all); err != nil {
		return err
	}
	fmt.Printf("\n[+] Complete: %d files inspected, %d findings, %d errors\n[+] JSON report: %s\n", all.FilesInspected, len(all.Findings), len(all.Errors), *output)
	return nil
}
func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	in := fs.String("input", "sharehunter-findings.json", "Input assessment JSON")
	format := fs.String("format", "html", "json, csv, markdown, html")
	out := fs.String("output", "sharehunter-report.html", "Output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	b, e := os.ReadFile(*in)
	if e != nil {
		return e
	}
	var a reporting.Assessment
	if e = json.Unmarshal(b, &a); e != nil {
		return e
	}
	switch strings.ToLower(*format) {
	case "json":
		return reporting.WriteJSON(*out, a)
	case "csv":
		return writeCSV(*out, a)
	case "markdown", "md":
		return writeMD(*out, a)
	case "html":
		return writeHTML(*out, a)
	default:
		return fmt.Errorf("unsupported format %q", *format)
	}
}
func writeCSV(path string, a reporting.Assessment) error {
	f, e := createPrivate(path)
	if e != nil {
		return e
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"target", "share", "path", "category", "keyword", "confidence", "line", "evidence"})
	for _, x := range a.Findings {
		_ = w.Write([]string{x.Target, x.Share, x.Path, x.Category, x.Keyword, fmt.Sprint(x.Confidence), fmt.Sprint(x.Line), x.Evidence})
	}
	return w.Error()
}
func writeMD(path string, a reporting.Assessment) error {
	f, e := createPrivate(path)
	if e != nil {
		return e
	}
	defer f.Close()
	fmt.Fprintf(f, "# ShareHunter Assessment\n\n- Version: %s\n- Date: %s\n- Targets: %s\n- Files inspected: %d\n- Findings: %d\n- Duration: %s\n\n## Findings\n\n| Target | Share | Path | Category | Confidence | Line |\n|---|---|---|---|---:|---:|\n", a.Version, a.At.Format(time.RFC3339), strings.Join(a.Targets, ", "), a.FilesInspected, len(a.Findings), a.Duration)
	for _, x := range a.Findings {
		fmt.Fprintf(f, "| %s | %s | %s | %s | %d | %d |\n", esc(x.Target), esc(x.Share), esc(x.Path), esc(x.Category), x.Confidence, x.Line)
	}
	return nil
}
func createPrivate(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func esc(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ") }
func writeHTML(path string, a reporting.Assessment) error {
	const page = `<!doctype html><html><head><meta charset="utf-8"><title>ShareHunter Assessment</title><style>body{font:15px system-ui;background:#10151d;color:#e6edf3;margin:3rem}h1{color:#ff8a32}table{border-collapse:collapse;width:100%}td,th{padding:10px;border-bottom:1px solid #34404e;text-align:left}th{color:#ffb16e}code{color:#9ed8ff}.muted{color:#9aa7b5}</style></head><body><h1>ShareHunter Assessment</h1><p class="muted">Created by z3r0 from Cyanre · {{.At}}</p><p>Targets: {{join .Targets}} | Files inspected: {{.FilesInspected}} | Findings: {{len .Findings}} | Duration: {{.Duration}}</p><table><tr><th>Target</th><th>Share</th><th>Path</th><th>Category</th><th>Confidence</th><th>Line</th><th>Redacted evidence</th></tr>{{range .Findings}}<tr><td>{{.Target}}</td><td>{{.Share}}</td><td><code>{{.Path}}</code></td><td>{{.Category}}</td><td>{{.Confidence}}%</td><td>{{.Line}}</td><td><code>{{.Evidence}}</code></td></tr>{{end}}</table></body></html>`
	f, e := createPrivate(path)
	if e != nil {
		return e
	}
	defer f.Close()
	t, e := template.New("r").Funcs(template.FuncMap{"join": func(x []string) string { return strings.Join(x, ", ") }}).Parse(page)
	if e != nil {
		return e
	}
	return t.Execute(f, a)
}
