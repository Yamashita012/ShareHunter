# ShareHunter

**High-Performance Network Share Secret Discovery Tool**  
Created by **z3r0 from Cyanre**

ShareHunter audits explicitly authorized SMB shares for potentially exposed credentials and sensitive configuration. It supports authenticated and current-session/guest access, recursive enumeration, bounded concurrent in-memory inspection, redacted findings, and JSON/CSV/Markdown/HTML reporting.

## Safety model

- No password guessing, spraying, or brute force.
- No upload or external transmission of scanned file contents.
- Source files are read in memory only; no temporary copies are created.
- Findings redact detected values. Original credential-bearing files are never exported.
- Reports are created with owner-only permissions where supported.
- Run only against systems for which you have written authorization.

## Requirements

- Go 1.22+
- Network reachability to TCP/445 on each target
- A user account with read access to the intended shares (or explicitly permitted guest access)

## Build

```bash
go mod tidy
go test ./...
go build -o sharehunter ./cmd/sharehunter
```

## Usage

```bash
# Authenticated; password is prompted securely if --password is omitted
./sharehunter scan --target 192.0.2.10 --username auditor --domain CORP

# Guest/current-session style access
./sharehunter scan --target 192.0.2.10 --auth none

# Multiple explicitly authorized targets
./sharehunter scan --targets targets.txt --username auditor --domain CORP

# Tune concurrency and limits
./sharehunter scan --target 192.0.2.10 --username auditor --workers 16 --max-size 8388608 --max-depth 8

# Alternate extensions / custom dictionary
./sharehunter scan --target 192.0.2.10 --auth none --extensions txt,ini,env,xml --keywords config/keywords.txt

# Convert a saved assessment JSON into another report format
./sharehunter report --input sharehunter-findings.json --format html --output assessment.html
./sharehunter report --input sharehunter-findings.json --format csv --output findings.csv
./sharehunter report --input sharehunter-findings.json --format markdown --output findings.md
```

`--password` is provided for automation but may be exposed through process listings or shell history. Prefer the secure interactive prompt. The `none` mode requests the SMB Guest account with an empty password. The selected SMB library does not support a truly anonymous NTLM session; the server must permit Guest mapping. This does not impersonate the local Windows logon token.

## Configuration

`config/keywords.txt` accepts a keyword per line or `category:keyword`. Built-in defaults include password, authentication, account, and infrastructure terms. Supported default extensions are listed in the project specification. `--extensions` replaces the default extension set.

## Output

The scan command writes a JSON assessment (default `sharehunter-findings.json`). Use `report` to render CSV, Markdown, or HTML. Evidence snippets are redacted and capped; raw secret values are not included. The confidence score is a heuristic and must be manually validated.

## Limitations

- SMB dialect negotiation and server policy determine which shares are visible. Hidden/admin shares may be listed but are accessible only if the account is authorized.
- The current implementation uses a single SMB session per target; it does not parallelize network sessions.
- DOCX/XLSX are ZIP containers and are not yet unpacked for inner-text scanning. Binary formats are skipped.
- High-entropy detection is reserved for a later release; current detection uses contextual keyword, assignment, and private-key-header rules.
- DOCX/XLSX archive extraction and an append-only audit log are not implemented in this initial build.
- `--auth none` requests the SMB Guest account with an empty password; it is not truly anonymous access or integrated Windows single sign-on.
- Directory and file counts reflect accessible entries; denied paths are recorded as errors where surfaced by the SMB library.

## Project structure

See `cmd/sharehunter` and `internal/` for CLI, SMB, enumeration, detection, scanning, and reporting modules.

## Dependencies

The SMB transport uses `github.com/hirochachacha/go-smb2` v1.1.0; secure terminal password input uses `golang.org/x/term`. The first `go mod tidy` / build requires access to the Go module proxy (or a pre-populated module cache).
