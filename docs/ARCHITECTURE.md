# Architecture

1. **CLI** validates explicit targets, limits, and authentication mode.
2. **SMB client** opens TCP/445 and negotiates an SMB session using NTLM credentials or anonymous/guest initiation.
3. **Enumeration** lists shares and recursively walks accessible directories with a configurable depth/file ceiling.
4. **Inspection workers** read eligible files through `fs.FS` with a strict byte cap and bounded goroutine pool.
5. **Detection** applies case-insensitive keyword and key/value heuristics plus private-key header checks.
6. **Reporting** stores metadata and redacted evidence only, then writes JSON or converts JSON to CSV/Markdown/HTML.

The number of inspection goroutines is bounded by `--workers`; each worker holds at most one file buffer at a time. File reads are limited to `max-size + 1` bytes to detect oversize files without loading them fully.
