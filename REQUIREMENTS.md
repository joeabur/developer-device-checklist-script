# Requirements and platform notes

Runtime dependencies
- `bash` (POSIX-style shell)
- `find`, `grep`, `awk`, `xargs` (coreutils/grep/awk)
- `shasum` or `sha256sum` for hash checks
- `netstat` (or `ss`) for active connection checks
- `npm` if you want npm-specific checks

macOS-specific utilities
- `codesign` is used to inspect application signatures
- `dscacheutil` is used to query recent DNS lookups

Notes
- On Linux, `dscacheutil` and `codesign` are not available; the script skips those checks.
- The script writes output to the Desktop; ensure write access to `~/Desktop`.
- The script is read-only and safe to run, but if issues are flagged, do not commit or push the results — contact Security Engineering.
