# Developer device checklist script

Purpose
- A read-only diagnostic script to help developers gather machine security indicators and share results with Security Engineering.

Quick start
- Make the script executable and run from a terminal:

```
chmod +x dev-security-check.sh
./dev-security-check.sh
```

Outputs
- The script writes a timestamped results file to the user's Desktop. Share that file with Security Engineering.

Platforms
- Primarily macOS-focused (checks codesign, LaunchAgents), but many checks run on Linux as well. See REQUIREMENTS.md for details.

Important
- This script only reads and reports data; it does not delete or remediate anything. If the script flags issues, follow instructions in the output and contact Security Engineering before making changes.

Files
- `dev-security-check.sh`: main diagnostic script
- `REQUIREMENTS.md`: runtime requirements and platform notes
- `CONTRIBUTING.md`, `SECURITY.md`: contribution and reporting guidance

Next steps
- I can initialize a git repo here and prepare a GitHub repository and CI (shellcheck) if you want — tell me to proceed.
