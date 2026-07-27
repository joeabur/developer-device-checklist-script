# Developer Device Checklist Script

[![ShellCheck](https://github.com/joeabur/developer-device-checklist-script/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/joeabur/developer-device-checklist-script/actions/workflows/shellcheck.yml)
[![Release](https://img.shields.io/github/v/release/joeabur/developer-device-checklist-script)](https://github.com/joeabur/developer-device-checklist-script/releases/latest)

## Purpose

Developer Device Checklist Script is a read-only diagnostic tool that helps developers collect machine security indicators and share the results with the Security Engineering team.

## Quick Start

Make the script executable and run it from a terminal:

```bash
chmod +x dev-security-check.sh
./dev-security-check.sh
```

## Output

A timestamped report is generated on the user's Desktop. Share this report with the Security Engineering team for review.

## Supported Platforms

The script is primarily designed for macOS, including checks for code signing and LaunchAgents. Many of the diagnostic checks also run on Linux.

Refer to **REQUIREMENTS.md** for platform-specific requirements and limitations.

## Important

- The script is read-only and does not modify, delete, or remediate any system files.
- If potential security issues are identified, follow the guidance provided in the report and contact the Security Engineering team before making any changes.

## Repository Structure

- `dev-security-check.sh` – Main diagnostic script
- `REQUIREMENTS.md` – Runtime requirements and platform information
- `CONTRIBUTING.md` – Contribution guidelines
- `SECURITY.md` – Security policy and vulnerability reporting

## Continuous Integration

GitHub Actions runs `ShellCheck` automatically to validate the shell script on every supported workflow.

## Publishing to GitHub

Create a GitHub repository, then configure the remote and push the project:

```bash
cd developer-device-checklist-script
git remote add origin git@github.com:<your-org-or-username>/developer-device-checklist-script.git
git push -u origin main
```
