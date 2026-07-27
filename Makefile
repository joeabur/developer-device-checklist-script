SHELL := /usr/bin/env bash

.PHONY: check
check:
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not found; install it to run checks"; exit 0; }
	@shellcheck -x dev-security-check.sh
