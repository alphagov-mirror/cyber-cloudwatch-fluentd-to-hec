#!/usr/bin/env sh

set -e
cd fluentdhec
flake8 *.py
MYPYPATH=../stubs mypy *.py
