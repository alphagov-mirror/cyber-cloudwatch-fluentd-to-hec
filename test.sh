#!/usr/bin/env sh

set -e
cd fluentdhec
MYPYPATH=../stubs mypy *.py
cd ..
tox
