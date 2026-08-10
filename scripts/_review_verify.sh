#!/usr/bin/env bash
# claude-review verify (DAN-2545) — INTENTIONAL bug; safe to remove.
set -euo pipefail
dest=$1
mkdir -p $dest/backup
