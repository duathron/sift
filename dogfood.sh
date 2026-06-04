#!/usr/bin/env sh
# sift dogfood — proves the installed CLI actually triages, end to end.
# Offline tier (mandatory): template summarizer, no network, no key.
# Live LLM tier (opt-in): set SIFT_DOGFOOD_LLM=1 + a provider key; skip != pass.
#
# NB: `sift triage` returns a SEVERITY-based exit code (0 = no elevated cluster,
# 1 = an elevated-priority cluster was found) — both are valid triage outcomes.
# Only exit >= 2 means a real error (usage / bad file / crash). The dogfood gates
# on "produced a triage report + did not error", not on a zero exit.
set -eu

FIXTURE="${1:-tests/fixtures/mixed.json}"

echo "== offline (template summarizer, no key, no cache) =="
set +e
uv run sift triage "$FIXTURE" --quiet --no-cache --provider template > /tmp/sift_dogfood_out.txt 2>/dev/null
rc=$?
set -e
[ "$rc" -ge 2 ] && { echo "DOGFOOD: FAIL — sift errored (exit $rc)"; exit 1; }
test -s /tmp/sift_dogfood_out.txt || { echo "DOGFOOD: FAIL — empty output"; exit 1; }
grep -qiE 'SIFT TRIAGE REPORT|Executive Summary|Cluster Overview' /tmp/sift_dogfood_out.txt \
    || { echo "DOGFOOD: FAIL — no triage report in output"; exit 1; }
echo "DOGFOOD: PASS (offline, sift exit $rc)"

if [ "${SIFT_DOGFOOD_LLM:-}" = "1" ]; then
    echo "== live LLM tier =="
    set +e
    uv run sift triage "$FIXTURE" --no-cache > /tmp/sift_dogfood_llm.txt 2>/dev/null
    rc=$?
    set -e
    [ "$rc" -ge 2 ] && { echo "DOGFOOD: FAIL — live LLM tier errored (exit $rc)"; exit 1; }
    test -s /tmp/sift_dogfood_llm.txt || { echo "DOGFOOD: FAIL — live tier empty"; exit 1; }
    echo "DOGFOOD: PASS (live LLM, exit $rc)"
else
    echo "DOGFOOD: live LLM tier not run (set SIFT_DOGFOOD_LLM=1 + provider key)."
fi
