"""Phase 1: Redaction value-level leak prevention.

Three channels are closed here (decided in the 2026-06-12 MeetUp session,
recorded in the project vault under AI/PROJECTS/CODING/sift/MeetUp Logs):

  Channel 1 (raw→output):
    ``alert.raw`` is blanked (``{}``) before IOC extraction so the raw dict
    is never serialised into JSON/HTML/MD/STIX output when redaction is active.
    A ``keep_raw=True`` override is provided for forensic captures where the
    operator explicitly wants to retain the raw dict despite redaction.

  Channel 2 (raw→re-extracted IOC):
    ``_collect_text_fields`` in ioc_extractor skips
    ``_extract_strings_from_dict(alert.raw)`` when ``alert.raw == {}``.
    Because Channel 1 blanks raw first, Channel 2 is automatically gated —
    no changes to ioc_extractor are needed.

  Channel 3 (IOC-drop):
    After extraction, any IOC whose ``.value`` matches a pre-redaction field
    string value is dropped from ``iocs`` / ``iocs_typed``.  The redacted
    field *text* in non-redacted named fields (e.g. the value appearing in
    ``description``) is NOT removed — that is the documented known residual
    deferred to Phase 2 (value-scrub).

Known residual (documented):
    If the redacted value also appears in a non-redacted named field, two
    related forms of residual exist — both share the same root cause and the
    same operator fix:

    (a) **Plain-text residual:** the field's text still contains the value
        (e.g. ``description="scan from 10.0.0.99"`` → the description text is
        not scrubbed).

    (b) **IOC-substring residual:** if a *larger* IOC is extracted from that
        non-redacted field and the redacted value is a substring of it (e.g.
        ``description="see http://10.0.0.99/x"`` → a ``url`` IOC
        ``http://10.0.0.99/x`` is extracted), channel 3 only drops IOCs whose
        ``.value`` *exactly equals* a redacted value.  The URL IOC does not
        match and therefore is NOT dropped — the IP appears in the IOC table
        of all output formats.

    Root cause: Channel 3 uses exact-value matching, not substring matching.
    Substring matching was deliberately deferred to Phase 2 (value-scrub) as
    it is unenumerable and risks over-dropping unrelated IOCs.

    Operator fix (both forms): also add the field that carries the value to
    ``--redact-fields`` (e.g. ``--redact-fields source_ip,description``).
    That blanks the field text, prevents the larger IOC from being extracted
    at all, and removes the plain-text occurrence.

    Phase 2 (value-scrub) is required to close these residuals without
    requiring the operator to enumerate every carrying field.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sift.models import IOC, Alert


# ---------------------------------------------------------------------------
# String-value fields that can carry a redactable plain-text value
# ---------------------------------------------------------------------------

_STRING_FIELDS = frozenset({"title", "description", "source_ip", "dest_ip", "user", "host", "category"})


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_redacted_values(alert: "Alert", fields: list[str]) -> set[str]:
    """Capture the pre-redaction string values of *fields* on *alert*.

    Only string-valued fields are collected; list/dict fields (``iocs``,
    ``iocs_typed``, ``raw``) are skipped because they cannot leak as a
    single string IOC match.

    Returns a ``set[str]`` of non-empty string values that are about to be
    redacted.  This set is used by :func:`drop_redacted_iocs` to filter the
    IOC lists after extraction (Channel 3).
    """
    values: set[str] = set()
    for field in fields:
        if field not in _STRING_FIELDS:
            continue
        val = getattr(alert, field, None)
        if val and isinstance(val, str):
            values.add(val)
    return values


def drop_redacted_iocs(
    iocs: list[str],
    iocs_typed: "list[IOC]",
    redacted_values: set[str],
) -> "tuple[list[str], list[IOC]]":
    """Remove IOC entries whose value matches a redacted field value.

    This is Channel 3 of the Phase 1 fix.  It operates on the *extracted*
    IOC lists (post-enrichment) and drops any entry whose ``.value`` appears
    in *redacted_values*.

    Returns ``(clean_iocs, clean_typed)``.
    """
    if not redacted_values:
        return iocs, iocs_typed
    clean_iocs = [v for v in iocs if v not in redacted_values]
    clean_typed = [ioc for ioc in iocs_typed if ioc.value not in redacted_values]
    return clean_iocs, clean_typed


def redact_and_suppress_raw(
    alert: "Alert",
    fields: list[str],
    *,
    keep_raw: bool = False,
) -> "Alert":
    """Redact *fields* on *alert* and — unless *keep_raw* is True — blank ``raw``.

    This is the Channel 1 + (implicit) Channel 2 fix:

    1. ``alert.redact(fields)`` blanks each named field.
    2. ``raw`` is additionally blanked (``{}``) so that the raw dict is
       neither serialised into output nor re-mined by the IOC extractor
       (because an empty dict produces no string leaves).

    *keep_raw=True* is a forensic override: the raw dict is preserved in
    the returned alert, but the named fields are still redacted.  Use this
    only when the downstream consumer explicitly needs the raw data despite
    active redaction.

    The original *alert* is never mutated; a new instance is returned.
    """
    redacted = alert.redact(fields)
    if keep_raw:
        return redacted
    return redacted.model_copy(update={"raw": {}})


def apply_redact_and_enrich(
    alert: "Alert",
    fields: list[str],
    *,
    keep_raw: bool = False,
) -> "Alert":
    """Full Phase 1 pipeline: redact, suppress raw, enrich IOCs, drop redacted IOC values.

    Combines all three channel fixes into one call for use at the pipeline
    boundary.  Does NOT mutate the original alert.

    Args:
        alert:     The alert to process.
        fields:    Field names to redact (passed to ``Alert.redact``).
        keep_raw:  Forensic override.  When ``True``, ``raw`` is preserved in
                   the output alert even though redaction is active.  IOC
                   extraction will then still mine raw — only channel 3
                   (IOC-drop) applies.  Use only when the operator explicitly
                   needs the raw dict (e.g. ``cfg.redaction.redact_raw=True``).

    Steps:
      1. Capture pre-redaction values (Channel 3 setup).
      2. Redact named fields + blank raw unless keep_raw (Channel 1 + 2).
      3. Run IOC extraction on the suppressed alert.
      4. Drop any extracted IOC whose value equals a redacted value (Channel 3).

    Returns the fully-cleaned enriched ``Alert``.
    """
    from sift.pipeline.ioc_extractor import enrich_alert_iocs

    # Step 1: capture values before blanking
    redacted_values = get_redacted_values(alert, fields)

    # Step 2: redact fields + blank raw (channels 1 + 2)
    suppressed = redact_and_suppress_raw(alert, fields, keep_raw=keep_raw)

    # Step 3: IOC extraction — raw is {} so no raw mining occurs (channel 2)
    enriched = enrich_alert_iocs(suppressed)

    # Step 4: drop IOC entries matching redacted values (channel 3)
    clean_iocs, clean_typed = drop_redacted_iocs(enriched.iocs, enriched.iocs_typed, redacted_values)
    return enriched.model_copy(update={"iocs": clean_iocs, "iocs_typed": clean_typed})
