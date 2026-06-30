"""LicenseRef synthesis for non-SPDX licenses.

A non-SPDX license (e.g. "CANN Open Software License 2.0") cannot be emitted
as a bare string in CycloneDX or SPDX — the validators reject it.  This module
converts such strings into a ``LicenseRef-<slug>`` identifier and pairs it with
the full license text so emitters can inline the text
(CycloneDX ``license.text``; SPDX ``hasExtractedLicensingInfos``).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# SPDX expression validation helpers
# ---------------------------------------------------------------------------

# A minimal (non-exhaustive) set of known SPDX license identifiers/keywords.
# We do a structural check rather than shipping the full SPDX license list.
_SPDX_KEYWORDS = frozenset(
    {
        "AND",
        "OR",
        "WITH",
        "NOASSERTION",
        "NONE",
    }
)

# SPDX specifies identifiers must only contain [idstring] chars:
# Letters, numbers, hyphens, and dots.  We also permit '+' for GPL-2.0+.
_SPDX_ID_CHAR = re.compile(r"^[A-Za-z0-9\-\.+]+$")


def is_spdx_expression(expr: str) -> bool:
    """Return ``True`` if *expr* is a plausibly valid SPDX license expression.

    Accepts:
    - Simple identifiers: ``"MIT"``, ``"Apache-2.0"``, ``"GPL-2.0-only"``
    - ``LicenseRef-*`` identifiers
    - Compound expressions with ``AND``/``OR``/``WITH`` (possibly parenthesised)
    - The special values ``"NOASSERTION"`` and ``"NONE"``

    Rejects:
    - Multi-word phrases that lack SPDX logical operators (AND/OR/WITH),
      e.g. ``"CANN Open Software License 2.0"`` or ``"GPL v2"``.

    This is a structural heuristic, not a full SPDX-expression parser.  Its
    purpose is to decide whether an emitter should use the value verbatim or
    wrap it as a ``LicenseRef-…``.
    """
    if not expr or not isinstance(expr, str):
        return False

    stripped = expr.strip()
    if not stripped:
        return False

    # Special SPDX values
    if stripped in ("NOASSERTION", "NONE"):
        return True

    # Strip all balanced parentheses for structural check
    flat = stripped.replace("(", " ").replace(")", " ").strip()

    # Split on whitespace into tokens
    tokens = [t for t in re.split(r"\s+", flat) if t]
    if not tokens:
        return False

    # Every token must be either a logical keyword or a valid SPDX identifier.
    for token in tokens:
        if token in _SPDX_KEYWORDS:
            continue
        if not _SPDX_ID_CHAR.match(token):
            return False

    # In a valid SPDX expression, identifier tokens and operator tokens must
    # alternate correctly.  The simplest structural rule that catches the common
    # false-positive cases ("CANN Open Software License 2.0", "GPL v2") is:
    #
    # Any two consecutive non-operator tokens is invalid — it means the
    # expression has adjacent identifiers without a logical operator between them.
    id_tokens = [t for t in tokens if t not in _SPDX_KEYWORDS]
    op_tokens = [t for t in tokens if t in _SPDX_KEYWORDS]

    if len(id_tokens) > 1 and len(op_tokens) == 0:
        # Multiple identifiers with no operators: plain English phrase, not SPDX.
        return False

    # Must start and end with an identifier (not an operator)
    first = tokens[0]
    last = tokens[-1]
    if first in _SPDX_KEYWORDS or last in _SPDX_KEYWORDS:
        return False

    # Structural checks passed. For an expression that is NOT a LicenseRef (the
    # SPDX license list deliberately does not model those), additionally require
    # every identifier to be a REAL SPDX license/exception id. Without this a
    # string that merely LOOKS like an id -- e.g. ``MPL2`` (a Notice's non-standard
    # spelling of ``MPL-2.0``) -- passes structurally, is emitted verbatim, and is
    # then rejected by the SPDX validator. Treating it as non-SPDX routes it to a
    # ``LicenseRef`` instead (valid output, honest about the non-standard name).
    if "licenseref-" not in stripped.lower() and not _spdx_known(stripped):
        return False

    return True


_spdx_licensing = None


def _spdx_known(expr: str) -> bool:
    """True if every symbol in ``expr`` is a known SPDX license/exception id.

    Backed by the ``license_expression`` SPDX list (a transitive dep of
    spdx-tools). If the library is unavailable it returns ``True`` so the
    structural heuristic alone decides -- the check never gets *stricter* than
    before when the list cannot be loaded.
    """
    global _spdx_licensing
    try:
        if _spdx_licensing is None:
            from license_expression import get_spdx_licensing

            _spdx_licensing = get_spdx_licensing()
        info = _spdx_licensing.validate(expr)
    except Exception:  # noqa: BLE001 -- any failure -> defer to structural heuristic
        return True
    return not info.errors


# ---------------------------------------------------------------------------
# LicenseRef slug generation
# ---------------------------------------------------------------------------

def _make_slug(name: str) -> str:
    """Convert a license display name into a ``LicenseRef``-safe slug.

    SPDX allows ``[idstring]`` chars (letters, digits, hyphens) in
    ``LicenseRef-<slug>``.  We replace spaces and dots with hyphens, strip
    other non-conforming characters, and collapse consecutive hyphens.
    """
    # Replace common separators with hyphens
    slug = re.sub(r"[\s/_.]+", "-", name)
    # Remove anything that isn't a letter, digit, or hyphen
    slug = re.sub(r"[^A-Za-z0-9\-]", "", slug)
    # Collapse runs of hyphens
    slug = re.sub(r"-{2,}", "-", slug)
    # Strip leading/trailing hyphens
    slug = slug.strip("-")
    return slug


def synthesize(expr_or_text: str, name: str) -> tuple[str, str]:
    """Return ``(licenseref_id, full_text)`` for a non-SPDX license.

    ``licenseref_id`` is a ``LicenseRef-<slug>`` string built from *name*
    (e.g. ``"CANN Open Software License 2.0"`` →
    ``"LicenseRef-CANN-Open-Software-License-2-0"``).

    ``full_text`` is *expr_or_text* (the full license text or the raw
    expression when no separate text is available).  Emitters inline the
    text so SPDX validators don't reject the ``LicenseRef-…`` as undefined.

    Usage example::

        licenseref_id, text = synthesize(license_text, "CANN Open Software License 2.0")
        component.license = licenseref_id
        # emitter inlines text via hasExtractedLicensingInfos / license.text
    """
    slug = _make_slug(name)
    if not slug:
        # A name of only non-ASCII / punctuation chars (e.g. a Chinese license
        # string) slugs to empty -> a bare "LicenseRef-" which SPDX rejects and
        # which invalidates the whole document. Fall back to a deterministic
        # content hash so the id is valid AND distinct names stay distinct.
        import hashlib

        digest = hashlib.sha1(name.encode("utf-8", "replace")).hexdigest()[:8]
        slug = f"unknown-{digest}"
    licenseref_id = f"LicenseRef-{slug}"
    return licenseref_id, expr_or_text
