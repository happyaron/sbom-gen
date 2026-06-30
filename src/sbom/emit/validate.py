"""Schema validation via the official libraries' own validators.

No vendored schemas: ``validate_cyclonedx`` uses ``cyclonedx-python-lib``'s
``JsonStrictValidator`` (CycloneDX 1.5) and ``validate_spdx`` uses
``spdx-tools``' full-document validator (SPDX 2.3). Each returns ``[]`` on
success, otherwise one :class:`~sbom.models.Warning` per issue.
"""

from __future__ import annotations

from ..models import Warning


def validate_cyclonedx(json_text: str) -> list[Warning]:
    """Validate ``json_text`` against CycloneDX 1.5; return ``[]`` if valid.

    Each schema violation becomes a ``Warning(code="cyclonedx_invalid", ...)``.
    If the validator's optional dependency (``jsonschema``) is unavailable, a
    single ``cyclonedx_validation_unavailable`` warning is returned instead of
    raising, so the pipeline still completes.
    """
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    validator = JsonStrictValidator(SchemaVersion.V1_5)
    try:
        errors = validator.validate_str(json_text, all_errors=True)
    except Exception as exc:  # noqa: BLE001 -- missing optional dep, surfaced
        from cyclonedx.exception import MissingOptionalDependencyException

        if isinstance(exc, MissingOptionalDependencyException):
            return [
                Warning(
                    code="cyclonedx_validation_unavailable",
                    detail=str(exc),
                )
            ]
        raise

    if errors is None:
        return []
    if not _is_iterable(errors):
        errors = [errors]
    warnings: list[Warning] = []
    for err in errors:
        warnings.append(
            Warning(code="cyclonedx_invalid", detail=str(err))
        )
    return warnings


def validate_spdx(json_text: str) -> list[Warning]:
    """Validate ``json_text`` against SPDX 2.3; return ``[]`` if valid.

    Parses the JSON into the ``spdx-tools`` model and runs the library's
    full-document validator. Each validation message becomes a
    ``Warning(code="spdx_invalid", ...)``; a parse failure becomes a single
    ``spdx_invalid`` warning describing the error.
    """
    from spdx_tools.spdx.parser.error import SPDXParsingError
    from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import (
        JsonLikeDictParser,
    )
    from spdx_tools.spdx.validation.document_validator import (
        validate_full_spdx_document,
    )
    import json as _json

    try:
        data = _json.loads(json_text)
        document = JsonLikeDictParser().parse(data)
    except SPDXParsingError as exc:
        return [
            Warning(
                code="spdx_invalid",
                detail="; ".join(exc.get_messages()),
            )
        ]
    except Exception as exc:  # noqa: BLE001 -- malformed input is a finding
        return [Warning(code="spdx_invalid", detail=str(exc))]

    messages = validate_full_spdx_document(document)
    warnings: list[Warning] = []
    for msg in messages:
        detail = getattr(msg, "validation_message", str(msg))
        warnings.append(Warning(code="spdx_invalid", detail=detail))
    return warnings


def _is_iterable(obj) -> bool:
    try:
        iter(obj)
    except TypeError:
        return False
    return not isinstance(obj, (str, bytes))
