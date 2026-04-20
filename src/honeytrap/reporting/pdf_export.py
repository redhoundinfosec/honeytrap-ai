"""HTML -> PDF conversion for HoneyTrap reports.

Uses ``weasyprint`` when available. If the import fails (optional
dependency not installed), :func:`export_pdf` logs a warning pointing to
the ``[pdf]`` extras and raises :class:`PDFExportError`.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class PDFExportError(RuntimeError):
    """Raised when PDF export cannot be performed."""


def _load_weasyprint():  # pragma: no cover - trivial import shim
    try:
        import weasyprint  # type: ignore[import-not-found]

        return weasyprint
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "weasyprint is not installed: %s. Install with `pip install honeytrap-ai[pdf]`.",
            exc,
        )
        return None


def is_available() -> bool:
    """Return True if the weasyprint backend can be imported."""
    return _load_weasyprint() is not None


def export_pdf(html_content: str, output_path: Path | str) -> Path:
    """Render ``html_content`` to a PDF file at ``output_path``.

    Raises :class:`PDFExportError` if weasyprint is not installed or the
    conversion fails. Returns the path that was written on success.
    """
    weasy = _load_weasyprint()
    if weasy is None:
        raise PDFExportError(
            "weasyprint is not installed. Install with `pip install honeytrap-ai[pdf]`."
        )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        weasy.HTML(string=html_content).write_pdf(str(out))
    except Exception as exc:  # noqa: BLE001
        logger.warning("PDF export failed: %s", exc)
        raise PDFExportError(f"PDF export failed: {exc}") from exc
    return out


__all__ = ["export_pdf", "is_available", "PDFExportError"]
