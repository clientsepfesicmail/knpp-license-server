"""Privacy-first Bank Import Pro statement processing for the Flutter Web app.

Phase 3/4 rules:
- Reuse the tested desktop Bank Import Pro parser for normal bank-generated PDFs.
- Fall back to free local Tesseract OCR only when normal PDF extraction fails.
- Do not persist extracted transactions. Return preview rows to the authenticated
  browser and keep only processing metadata in Supabase.
"""

from __future__ import annotations

import math
import os
import shutil
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any

from core import banksync_engine as engine


def _as_float(value: Any) -> float:
    try:
        return round(float(value or 0), 2)
    except Exception:
        return 0.0


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def processor_capabilities() -> dict[str, Any]:
    """Expose deployment capability without leaking any secret."""
    tesseract_path = shutil.which(os.environ.get("TESSERACT_CMD", "tesseract"))
    try:
        import pypdfium2  # noqa: F401
        pdf_renderer_ready = True
    except Exception:
        pdf_renderer_ready = False
    try:
        import pytesseract  # noqa: F401
        pytesseract_ready = True
    except Exception:
        pytesseract_ready = False
    return {
        "digital_pdf": True,
        "ocr_enabled": os.environ.get("BANK_IMPORT_OCR_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"},
        "tesseract_installed": bool(tesseract_path),
        "pdf_renderer_installed": pdf_renderer_ready,
        "pytesseract_installed": pytesseract_ready,
        "ocr_ready": bool(tesseract_path and pdf_renderer_ready and pytesseract_ready),
        "max_ocr_pages": max(1, _safe_int(os.environ.get("MAX_BANK_IMPORT_OCR_PAGES", "30"), 30)),
    }


def count_pdf_pages(pdf_path: str, password: str = "") -> int:
    try:
        from pypdf import PdfReader
        reader = PdfReader(pdf_path)
        if getattr(reader, "is_encrypted", False):
            if not password:
                raise RuntimeError("This PDF is password-protected. Enter the PDF password and process again.")
            unlocked = reader.decrypt(password)
            if not unlocked:
                raise RuntimeError("The PDF password is incorrect. Enter the correct password and process again.")
        return len(reader.pages)
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Could not read the PDF page count: {type(exc).__name__}: {str(exc).strip()}") from exc


def _verify_pdf_signature(pdf_path: str) -> None:
    try:
        with open(pdf_path, "rb") as handle:
            head = handle.read(1024)
        if b"%PDF-" not in head:
            raise RuntimeError("The uploaded file is not a valid PDF bank statement.")
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError("The temporary PDF could not be opened for processing.") from exc


def _preprocess_for_ocr(image):
    from PIL import ImageFilter, ImageOps
    gray = ImageOps.grayscale(image)
    gray = ImageOps.autocontrast(gray, cutoff=1)
    if gray.width < 1800:
        ratio = 1800 / max(1, gray.width)
        gray = gray.resize((1800, max(1, int(gray.height * ratio))))
    gray = gray.filter(ImageFilter.UnsharpMask(radius=1.2, percent=150, threshold=3))
    return gray


def _ocr_pdf_text(pdf_path: str, password: str, page_count: int) -> tuple[str, float]:
    caps = processor_capabilities()
    if not caps["ocr_enabled"]:
        raise RuntimeError("This PDF appears scanned/image-based. Free OCR is disabled on the processing server.")
    if not caps["ocr_ready"]:
        raise RuntimeError(
            "This PDF appears scanned/image-based. Free OCR support is coded, but Tesseract is not installed on the server yet. "
            "Deploy the included Dockerfile before testing scanned PDFs."
        )
    max_pages = int(caps["max_ocr_pages"])
    if page_count > max_pages:
        raise RuntimeError(
            f"This scanned PDF contains {page_count} pages. The free OCR safety limit is {max_pages} pages per file. "
            "Split the scanned PDF into smaller files and process again."
        )

    import pypdfium2 as pdfium
    import pytesseract
    from pytesseract import Output

    psm = str(_safe_int(os.environ.get("BANK_IMPORT_TESSERACT_PSM", "6"), 6))
    scale = float(os.environ.get("BANK_IMPORT_OCR_RENDER_SCALE", "2.5") or 2.5)
    text_parts: list[str] = []
    confidences: list[float] = []
    try:
        document = pdfium.PdfDocument(pdf_path, password=password or None)
    except Exception as exc:
        raise RuntimeError("Could not render the scanned PDF. Check the PDF password and try again.") from exc

    try:
        for page_index in range(len(document)):
            page = document[page_index]
            bitmap = page.render(scale=scale)
            image = bitmap.to_pil()
            prepared = _preprocess_for_ocr(image)
            data = pytesseract.image_to_data(prepared, output_type=Output.DICT, config=f"--psm {psm} -l eng")
            grouped: OrderedDict[tuple[int, int, int], list[str]] = OrderedDict()
            for index, token in enumerate(data.get("text", [])):
                value = str(token or "").strip()
                if not value:
                    continue
                key = (
                    int(data.get("block_num", [0])[index] or 0),
                    int(data.get("par_num", [0])[index] or 0),
                    int(data.get("line_num", [0])[index] or 0),
                )
                grouped.setdefault(key, []).append(value)
                try:
                    confidence = float(data.get("conf", ["-1"])[index])
                    if confidence >= 0:
                        confidences.append(confidence)
                except Exception:
                    pass
            lines = [" ".join(tokens) for tokens in grouped.values() if tokens]
            text_parts.append("\n".join(lines))
            try:
                prepared.close()
                image.close()
                bitmap.close()
                page.close()
            except Exception:
                pass
    finally:
        try:
            document.close()
        except Exception:
            pass
    return "\n".join(text_parts).strip(), round(sum(confidences) / len(confidences), 1) if confidences else 0.0


def _normalize_bank(value: Any) -> str:
    text = str(value or "AUTO").strip().upper()
    return "AUTO" if not text else text


def _apply_contra_detection(txns: list[dict[str, Any]]) -> None:
    import re
    contra_keywords = [
        "cash deposit", "cash deposited", "cash dep", "cash dep self", "cash deposit self",
        "cash depositself", "by cash", "cash -", "cash /", "cdm deposit", "cdm cash", "atm dep",
        "atm deposit", "cash withdrawal", "cash withdrawn", "cash withd", "cash wdl", "cash withdraw self",
        "cash withdrawal self", "cash withdrawal by self", "cash wd", "cash w/d", "atm withdrawal",
        "atm cash withdrawal", "atm wd", "atm wdl", "cash at atm", "cash withdrawl",
    ]
    non_contra_keywords = [
        "cash dep chg", "cash deposit chg", "cash handling", "inter city", "intercity", "charges", "charge",
        " chg ", " chgs ", "+gst", "fee", "fees", "commission", "interest", "gst on", "imps", "upi/cr",
        "upi/dr", "neft", "rtgs", "by transfer", "transfer from", "transfer to", "cheque deposit", "inb ",
        "inbct", "sbiy", "salary",
    ]
    for txn in txns:
        raw = " ".join(str(txn.get(key) or "") for key in ("narration", "description", "particulars", "remarks"))
        narration = re.sub(r"\s+", " ", re.sub(r"[-_]+", " ", raw)).lower().strip()
        debit = _as_float(txn.get("debit"))
        credit = _as_float(txn.get("credit"))
        if any(keyword in narration for keyword in non_contra_keywords):
            continue
        is_contra = any(keyword in narration for keyword in contra_keywords)
        if not is_contra:
            is_contra = any(word in narration for word in ("cash", "atm", "cdm")) and any(
                word in narration for word in ("deposit", "withdraw", "withdrawal", "withdrawl", "wdl", "self")
            )
        if not is_contra and debit > 0 and narration.startswith("cash "):
            is_contra = True
        if is_contra and (debit > 0 or credit > 0):
            txn["_original_voucher_type"] = txn.get("voucher_type", "")
            txn["voucher_type"] = "Contra"
            txn["contra_subtype"] = "cash_deposit" if credit > 0 else "cash_withdrawal"


def _finalize_transactions(txns: list[dict[str, Any]], *, extraction_mode: str, ocr_confidence: float = 0.0) -> dict[str, Any]:
    clean_rows: list[dict[str, Any]] = []
    for sequence, raw in enumerate(txns, 1):
        row = dict(raw or {})
        date_value = row.get("date")
        if isinstance(date_value, datetime):
            iso_date = date_value.date().isoformat()
            display_date = date_value.strftime("%d %b %Y")
        else:
            iso_date = str(date_value or "")
            display_date = iso_date
        debit = _as_float(row.get("debit"))
        credit = _as_float(row.get("credit"))
        balance = _as_float(row.get("balance"))
        voucher_type = str(row.get("voucher_type") or ("Payment" if debit > 0 else "Receipt"))
        clean_rows.append({
            "sequence": int(row.get("_bank_import_seq") or sequence),
            "date": iso_date,
            "display_date": display_date,
            "voucher_type": voucher_type,
            "narration": str(row.get("narration") or row.get("description") or row.get("particulars") or "").strip(),
            "reference": str(row.get("ref") or row.get("reference") or "").strip(),
            "debit": debit,
            "credit": credit,
            "balance": balance,
            "contra_subtype": str(row.get("contra_subtype") or ""),
            "needs_review": extraction_mode == "ocr",
            "review_reason": "OCR-extracted row: verify before Tally push." if extraction_mode == "ocr" else "",
        })

    # Soft running-balance review. Some overdraft statements show balance as an
    # absolute DR figure, so accept either positive or negative opening sign.
    mismatch_count = 0
    for index in range(1, len(clean_rows)):
        prev = clean_rows[index - 1]
        current = clean_rows[index]
        if not prev["balance"] or not current["balance"]:
            continue
        debit = current["debit"]
        credit = current["credit"]
        candidates = {
            round(abs(prev["balance"] - debit + credit), 2),
            round(abs(-prev["balance"] - debit + credit), 2),
        }
        if not any(math.isclose(current["balance"], candidate, abs_tol=0.05) for candidate in candidates):
            current["needs_review"] = True
            current["review_reason"] = "Running-balance check needs manual review."
            mismatch_count += 1

    payments = [row for row in clean_rows if row["voucher_type"] == "Payment"]
    receipts = [row for row in clean_rows if row["voucher_type"] == "Receipt"]
    contra = [row for row in clean_rows if row["voucher_type"] == "Contra"]
    return {
        "transactions": clean_rows,
        "total": len(clean_rows),
        "total_debit": round(sum(row["debit"] for row in clean_rows), 2),
        "total_credit": round(sum(row["credit"] for row in clean_rows), 2),
        "payment_count": len(payments),
        "receipt_count": len(receipts),
        "contra_count": len(contra),
        "payment_total": round(sum(row["debit"] for row in payments), 2),
        "receipt_total": round(sum(row["credit"] for row in receipts), 2),
        "contra_total": round(sum(row["debit"] + row["credit"] for row in contra), 2),
        "review_count": sum(1 for row in clean_rows if row["needs_review"]),
        "balance_mismatch_count": mismatch_count,
        "ocr_confidence": round(float(ocr_confidence or 0), 1),
    }


def _parse_ocr_text(text: str, requested_bank: str) -> tuple[str, list[dict[str, Any]], list[tuple[int, int]]]:
    bank = requested_bank if requested_bank not in {"", "AUTO"} else engine.detect_bank(text)
    upper = str(bank or "UNKNOWN").upper()
    txns: list[dict[str, Any]] = []
    if upper == "HDFC":
        txns = engine.parse_hdfc_text(text)
    elif upper == "ICICI":
        txns = engine.parse_icici_text(text)
    elif upper in {"SOUTH INDIAN BANK", "SIB"}:
        txns = engine.parse_south_indian_bank_text(text)
    elif upper == "INDIAN BANK":
        txns = engine.parse_indian_bank_text(text)
    if not txns:
        txns = engine.parse_from_text(text, bank=bank)
    if not txns:
        raise RuntimeError(
            "Free OCR could read the scanned pages, but transactions could not be extracted reliably. "
            "Upload a clearer scan or a bank-downloaded searchable PDF."
        )
    txns.sort(key=lambda row: row.get("date") or datetime.min)
    for sequence, txn in enumerate(txns, 1):
        txn.setdefault("_bank_import_seq", sequence)
    _apply_contra_detection(txns)
    return bank, txns, engine.find_duplicates(txns)


def process_bank_statement(pdf_path: str, *, password: str = "", bank: str = "AUTO") -> dict[str, Any]:
    _verify_pdf_signature(pdf_path)
    page_count = count_pdf_pages(pdf_path, password=password)
    requested_bank = _normalize_bank(bank)
    digital_error = ""
    try:
        parsed = engine.convert(
            pdf_path=pdf_path,
            bank=requested_bank,
            password=password,
            skip_duplicates=False,
            export_formats=[],
        )
        summary = _finalize_transactions(parsed.get("transactions") or [], extraction_mode="digital")
        summary.update({
            "bank": parsed.get("bank") or "UNKNOWN",
            "page_count": page_count,
            "extraction_mode": "digital",
            "duplicates_detected": len(parsed.get("duplicates") or []),
            "message": "Digital PDF extracted successfully using the tested Bank Import Pro parser.",
        })
        return summary
    except Exception as exc:
        digital_error = str(exc).strip()

    ocr_text, ocr_confidence = _ocr_pdf_text(pdf_path, password=password, page_count=page_count)
    if not ocr_text:
        raise RuntimeError("Free OCR could not read text from this scanned PDF. Upload a clearer scan.")
    detected_bank, txns, duplicates = _parse_ocr_text(ocr_text, requested_bank)
    summary = _finalize_transactions(txns, extraction_mode="ocr", ocr_confidence=ocr_confidence)
    summary.update({
        "bank": detected_bank or "UNKNOWN",
        "page_count": page_count,
        "extraction_mode": "ocr",
        "duplicates_detected": len(duplicates),
        "message": "Scanned PDF extracted using free Tesseract OCR. Review highlighted rows before Tally push.",
        "digital_parser_note": digital_error[:500],
    })
    return summary
