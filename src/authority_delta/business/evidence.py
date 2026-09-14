"""Preserve originals; bounded text extraction is not evidence verification."""
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import PurePath

MAX_FILE_BYTES = 2_000_000
MAX_TEXT_BYTES = 100_000


def extract(name, raw):
    if not isinstance(name, str) or not name or '\\' in name or PurePath(name).name != name or len(name) > 160 or any(ord(c) < 32 for c in name):
        raise ValueError('Use a plain file name')
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise ValueError('Select a nonempty file no larger than 2 MB')
    suffix = name.rsplit('.', 1)[-1].lower()
    mime = {'txt': 'text/plain', 'pdf': 'application/pdf', 'json': 'application/json'}.get(suffix)
    if not mime:
        raise ValueError('Use TXT, text PDF or JSON evidence')
    try:
        if suffix in ('txt', 'json'):
            text = raw.decode('utf-8-sig')
            if suffix == 'json':
                json.loads(text)
            if '\x00' in text:
                raise ValueError('Binary text is not supported')
            method = 'UTF8_TEXT' if suffix == 'txt' else 'UTF8_JSON'
        else:
            if not raw.startswith(b'%PDF-'):
                raise ValueError('Invalid PDF signature')
            # Keep PDF parsing outside the API process and bound time/memory.
            result = subprocess.run([sys.executable, '-m', 'authority_delta.business.evidence', '--pdf'],
                                    input=raw, capture_output=True, timeout=10)
            if result.returncode:
                raise ValueError('PDF text could not be extracted; use a text PDF or TXT')
            payload = json.loads(result.stdout)
            if payload.get('status') != 'READY':
                raise ValueError(payload.get('reason', 'PDF needs readable text'))
            text, method = payload['text'], 'PYPDF_TEXT'
        if not text.strip():
            raise ValueError('No readable text was found')
        if len(text.encode()) > MAX_TEXT_BYTES:
            raise ValueError('Extracted text is too long; split the document')
        return {'status': 'READY', 'text': text, 'method': method, 'content_type': mime, 'reason': None}
    except (ValueError, UnicodeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {'status': 'NEEDS_INPUT', 'text': '', 'method': None, 'content_type': mime, 'reason': str(exc)[:250]}


def pdf_child():
    import io
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (350_000_000, 350_000_000))
    resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
    from pypdf import PdfReader
    try:
        raw = sys.stdin.buffer.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('PDF exceeds the file limit')
        reader = PdfReader(io.BytesIO(raw), strict=True)
        if reader.is_encrypted:
            raise ValueError('Encrypted PDF needs an unlocked text copy')
        if not 1 <= len(reader.pages) <= 30:
            raise ValueError('Use a PDF with one to thirty pages')
        pages = []
        size = 0
        for i, page in enumerate(reader.pages):
            text = page.extract_text() or ''
            if not text.strip():
                raise ValueError('A PDF page has no extractable text; provide a text version')
            size += len(text.encode())
            if size > MAX_TEXT_BYTES:
                raise ValueError('PDF text is too long; split the document')
            pages.append(f'[Page {i+1}]\n{text}')
        print(json.dumps({'status': 'READY', 'text': '\n\n'.join(pages)}))
    except Exception:
        print(json.dumps({'status': 'NEEDS_INPUT', 'reason': 'PDF could not be read within the supported text, page or memory limits'}))


if __name__ == '__main__':
    pdf_child()
