#!/usr/bin/env python3
"""Passive attachment inspection and hash-only threat intelligence enrichment."""
import sys
import os
import json
import re
import hashlib
from pathlib import Path
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv
from PIL import Image
import pytesseract
from pypdf import PdfReader

load_dotenv(Path(__file__).with_name('api_keys.env'))
URL_REGEX = r'https?://[^\s<>\"]+|www\.[^\s<>\"]+'
IGNORED_DOMAINS = {'w3.org', 'schema.org', 'adobe.com'}

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        domain = (parsed.hostname or '').lower()
        return bool(domain) and domain not in IGNORED_DOMAINS and not any(domain.endswith('.' + d) for d in IGNORED_DOMAINS)
    except Exception:
        return False

def extract_urls_from_string(text: str) -> list:
    return sorted({clean for match in re.findall(URL_REGEX, text) if (clean := match.strip('.,;()[]{}')) and is_valid_url(clean)})

def extract_pdf_content(pdf_path: str) -> dict:
    extracted_text = ''
    embedded_uris = set()
    try:
        reader = PdfReader(pdf_path)
        for page in reader.pages:
            extracted_text += (page.extract_text() or '') + '\n'
            for annot in page.get('/Annots', []):
                try:
                    obj = annot.get_object()
                    if obj.get('/Subtype') == '/Link':
                        action = obj.get('/A')
                        if action and '/URI' in action:
                            uri = str(action['/URI']).strip()
                            if is_valid_url(uri):
                                embedded_uris.add(uri)
                except Exception:
                    continue
    except Exception as exc:
        return {'error': f'Failed to parse PDF: {exc}'}
    text_urls = extract_urls_from_string(extracted_text)
    all_urls = sorted(embedded_uris | set(text_urls))
    return {'file_type': 'PDF', 'page_count': len(reader.pages),
            'extracted_text_snippet': extracted_text.strip()[:500] if extracted_text.strip() else 'No extractable plain text',
            'embedded_annotation_uris': sorted(embedded_uris), 'text_rendered_urls': text_urls,
            'all_extracted_urls': all_urls, 'has_clickable_actions': bool(all_urls)}

def extract_image_content(image_path: str) -> dict:
    try:
        with Image.open(image_path) as img:
            ocr_text = pytesseract.image_to_string(img)
            fmt, size = img.format, f'{img.width}x{img.height}'
        urls = extract_urls_from_string(ocr_text)
        return {'file_type': 'IMAGE', 'image_format': fmt, 'image_size': size,
                'ocr_text': ocr_text.strip() or 'No text recognized',
                'extracted_urls': urls, 'has_clickable_actions': bool(urls)}
    except Exception as exc:
        return {'error': f'Failed to process Image via OCR: {exc}'}

def analyze_attachment_content(file_path: str) -> dict:
    if not os.path.isfile(file_path):
        return {'error': f'File not found or not a regular file: {file_path}'}
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.pdf':
        return extract_pdf_content(file_path)
    if ext in ('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff'):
        return extract_image_content(file_path)
    return {'file_type': 'BINARY_OTHER', 'extension': ext,
            'note': 'Content extraction skipped; hash-only intelligence lookup (no file execution or upload).'}

def file_hashes(path: str) -> dict:
    digests = {name: hashlib.new(name) for name in ('md5', 'sha1', 'sha256')}
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}

def request_error(response):
    if response.status_code == 404:
        return {'status': 'NOT_FOUND', 'reason': 'No existing record'}
    if response.status_code == 429:
        return {'status': 'UNAVAILABLE', 'reason': 'Rate limited (429)'}
    if response.status_code in (401, 403):
        return {'status': 'UNAVAILABLE', 'reason': f'API authentication/permission denied ({response.status_code})'}
    return {'status': 'ERROR', 'reason': f'HTTP {response.status_code}'}

def check_virustotal(sha256: str) -> dict:
    key = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    if not key:
        return {'status': 'SKIPPED', 'reason': 'VIRUSTOTAL_API_KEY missing'}
    try:
        response = requests.get(f'https://www.virustotal.com/api/v3/files/{sha256}',
                                headers={'x-apikey': key}, timeout=(5, 20))
        if response.status_code != 200:
            return request_error(response)
        attrs = response.json().get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats')
        if not isinstance(stats, dict) or not stats:
            return {'status': 'INCONCLUSIVE', 'reason': 'No file analysis statistics'}
        return {'status': 'SUCCESS', 'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0), 'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0), 'last_analysis_date': attrs.get('last_analysis_date'),
                'meaningful_name': attrs.get('meaningful_name')}
    except (requests.RequestException, ValueError, TypeError) as exc:
        return {'status': 'ERROR', 'reason': str(exc)}

def check_malwarebazaar(sha256: str) -> dict:
    key = os.getenv('MALWAREBAZAAR_API_KEY', '').strip()
    if not key:
        return {'status': 'SKIPPED', 'reason': 'MALWAREBAZAAR_API_KEY missing'}
    try:
        response = requests.post('https://mb-api.abuse.ch/api/v1/',
                                 headers={'Auth-Key': key},
                                 data={'query': 'get_info', 'hash': sha256}, timeout=(5, 20))
        if response.status_code != 200:
            return request_error(response)
        body = response.json()
        status = body.get('query_status')
        if status == 'hash_not_found':
            return {'status': 'NOT_FOUND', 'reason': 'Hash not in MalwareBazaar database'}
        if status == 'ok' and isinstance(body.get('data'), list) and body['data']:
            entry = body['data'][0]
            return {'status': 'MALICIOUS', 'signature': entry.get('signature'),
                    'tags': entry.get('tags'), 'first_seen': entry.get('first_seen'),
                    'file_type': entry.get('file_type')}
        return {'status': 'ERROR', 'reason': f'Unexpected MalwareBazaar query_status: {status}'}
    except (requests.RequestException, ValueError, TypeError) as exc:
        return {'status': 'ERROR', 'reason': str(exc)}

def correlate(reports: dict) -> dict:
    vt, mb = reports['virustotal'], reports['malwarebazaar']
    flags = []
    malicious = 0
    suspicious = 0
    no_detection = 0
    if vt['status'] == 'SUCCESS':
        if vt.get('malicious', 0) > 0:
            malicious += 1
            flags.append(f"VirusTotal: {vt['malicious']} engines marked file malicious")
        elif vt.get('suspicious', 0) > 0:
            suspicious += 1
            flags.append(f"VirusTotal: {vt['suspicious']} engines marked file suspicious")
        else:
            no_detection += 1
    if mb['status'] == 'MALICIOUS':
        malicious += 1
        flags.append('MalwareBazaar: file hash matched a malware sample')
    elif mb['status'] == 'NOT_FOUND':
        no_detection += 1
    if malicious:
        verdict = 'MALICIOUS'
    elif suspicious:
        verdict = 'SUSPICIOUS'
    elif no_detection:
        verdict = 'NO_KNOWN_THREATS'
    else:
        verdict = 'INCONCLUSIVE'
    return {'verdict': verdict, 'threat_score': malicious * 2 + suspicious,
            'engine_summary': {'total_tools_configured': len(reports),
                               'malicious_count': malicious, 'suspicious_count': suspicious,
                               'no_detection_count': no_detection,
                               'unavailable_or_error_count': sum(1 for r in reports.values() if r['status'] not in ('SUCCESS', 'MALICIOUS', 'NOT_FOUND'))},
            'triggered_flags': flags,
            'note': 'Hash reputation only; absence of detections is not proof of safety.'}

def analyze_file(path: str) -> dict:
    if not os.path.isfile(path):
        return {'error': f'File not found or not a regular file: {path}'}
    try:
        hashes = file_hashes(path)
    except OSError as exc:
        return {'error': f'Unable to read file: {exc}'}
    reports = {'virustotal': check_virustotal(hashes['sha256']),
               'malwarebazaar': check_malwarebazaar(hashes['sha256'])}
    correlation = correlate(reports)
    return {'file_name': os.path.basename(path), 'file_size_bytes': os.path.getsize(path),
            'hashes': hashes, 'content_analysis': analyze_attachment_content(path),
            **correlation, 'raw_engine_reports': reports}

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python attachment_analyzer_ti.py <file_path>')
        sys.exit(1)
    print(json.dumps(analyze_file(sys.argv[1]), indent=2))
