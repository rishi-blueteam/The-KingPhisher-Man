#!/usr/bin/env python3
"""Passive IP investigation: registration, ASN, reputation, DNS, and optional passive DNS.
No traceroute, active scanning, or connection to the investigated IP.
"""
import ipaddress
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name('api_keys.env'))
SESSION = requests.Session()
SESSION.headers.update({'User-Agent': 'SOC-IP-Analyzer/2.0'})


def clean_ip(value):
    return value.strip().replace('[.]', '.').strip('[]')


def error_result(exc):
    return {'status': 'ERROR', 'reason': str(exc)}


def fetch_json(url, *, headers=None, params=None, timeout=(5, 15)):
    try:
        response = SESSION.get(url, headers=headers, params=params, timeout=timeout)
        if response.status_code == 429:
            return {'status': 'UNAVAILABLE', 'reason': 'Rate limited (HTTP 429)'}
        if response.status_code in (401, 403):
            return {'status': 'UNAVAILABLE', 'reason': f'Authorization denied (HTTP {response.status_code})'}
        if response.status_code == 404:
            return {'status': 'NOT_FOUND'}
        response.raise_for_status()
        return {'status': 'SUCCESS', 'data': response.json()}
    except (requests.RequestException, ValueError) as exc:
        return error_result(exc)


def rdap_lookup(ip):
    result = fetch_json(f'https://rdap.org/ip/{ip}')
    if result['status'] != 'SUCCESS':
        return result
    d = result['data']
    cidrs = []
    for item in d.get('cidr0_cidrs', []):
        prefix = item.get('v4prefix') or item.get('v6prefix')
        if prefix is not None and item.get('length') is not None:
            cidrs.append(f"{prefix}/{item['length']}")
    return {'status': 'SUCCESS', 'network_name': d.get('name'), 'handle': d.get('handle'),
            'country': d.get('country'), 'start_address': d.get('startAddress'),
            'end_address': d.get('endAddress'), 'cidrs': cidrs,
            'source': f'https://rdap.org/ip/{ip}'}


def asn_lookup(ip):
    # ipwho.is provides HTTPS enrichment without a key; results are approximate.
    result = fetch_json(f'https://ipwho.is/{ip}')
    if result['status'] != 'SUCCESS':
        return result
    d = result['data']
    if not d.get('success', False):
        return {'status': 'ERROR', 'reason': d.get('message', 'Lookup failed')}
    conn = d.get('connection') or {}
    return {'status': 'SUCCESS', 'asn': conn.get('asn'), 'organization': conn.get('org'),
            'isp': conn.get('isp'), 'country': d.get('country'),
            'usage_type': 'UNKNOWN', 'usage_type_note': 'ASN/ISP alone does not establish residential, proxy, or hosting usage',
            'source': 'https://ipwho.is/'}


def virustotal_lookup(ip):
    key = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    if not key:
        return {'status': 'SKIPPED', 'reason': 'VIRUSTOTAL_API_KEY missing'}
    result = fetch_json(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                        headers={'x-apikey': key})
    if result['status'] != 'SUCCESS':
        return result
    attr = result['data'].get('data', {}).get('attributes', {})
    stats = attr.get('last_analysis_stats') or {}
    if not stats:
        return {'status': 'INCONCLUSIVE', 'reason': 'No last_analysis_stats available'}
    return {'status': 'SUCCESS', 'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0), 'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0), 'reputation': attr.get('reputation'),
            'last_analysis_date': attr.get('last_analysis_date')}


def abuseipdb_lookup(ip):
    key = os.getenv('ABUSEIPDB_API_KEY', '').strip()
    if not key:
        return {'status': 'SKIPPED', 'reason': 'ABUSEIPDB_API_KEY missing'}
    result = fetch_json('https://api.abuseipdb.com/api/v2/check',
                        headers={'Key': key, 'Accept': 'application/json'},
                        params={'ipAddress': ip, 'maxAgeInDays': 90})
    if result['status'] != 'SUCCESS':
        return result
    d = result['data'].get('data') or {}
    if 'abuseConfidenceScore' not in d:
        return {'status': 'INCONCLUSIVE', 'reason': 'No abuse confidence score'}
    return {'status': 'SUCCESS', 'abuse_confidence_score': d.get('abuseConfidenceScore'),
            'total_reports': d.get('totalReports'), 'last_reported_at': d.get('lastReportedAt'),
            'usage_type': d.get('usageType'), 'isp': d.get('isp'),
            'is_whitelisted': d.get('isWhitelisted'), 'is_tor': d.get('isTor')}


def reverse_dns(ip):
    try:
        ptr, _, _ = socket.gethostbyaddr(ip)
    except (OSError, socket.herror) as exc:
        return {'status': 'NO_PTR', 'reason': str(exc), 'forward_confirmed': None}
    try:
        addr = ipaddress.ip_address(ip)
        matches = sorted({entry[4][0] for entry in socket.getaddrinfo(
            ptr, None, socket.AF_INET6 if addr.version == 6 else socket.AF_INET, socket.SOCK_STREAM)})
        confirmed = ip in matches
        return {'status': 'SUCCESS' if confirmed else 'MISMATCH', 'ptr_hostname': ptr,
                'forward_addresses': matches, 'forward_confirmed': confirmed,
                'note': 'FCrDNS mismatch is not proof of spoofing'}
    except OSError as exc:
        return {'status': 'FORWARD_LOOKUP_FAILED', 'ptr_hostname': ptr,
                'forward_confirmed': False, 'reason': str(exc)}


def tor_exit_lookup(ip):
    # Tor Project publishes a snapshot of exit addresses; not a complete proxy/VPN feed.
    try:
        response = SESSION.get('https://check.torproject.org/torbulkexitlist', timeout=(5, 15))
        response.raise_for_status()
        addresses = {line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('#')}
        return {'status': 'SUCCESS', 'is_tor_exit': ip in addresses,
                'source': 'https://check.torproject.org/torbulkexitlist',
                'note': 'Snapshot may lag behind current Tor exit status'}
    except requests.RequestException as exc:
        return error_result(exc)


def passive_dns_lookup(ip):
    # VT relationship coverage is limited by account plan; not an exhaustive reverse-IP census.
    key = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    if not key:
        return {'status': 'SKIPPED', 'reason': 'VIRUSTOTAL_API_KEY missing'}
    result = fetch_json(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions',
                        headers={'x-apikey': key}, params={'limit': 40})
    if result['status'] != 'SUCCESS':
        return result
    items = result['data'].get('data', [])
    domains = sorted({d.get('attributes', {}).get('host_name') for d in items
                      if d.get('attributes', {}).get('host_name')})
    return {'status': 'SUCCESS', 'associated_domains': domains, 'sample_size': len(domains),
            'malicious_neighbor_ratio': None, 'domain_churn': {'status': 'NOT_EVALUATED'},
            'note': 'Historical resolutions are not necessarily currently co-hosted; domain reputations not checked; sample is incomplete'}


# These are contextual indicators, NOT proof of shared infrastructure.
CLOUD_CDN_TERMS = ('cloudflare', 'akamai', 'fastly', 'amazon', 'aws', 'google cloud',
                   'microsoft azure', 'azure', 'cloudfront')


def classify_infrastructure(asn, abuse):
    values = [asn.get('organization'), asn.get('isp'), abuse.get('isp')]
    text = ' '.join(str(v).lower() for v in values if v)
    matches = [term for term in CLOUD_CDN_TERMS if term in text]
    return {'cloud_or_cdn_provider_hint': matches or None,
            'shared_infrastructure_confirmed': None,
            'block_ip_recommendation': 'REVIEW_MANUALLY',
            'note': 'Provider name alone cannot establish whether this specific IP is shared or dedicated'}


def correlate(vt, abuse, tor, rdns, infrastructure):
    flags, malicious_sources, suspicious_sources, evaluated = [], 0, 0, 0
    if vt.get('status') == 'SUCCESS':
        evaluated += 1
        if vt.get('malicious', 0) > 0:
            malicious_sources += 1
            flags.append(f"VirusTotal: {vt['malicious']} engines flagged IP malicious")
        elif vt.get('suspicious', 0) > 0:
            suspicious_sources += 1
            flags.append(f"VirusTotal: {vt['suspicious']} engines flagged IP suspicious")
    if abuse.get('status') == 'SUCCESS':
        evaluated += 1
        score = abuse.get('abuse_confidence_score', 0) or 0
        if score >= 75:
            malicious_sources += 1
            flags.append(f'AbuseIPDB: high abuse confidence ({score}/100)')
        elif score >= 25:
            suspicious_sources += 1
            flags.append(f'AbuseIPDB: elevated abuse confidence ({score}/100)')
    if tor.get('status') == 'SUCCESS':
        evaluated += 1
        if tor.get('is_tor_exit'):
            flags.append('Tor exit node: contextual indicator only, not evidence of malicious activity')
    if rdns.get('status') == 'MISMATCH':
        flags.append('FCrDNS mismatch: configuration/identity observation, not proof of spoofing')
    if malicious_sources:
        verdict = 'MALICIOUS'
    elif suspicious_sources:
        verdict = 'SUSPICIOUS'
    elif evaluated:
        verdict = 'NO_KNOWN_THREATS'
    else:
        verdict = 'INCONCLUSIVE'
    return {'verdict': verdict, 'threat_score': malicious_sources * 2 + suspicious_sources,
            'malicious_source_count': malicious_sources, 'suspicious_source_count': suspicious_sources,
            'reputation_sources_evaluated': int(vt.get('status') == 'SUCCESS') + int(abuse.get('status') == 'SUCCESS'),
            'triggered_flags': flags,
            'blocking_guidance': 'Avoid automatic IP-level blocking; assess tenant ownership and corroborating domain/URL evidence'
                                 if infrastructure.get('cloud_or_cdn_provider_hint') else 'Review context and corroborating evidence before blocking'}


def query_ip_intelligent(ip):
    cleaned = clean_ip(ip)
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return {'query_ip': cleaned, 'error': 'Invalid IPv4 or IPv6 address'}
    ip = str(addr)
    classification = {'version': addr.version, 'is_global': addr.is_global,
                      'is_private': addr.is_private, 'is_loopback': addr.is_loopback,
                      'is_link_local': addr.is_link_local, 'is_multicast': addr.is_multicast}
    if not addr.is_global or addr.is_multicast:
        return {'query_ip': ip, 'ip_classification': classification,
                'risk_assessment': {'verdict': 'NOT_APPLICABLE', 'threat_score': None,
                                    'triggered_flags': ['Non-global or multicast address: external IP reputation not applicable']},
                'note': 'No traceroute performed; no upstream router substituted'}
    rdap = rdap_lookup(ip)
    asn = asn_lookup(ip)
    vt = virustotal_lookup(ip)
    abuse = abuseipdb_lookup(ip)
    tor = tor_exit_lookup(ip)
    rdns = reverse_dns(ip)
    passive = passive_dns_lookup(ip)
    infra = classify_infrastructure(asn, abuse)
    return {'query_ip': ip, 'analyzed_at_utc': datetime.now(timezone.utc).isoformat(),
            'ip_classification': classification,
            'network_intelligence': {'rdap': rdap, 'asn': asn, 'infrastructure': infra},
            'threat_intelligence': {'virustotal': vt, 'abuseipdb': abuse,
                                    'spamhaus': {'status': 'NOT_CONFIGURED', 'reason': 'Requires separately validated supported lookup integration'},
                                    'tor_exit': tor},
            'reverse_ip': passive, 'reverse_dns': rdns,
            'risk_assessment': correlate(vt, abuse, tor, rdns, infra)}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python ip_analyzer_updated.py <ip_address>', file=sys.stderr)
        sys.exit(1)
    print(json.dumps(query_ip_intelligent(sys.argv[1]), indent=2))
