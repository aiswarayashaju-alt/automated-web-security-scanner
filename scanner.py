"""Non-invasive HTTP security header and CORS configuration audit.
Only scan websites you own or are authorized to test.
"""
import argparse
import html
import json
import pathlib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HEADERS = {
    'Content-Security-Policy': 'Helps reduce script injection impact',
    'X-Content-Type-Options': 'Prevents MIME sniffing',
    'Referrer-Policy': 'Controls referrer information',
    'Permissions-Policy': 'Restricts browser capabilities',
    'Strict-Transport-Security': 'Encourages HTTPS on subsequent visits',
    'X-Frame-Options': 'Helps prevent framing (CSP frame-ancestors is an alternative)',
}
USER_AGENT = 'EducationalWebSecurityScanner/1.0 (authorized audit)'


def fetch(url, extra_headers=None, method='GET', timeout=8):
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, **(extra_headers or {})}, method=method)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {'status': resp.status, 'headers': dict(resp.headers.items()), 'url': resp.url}
    except urllib.error.HTTPError as exc:
        return {'status': exc.code, 'headers': dict(exc.headers.items()), 'url': exc.url}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_headers(headers):
    return {k.lower(): v for k, v in headers.items()}


def audit_headers(headers, scheme):
    h = normalize_headers(headers)
    findings = []
    csp = h.get('content-security-policy', '')
    for name, purpose in HEADERS.items():
        if name == 'Strict-Transport-Security' and scheme != 'https':
            continue
        if name == 'X-Frame-Options' and 'frame-ancestors' in csp.lower():
            continue
        if name.lower() not in h:
            findings.append({'severity': 'Medium' if name in ('Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options') else 'Low', 'check': name, 'detail': f'Missing {name}. {purpose}.'})
    if h.get('x-content-type-options', '').lower() not in ('', 'nosniff'):
        findings.append({'severity': 'Medium', 'check': 'X-Content-Type-Options', 'detail': 'Expected nosniff value.'})
    return findings


def audit_cors(headers, test_origin):
    h = normalize_headers(headers)
    allow = h.get('access-control-allow-origin', '')
    creds = h.get('access-control-allow-credentials', '').lower() == 'true'
    findings = []
    if allow == '*' and creds:
        findings.append({'severity': 'Medium', 'check': 'CORS', 'detail': 'Wildcard origin combined with credentials; browsers generally block credentialed access, but review policy.'})
    elif allow == '*':
        findings.append({'severity': 'Info', 'check': 'CORS', 'detail': 'Wildcard origin allowed. Verify resource is intended to be public.'})
    elif allow == test_origin and creds:
        findings.append({'severity': 'High', 'check': 'CORS', 'detail': 'Test origin was reflected with credential access. Confirm whether untrusted origins are accepted.'})
    elif allow == test_origin:
        findings.append({'severity': 'Medium', 'check': 'CORS', 'detail': 'Test origin was allowed. Verify origin allowlist.'})
    return findings


def scan(url, timeout=8):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Provide a valid http(s) URL without embedded credentials.')
    # A single origin is requested; no redirects are followed to unrelated hosts.
    origin = 'https://scanner-test.invalid'
    base = fetch(url, timeout=timeout)
    cors = fetch(url, {'Origin': origin}, timeout=timeout)
    findings = audit_headers(base['headers'], parsed.scheme) + audit_cors(cors['headers'], origin)
    return {'target': url, 'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'http_status': base['status'], 'cors_http_status': cors['status'], 'headers': base['headers'], 'cors_response_headers': cors['headers'], 'findings': findings, 'limitations': ['Only one URL is checked; no crawling.', 'Missing headers are indicators, not proof of exploitable vulnerabilities.', 'CORS is checked using one synthetic origin, without authentication.', 'Redirects are not followed.', 'Only run with authorization.']}


def save_reports(result, output):
    path = pathlib.Path(output)
    path.mkdir(parents=True, exist_ok=True)
    (path / 'report.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    rows = ''.join('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(*(html.escape(str(item[k])) for k in ('severity', 'check', 'detail'))) for item in result['findings'])
    page = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Scan Report</title><style>body{{font:16px Arial,sans-serif;max-width:960px;margin:35px auto;padding:0 18px;color:#172b4d}}h1{{color:#123e72}}table{{border-collapse:collapse;width:100%}}td,th{{padding:12px;border:1px solid #d8e0e9;text-align:left}}th{{background:#edf4fc}}tr:nth-child(even){{background:#f8fafc}}.note{{background:#fff8e6;padding:14px;border-radius:8px}}</style><h1>Automated Web Security Scanner</h1><p><b>Target:</b> {html.escape(result['target'])}</p><p><b>Checked (UTC):</b> {html.escape(result['checked_at_utc'])}</p><p><b>HTTP status:</b> {result['http_status']}</p><h2>Findings ({len(result['findings'])})</h2><table><tr><th>Severity</th><th>Check</th><th>Observation</th></tr>{rows}</table><h2>Limitations</h2><div class="note">{''.join('<p>'+html.escape(x)+'</p>' for x in result['limitations'])}</div></html>'''
    (path / 'report.html').write_text(page, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Authorized web header and CORS audit')
    parser.add_argument('url', help='HTTP or HTTPS URL you are authorized to scan')
    parser.add_argument('--output', default='output', help='Report directory')
    parser.add_argument('--timeout', type=float, default=8)
    args = parser.parse_args()
    if not (0 < args.timeout <= 30):
        parser.error('Timeout must be between 0 and 30 seconds.')
    try:
        result = scan(args.url, args.timeout)
        save_reports(result, args.output)
        print('Status:', result['http_status'])
        print('Findings:', len(result['findings']))
        for item in result['findings']:
            print(f"[{item['severity']}] {item['check']}: {item['detail']}")
        print('Reports:', pathlib.Path(args.output).resolve())
    except (ValueError, urllib.error.URLError, TimeoutError, OSError) as exc:
        parser.exit(1, f'Scan failed: {exc}\n')


if __name__ == '__main__':
    main()
