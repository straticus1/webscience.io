"""
WebScience.io - The Web Swiss Army Knife
Comprehensive web analysis: HTTP, Security, Performance, SEO, Screenshots, Monitoring
Part of the After Dark Systems ecosystem
"""

from flask import Flask, request, jsonify, render_template, redirect, session, Response
from flask_cors import CORS
import os
import logging
import requests
import ssl
import socket
import json
import hashlib
import re
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

from bs4 import BeautifulSoup
import dns.resolver
import dns.reversename
import whois as whois_lib

# Shared authentication with DNSScience ecosystem
import sys
_dnsscience_path = os.environ.get(
    'DNSSCIENCE_PATH',
    '/Users/ryan/development/afterdarksys.com/subdomains/dnsscience'
)
sys.path.insert(0, _dnsscience_path)
from database import Database
from auth import UserAuth, login_required, optional_auth

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'webscience-dev-key-change-in-production')

# CORS
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://webscience.io", "https://www.webscience.io",
                    "https://dnsscience.io", "http://localhost:*"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-API-Key"]
    }
})

# Session configuration
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 30

# =============================================================================
# Tool Configuration
# =============================================================================

TOOLS = {
    'http': {
        'name': 'HTTP Observatory',
        'icon': 'fa-globe',
        'color': 'blue',
        'description': 'Analyze HTTP headers, redirects, response times'
    },
    'security': {
        'name': 'Security Scanner',
        'icon': 'fa-shield-halved',
        'color': 'red',
        'description': 'SSL/TLS grading, security headers, vulnerability checks'
    },
    'performance': {
        'name': 'Performance Lab',
        'icon': 'fa-gauge-high',
        'color': 'green',
        'description': 'Page speed, timing metrics, resource analysis'
    },
    'seo': {
        'name': 'SEO Inspector',
        'icon': 'fa-magnifying-glass-chart',
        'color': 'purple',
        'description': 'Meta tags, Open Graph, structured data, robots'
    },
    'screenshot': {
        'name': 'Visual Capture',
        'icon': 'fa-camera',
        'color': 'pink',
        'description': 'Screenshots, visual diffs, page archiving'
    },
    'monitor': {
        'name': 'Uptime Monitor',
        'icon': 'fa-heart-pulse',
        'color': 'yellow',
        'description': 'Availability monitoring, alerts, status history'
    }
}

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Permissions-Policy',
    'Cross-Origin-Opener-Policy',
    'Cross-Origin-Resource-Policy',
    'Cross-Origin-Embedder-Policy'
]

# =============================================================================
# Utility Functions
# =============================================================================

def normalize_url(url):
    """Ensure URL has a scheme"""
    if not url:
        return None
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def get_ssl_info(hostname, port=443):
    """Get SSL certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Parse certificate dates
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.now()).days

                # Get subject and issuer
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))

                # Get SANs
                sans = []
                for type_val, val in cert.get('subjectAltName', []):
                    if type_val == 'DNS':
                        sans.append(val)

                return {
                    'valid': True,
                    'subject': subject.get('commonName', ''),
                    'issuer': issuer.get('organizationName', issuer.get('commonName', '')),
                    'not_before': not_before.isoformat(),
                    'not_after': not_after.isoformat(),
                    'days_left': days_left,
                    'sans': sans,
                    'cipher': cipher[0] if cipher else None,
                    'protocol': version,
                    'key_size': cipher[2] if cipher else None
                }
    except ssl.SSLCertVerificationError as e:
        return {'valid': False, 'error': str(e), 'error_type': 'verification'}
    except ssl.SSLError as e:
        return {'valid': False, 'error': str(e), 'error_type': 'ssl'}
    except socket.timeout:
        return {'valid': False, 'error': 'Connection timeout', 'error_type': 'timeout'}
    except Exception as e:
        return {'valid': False, 'error': str(e), 'error_type': 'connection'}

def analyze_security_headers(headers):
    """Analyze security headers and return scores"""
    results = {}
    score = 0
    max_score = len(SECURITY_HEADERS) * 10

    for header in SECURITY_HEADERS:
        value = headers.get(header)
        if value:
            results[header] = {
                'present': True,
                'value': value,
                'score': 10
            }
            score += 10

            # Additional checks for specific headers
            if header == 'Strict-Transport-Security':
                if 'max-age=31536000' in value or int(re.search(r'max-age=(\d+)', value).group(1) if re.search(r'max-age=(\d+)', value) else 0) >= 31536000:
                    results[header]['grade'] = 'A'
                elif 'max-age' in value:
                    results[header]['grade'] = 'B'
                else:
                    results[header]['grade'] = 'C'

            elif header == 'Content-Security-Policy':
                if 'default-src' in value:
                    results[header]['grade'] = 'A' if "'unsafe-inline'" not in value else 'B'
                else:
                    results[header]['grade'] = 'C'
        else:
            results[header] = {
                'present': False,
                'value': None,
                'score': 0,
                'grade': 'F'
            }

    return {
        'headers': results,
        'score': score,
        'max_score': max_score,
        'percentage': round((score / max_score) * 100, 1),
        'grade': 'A' if score >= 80 else 'B' if score >= 60 else 'C' if score >= 40 else 'D' if score >= 20 else 'F'
    }

def extract_meta_tags(html):
    """Extract meta tags from HTML using BeautifulSoup"""
    meta = {
        'title': None, 'description': None, 'keywords': None,
        'author': None, 'viewport': None, 'robots': None,
        'canonical': None, 'og': {}, 'twitter': {}, 'structured_data': []
    }
    try:
        soup = BeautifulSoup(html, 'lxml')
    except Exception:
        soup = BeautifulSoup(html, 'html.parser')

    title_tag = soup.find('title')
    if title_tag:
        meta['title'] = title_tag.get_text(strip=True)

    for tag in soup.find_all('meta'):
        name = (tag.get('name') or '').lower()
        prop = (tag.get('property') or '').lower()
        content = tag.get('content', '')

        if name == 'description':    meta['description'] = content
        elif name == 'keywords':     meta['keywords'] = content
        elif name == 'author':       meta['author'] = content
        elif name == 'viewport':     meta['viewport'] = content
        elif name == 'robots':       meta['robots'] = content
        elif name.startswith('twitter:'): meta['twitter'][name[8:]] = content

        if prop.startswith('og:'):   meta['og'][prop[3:]] = content

    canonical = soup.find('link', rel='canonical')
    if canonical:
        meta['canonical'] = canonical.get('href')

    for script in soup.find_all('script', type='application/ld+json'):
        try:
            meta['structured_data'].append(json.loads(script.string or ''))
        except Exception:
            pass

    return meta


def detect_technologies(headers, html):
    """Fingerprint server, CDN, CMS, frameworks, and analytics from headers + HTML"""
    h = {k.lower(): v for k, v in headers.items()}
    result = {
        'server': h.get('server', '') or None,
        'powered_by': h.get('x-powered-by', '') or None,
        'cdn': None,
        'hosting': None,
        'cms': [],
        'frameworks': [],
        'js_libraries': [],
        'analytics': [],
        'interesting_headers': {},
    }

    # CDN / hosting from headers
    cdn_header_map = [
        ('cf-ray',                'Cloudflare'),
        ('x-vercel-id',           'Vercel'),
        ('x-nf-request-id',       'Netlify'),
        ('x-amz-cf-id',           'AWS CloudFront'),
        ('x-akamai-request-id',   'Akamai'),
        ('x-fastly-request-id',   'Fastly'),
        ('surrogate-key',         'Fastly'),
        ('x-azure-ref',           'Azure CDN'),
        ('x-github-request-id',   'GitHub Pages'),
        ('fly-request-id',        'Fly.io'),
        ('x-render-origin-server','Render'),
        ('x-railway-request-id',  'Railway'),
    ]
    for header, name in cdn_header_map:
        if header in h:
            result['cdn'] = name
            break

    # Server header fallback for CDN
    if not result['cdn'] and result['server']:
        srv = result['server'].lower()
        if 'cloudflare' in srv:  result['cdn'] = 'Cloudflare'
        elif 'netlify'  in srv:  result['cdn'] = 'Netlify'
        elif 'vercel'   in srv:  result['cdn'] = 'Vercel'

    hosting_map = [
        ('x-vercel-id',            'Vercel'),
        ('x-nf-request-id',        'Netlify'),
        ('x-github-request-id',    'GitHub Pages'),
        ('x-heroku-queue-wait-time','Heroku'),
        ('x-amzn-requestid',       'AWS'),
        ('x-cloud-trace-context',  'Google Cloud'),
        ('fly-request-id',         'Fly.io'),
        ('x-render-origin-server', 'Render'),
        ('x-railway-request-id',   'Railway'),
    ]
    for header, name in hosting_map:
        if header in h:
            result['hosting'] = name
            break

    # Interesting headers worth surfacing
    interesting = [
        'x-powered-by', 'x-generator', 'x-drupal-cache', 'x-wordpress-cache',
        'x-shopify-stage', 'x-wix-request-id', 'x-aspnet-version',
        'x-aspnetmvc-version', 'x-runtime', 'x-request-id',
    ]
    for ih in interesting:
        if ih in h and h[ih]:
            result['interesting_headers'][ih] = h[ih]

    if not html:
        return result

    # ── HTML fingerprinting ────────────────────────────────────────────────
    # CMS
    cms_signatures = [
        ('/wp-content/',         'WordPress'),
        ('/wp-includes/',        'WordPress'),
        ('data-wpfc-',           'WordPress'),
        ('/sites/default/files/','Drupal'),
        ('data-drupal-',         'Drupal'),
        ('/components/com_',     'Joomla'),
        ('cdn.shopify.com',      'Shopify'),
        ('Shopify.theme',        'Shopify'),
        ('static.squarespace.com','Squarespace'),
        ('wixstatic.com',        'Wix'),
        ('/ghost/api/',          'Ghost'),
        ('ghost.io',             'Ghost'),
        ('webflow.com',          'Webflow'),
        ('cdn.builder.io',       'Builder.io'),
    ]
    seen_cms = set()
    for sig, name in cms_signatures:
        if sig in html and name not in seen_cms:
            result['cms'].append(name)
            seen_cms.add(name)

    # Frameworks
    fw_signatures = [
        ('__NEXT_DATA__',       'Next.js'),
        ('/_next/',             'Next.js'),
        ('__nuxt',              'Nuxt.js'),
        ('/_nuxt/',             'Nuxt.js'),
        ('___gatsby',           'Gatsby'),
        ('/gatsby-',            'Gatsby'),
        ('csrfmiddlewaretoken', 'Django'),
        ('data-turbolinks',     'Rails/Turbolinks'),
        ('data-turbo-',         'Rails/Turbo'),
        ('sveltekit',           'SvelteKit'),
        ('__sveltekit',         'SvelteKit'),
        ('astro-island',        'Astro'),
        ('x-astro-',            'Astro'),
        ('remix-manifest',      'Remix'),
        ('__remix_manifest',    'Remix'),
        ('laravel_session',     'Laravel'),
        ('_inertia',            'Inertia.js'),
        ('livewire',            'Laravel Livewire'),
    ]
    seen_fw = set()
    for sig, name in fw_signatures:
        if sig in html and name not in seen_fw:
            result['frameworks'].append(name)
            seen_fw.add(name)

    # JS libraries
    js_signatures = [
        ('__reactFiber',        'React'),
        ('data-reactroot',      'React'),
        ('React.createElement', 'React'),
        ('__vue__',             'Vue.js'),
        ('data-v-',             'Vue.js'),
        ('Vue.config',          'Vue.js'),
        ('ng-version',          'Angular'),
        ('ng-app=',             'AngularJS'),
        ('__svelte',            'Svelte'),
        ('jQuery',              'jQuery'),
        ('jquery.min.js',       'jQuery'),
        ('hx-get=',             'HTMX'),
        ('hx-post=',            'HTMX'),
        ('x-data=',             'Alpine.js'),
        ('alpine.min.js',       'Alpine.js'),
        ('stimulus',            'Stimulus'),
        ('turbo.es',            'Hotwire/Turbo'),
    ]
    seen_js = set()
    for sig, name in js_signatures:
        if sig in html and name not in seen_js:
            result['js_libraries'].append(name)
            seen_js.add(name)

    # Analytics
    analytics_signatures = [
        ('google-analytics.com', 'Google Analytics'),
        ('gtag(',                'Google Analytics'),
        ('googletagmanager.com', 'Google Tag Manager'),
        ('GTM-',                 'Google Tag Manager'),
        ('plausible.io',         'Plausible'),
        ('usefathom.com',        'Fathom'),
        ('hotjar.com',           'Hotjar'),
        ('mixpanel.com',         'Mixpanel'),
        ('segment.com',          'Segment'),
        ('posthog.com',          'PostHog'),
        ('clarity.ms',           'Microsoft Clarity'),
        ('heap.io',              'Heap'),
        ('fullstory.com',        'FullStory'),
        ('amplitude.com',        'Amplitude'),
        ('intercom.io',          'Intercom'),
        ('crisp.chat',           'Crisp'),
        ('drift.com',            'Drift'),
        ('hubspot.com',          'HubSpot'),
    ]
    seen_an = set()
    for sig, name in analytics_signatures:
        if sig in html and name not in seen_an:
            result['analytics'].append(name)
            seen_an.add(name)

    # Check x-generator meta tag
    gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if gen_match:
        result['interesting_headers']['x-generator (meta)'] = gen_match.group(1)

    return result


def parse_cookies(response):
    """Parse Set-Cookie headers and grade security attributes"""
    cookies = []
    raw_cookie_headers = []

    # urllib3 HTTPHeaderDict supports getlist for duplicate headers
    try:
        raw_cookie_headers = response.raw.headers.getlist('Set-Cookie')
    except Exception:
        raw = response.headers.get('Set-Cookie', '')
        if raw:
            raw_cookie_headers = [raw]

    for cookie_str in raw_cookie_headers:
        parts = [p.strip() for p in cookie_str.split(';')]
        if not parts or not parts[0]:
            continue

        name_value = parts[0].split('=', 1)
        name = name_value[0].strip()
        if not name:
            continue
        value = name_value[1] if len(name_value) > 1 else ''

        attrs = {}
        for part in parts[1:]:
            if '=' in part:
                k, v = part.split('=', 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[part.strip().lower()] = True

        secure   = 'secure'   in attrs
        httponly = 'httponly' in attrs
        samesite = attrs.get('samesite')
        max_age  = attrs.get('max-age')
        expires  = attrs.get('expires')
        domain   = attrs.get('domain', '')
        path     = attrs.get('path', '/')

        score = 0
        issues = []
        if secure:   score += 35
        else:        issues.append('Missing Secure flag — cookie transmitted over HTTP')
        if httponly: score += 35
        else:        issues.append('Missing HttpOnly flag — accessible via JavaScript (XSS risk)')
        if samesite:
            ss_lower = samesite.lower()
            if ss_lower == 'strict':   score += 30
            elif ss_lower == 'lax':    score += 20
            else:                      score += 5; issues.append('SameSite=None requires Secure flag')
        else:
            issues.append('Missing SameSite attribute — vulnerable to CSRF')

        grade = 'A' if score >= 90 else 'B' if score >= 65 else 'C' if score >= 40 else 'F'

        cookies.append({
            'name':     name,
            'value':    value[:24] + '…' if len(value) > 24 else value,
            'secure':   secure,
            'httponly': httponly,
            'samesite': samesite,
            'expires':  expires,
            'max_age':  max_age,
            'domain':   domain,
            'path':     path,
            'score':    score,
            'grade':    grade,
            'issues':   issues,
        })

    return cookies


def resolve_host(hostname):
    """Resolve hostname to IPs and reverse DNS"""
    result = {'ips': [], 'reverse_dns': []}
    try:
        answers = dns.resolver.resolve(hostname, 'A', lifetime=5)
        result['ips'] = [str(r) for r in answers]
        for ip in result['ips'][:4]:
            try:
                rev = dns.resolver.resolve(dns.reversename.from_address(ip), 'PTR', lifetime=3)
                result['reverse_dns'].append({'ip': ip, 'hostname': str(rev[0]).rstrip('.')})
            except Exception:
                result['reverse_dns'].append({'ip': ip, 'hostname': None})
    except Exception as e:
        result['error'] = str(e)
    return result


def get_dns_intel(hostname):
    """Full DNS intel: A, AAAA, MX, NS, CNAME records"""
    result = {'a_records': [], 'aaaa_records': [], 'mx_records': [], 'ns_records': [], 'cname': None}
    for rtype, key in [('A','a_records'), ('AAAA','aaaa_records'), ('NS','ns_records')]:
        try:
            ans = dns.resolver.resolve(hostname, rtype, lifetime=5)
            result[key] = [str(r).rstrip('.') for r in ans]
        except Exception:
            pass
    try:
        mx = dns.resolver.resolve(hostname, 'MX', lifetime=5)
        result['mx_records'] = [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in sorted(mx, key=lambda x: x.preference)]
    except Exception:
        pass
    try:
        cname = dns.resolver.resolve(hostname, 'CNAME', lifetime=5)
        result['cname'] = str(cname[0].target).rstrip('.')
    except Exception:
        pass
    return result


def get_whois_info(domain):
    """WHOIS lookup with normalized output"""
    try:
        w = whois_lib.whois(domain)

        def first(val):
            if isinstance(val, list):
                return str(val[0]) if val else None
            return str(val) if val else None

        return {
            'registrar':       first(w.registrar),
            'organization':    first(w.org),
            'country':         first(w.country),
            'creation_date':   first(w.creation_date),
            'expiration_date': first(w.expiration_date),
            'updated_date':    first(w.updated_date),
            'name_servers':    [str(ns).lower() for ns in (w.name_servers or [])],
            'status':          [str(s) for s in (w.status if isinstance(w.status, list) else [w.status] if w.status else [])],
        }
    except Exception as e:
        return {'error': str(e)}

def calculate_seo_score(meta, html):
    """Calculate SEO score based on meta tags and content"""
    score = 0
    issues = []
    warnings = []

    # Title (20 points)
    if meta['title']:
        title_len = len(meta['title'])
        if 30 <= title_len <= 60:
            score += 20
        elif title_len > 0:
            score += 10
            if title_len < 30:
                warnings.append(f'Title too short ({title_len} chars, aim for 30-60)')
            else:
                warnings.append(f'Title too long ({title_len} chars, aim for 30-60)')
    else:
        issues.append('Missing title tag')

    # Description (20 points)
    if meta['description']:
        desc_len = len(meta['description'])
        if 120 <= desc_len <= 160:
            score += 20
        elif desc_len > 0:
            score += 10
            if desc_len < 120:
                warnings.append(f'Description too short ({desc_len} chars, aim for 120-160)')
            else:
                warnings.append(f'Description too long ({desc_len} chars, aim for 120-160)')
    else:
        issues.append('Missing meta description')

    # Open Graph (15 points)
    og_required = ['title', 'description', 'image', 'url']
    og_score = sum(5 if meta['og'].get(k) else 0 for k in og_required[:3])
    score += min(og_score, 15)
    if not meta['og'].get('title'):
        warnings.append('Missing og:title')
    if not meta['og'].get('image'):
        warnings.append('Missing og:image')

    # Twitter Cards (10 points)
    if meta['twitter'].get('card'):
        score += 10
    else:
        warnings.append('Missing Twitter card meta tags')

    # Canonical (10 points)
    if meta['canonical']:
        score += 10
    else:
        warnings.append('Missing canonical URL')

    # Viewport (10 points)
    if meta['viewport']:
        score += 10
    else:
        issues.append('Missing viewport meta tag (mobile-friendliness)')

    # Structured Data (15 points)
    if meta['structured_data']:
        score += 15
    else:
        warnings.append('No structured data (JSON-LD) found')

    return {
        'score': score,
        'max_score': 100,
        'percentage': score,
        'grade': 'A' if score >= 80 else 'B' if score >= 60 else 'C' if score >= 40 else 'D' if score >= 20 else 'F',
        'issues': issues,
        'warnings': warnings
    }

# =============================================================================
# Routes - Pages
# =============================================================================

@app.route('/')
@optional_auth
def index():
    url = request.args.get('url', '')
    return render_template('analyze.html', url=url, tools=TOOLS)

@app.route('/analyze')
@optional_auth
def analyze():
    url = request.args.get('url', '')
    return render_template('analyze.html', url=url, tools=TOOLS)

# Individual tool routes redirect to main workspace with tab pre-selected
@app.route('/http')
def http_tool():
    return redirect(f'/?tab=http&url={request.args.get("url","")}')

@app.route('/security')
def security_tool():
    return redirect(f'/?tab=security&url={request.args.get("url","")}')

@app.route('/performance')
def performance_tool():
    return redirect(f'/?tab=performance&url={request.args.get("url","")}')

@app.route('/seo')
def seo_tool():
    return redirect(f'/?tab=seo&url={request.args.get("url","")}')

@app.route('/screenshot')
def screenshot_tool():
    return redirect('/?tab=intel')

@app.route('/monitor')
@login_required
def monitor_tool():
    return render_template('tools/monitor.html', tool=TOOLS['monitor'])

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', tools=TOOLS)

# =============================================================================
# API Routes - HTTP Observatory
# =============================================================================

@app.route('/api/http/analyze', methods=['POST'])
@optional_auth
def api_http_analyze():
    """Analyze HTTP response, headers, and redirects"""
    data = request.get_json() or {}
    url = normalize_url(data.get('url'))

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        parsed = urlparse(url)
        results = {
            'url': url,
            'hostname': parsed.netloc,
            'timestamp': datetime.utcnow().isoformat(),
            'redirects': [],
            'final_url': None,
            'response': None,
            'headers': None,
            'timing': None
        }

        # Follow redirects manually to capture chain
        current_url = url
        redirect_count = 0
        max_redirects = 10

        session_req = requests.Session()

        while redirect_count < max_redirects:
            start_time = time.time()
            response = session_req.get(
                current_url,
                allow_redirects=False,
                timeout=30,
                headers={'User-Agent': 'WebScience.io Bot/1.0'}
            )
            elapsed = time.time() - start_time

            redirect_info = {
                'url': current_url,
                'status_code': response.status_code,
                'status_text': response.reason,
                'time_ms': round(elapsed * 1000, 2),
                'headers': dict(response.headers)
            }
            results['redirects'].append(redirect_info)

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location')
                if location:
                    current_url = urljoin(current_url, location)
                    redirect_count += 1
                else:
                    break
            else:
                break

        # Final response info
        results['final_url'] = current_url
        final = results['redirects'][-1] if results['redirects'] else None

        if final:
            results['response'] = {
                'status_code': final['status_code'],
                'status_text': final['status_text'],
                'content_type': final['headers'].get('Content-Type', ''),
                'content_length': final['headers'].get('Content-Length', 'Unknown'),
                'server': final['headers'].get('Server', 'Unknown')
            }
            results['headers'] = final['headers']
            results['timing'] = {
                'total_ms': sum(r['time_ms'] for r in results['redirects']),
                'redirect_count': len(results['redirects']) - 1
            }

        # Host resolution
        results['host_info'] = resolve_host(parsed.netloc)

        return jsonify(results)

    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timeout', 'url': url}), 504
    except requests.exceptions.SSLError as e:
        return jsonify({'error': f'SSL Error: {str(e)}', 'url': url}), 502
    except requests.exceptions.ConnectionError as e:
        return jsonify({'error': f'Connection failed: {str(e)}', 'url': url}), 502
    except Exception as e:
        logger.exception(f"HTTP analyze error for {url}")
        return jsonify({'error': str(e), 'url': url}), 500

# =============================================================================
# API Routes - Security Scanner
# =============================================================================

@app.route('/api/security/analyze', methods=['POST'])
@optional_auth
def api_security_analyze():
    """Comprehensive security analysis"""
    data = request.get_json() or {}
    url = normalize_url(data.get('url'))

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        parsed = urlparse(url)
        hostname = parsed.netloc

        results = {
            'url': url,
            'hostname': hostname,
            'timestamp': datetime.utcnow().isoformat(),
            'ssl': None,
            'headers': None,
            'overall_grade': None
        }

        # SSL/TLS Analysis
        if parsed.scheme == 'https':
            results['ssl'] = get_ssl_info(hostname)
        else:
            results['ssl'] = {
                'valid': False,
                'error': 'Site not using HTTPS',
                'error_type': 'no_https'
            }

        # Fetch page and analyze headers
        try:
            response = requests.get(
                url,
                timeout=30,
                headers={'User-Agent': 'WebScience.io Security Scanner/1.0'},
                verify=True
            )
            results['headers'] = analyze_security_headers(response.headers)
        except:
            results['headers'] = {
                'error': 'Could not fetch page for header analysis',
                'score': 0,
                'max_score': 100,
                'percentage': 0,
                'grade': 'F'
            }

        # Calculate overall grade
        ssl_score = 50 if results['ssl'].get('valid') else 0
        if results['ssl'].get('valid') and results['ssl'].get('days_left', 0) > 30:
            ssl_score = 50
        elif results['ssl'].get('valid'):
            ssl_score = 30

        header_score = results['headers'].get('percentage', 0) / 2  # 50 points max
        total_score = ssl_score + header_score

        results['overall_grade'] = {
            'score': round(total_score, 1),
            'max_score': 100,
            'grade': 'A+' if total_score >= 95 else 'A' if total_score >= 85 else 'B' if total_score >= 70 else 'C' if total_score >= 50 else 'D' if total_score >= 30 else 'F'
        }

        return jsonify(results)

    except Exception as e:
        logger.exception(f"Security analyze error for {url}")
        return jsonify({'error': str(e), 'url': url}), 500

# =============================================================================
# API Routes - Performance Analysis
# =============================================================================

@app.route('/api/performance/analyze', methods=['POST'])
@optional_auth
def api_performance_analyze():
    """Performance and timing analysis"""
    data = request.get_json() or {}
    url = normalize_url(data.get('url'))

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        results = {
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'timing': {},
            'size': {},
            'resources': [],
            'recommendations': []
        }

        # Measure connection and response timing
        start = time.time()

        # DNS lookup time (approximate)
        parsed = urlparse(url)
        dns_start = time.time()
        socket.gethostbyname(parsed.netloc)
        dns_time = (time.time() - dns_start) * 1000

        # Full request
        response = requests.get(
            url,
            timeout=60,
            headers={'User-Agent': 'WebScience.io Performance Analyzer/1.0'},
            stream=True
        )

        # Time to first byte
        ttfb = (time.time() - start) * 1000

        # Download content
        content = response.content
        total_time = (time.time() - start) * 1000

        results['timing'] = {
            'dns_ms': round(dns_time, 2),
            'ttfb_ms': round(ttfb, 2),
            'download_ms': round(total_time - ttfb, 2),
            'total_ms': round(total_time, 2)
        }

        # Size analysis
        content_length = len(content)
        results['size'] = {
            'total_bytes': content_length,
            'total_kb': round(content_length / 1024, 2),
            'compressed': 'gzip' in response.headers.get('Content-Encoding', '') or 'br' in response.headers.get('Content-Encoding', ''),
            'content_type': response.headers.get('Content-Type', 'unknown')
        }

        # Parse HTML for resources using BS4
        html = content.decode('utf-8', errors='ignore')
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')

        scripts     = len(soup.find_all('script', src=True))
        stylesheets = len(soup.find_all('link', rel=lambda r: r and 'stylesheet' in r))
        images      = len(soup.find_all('img', src=True))

        results['resources'] = {
            'scripts': scripts,
            'stylesheets': stylesheets,
            'images': images,
            'total': scripts + stylesheets + images
        }

        # Generate recommendations
        if results['timing']['ttfb_ms'] > 600:
            results['recommendations'].append({
                'type': 'warning',
                'category': 'Server',
                'message': f"Time to First Byte is slow ({round(results['timing']['ttfb_ms'])}ms). Consider server-side caching or CDN."
            })

        if not results['size']['compressed']:
            results['recommendations'].append({
                'type': 'error',
                'category': 'Compression',
                'message': 'Response is not compressed. Enable gzip or brotli compression.'
            })

        if results['size']['total_kb'] > 500:
            results['recommendations'].append({
                'type': 'warning',
                'category': 'Size',
                'message': f"Page size is large ({results['size']['total_kb']}KB). Consider optimizing resources."
            })

        if scripts > 10:
            results['recommendations'].append({
                'type': 'info',
                'category': 'Scripts',
                'message': f"{scripts} external scripts detected. Consider bundling or lazy loading."
            })

        # Calculate score
        score = 100
        if results['timing']['ttfb_ms'] > 600:
            score -= 20
        if results['timing']['ttfb_ms'] > 1000:
            score -= 20
        if not results['size']['compressed']:
            score -= 15
        if results['size']['total_kb'] > 500:
            score -= 15
        if scripts > 15:
            score -= 10

        results['score'] = {
            'value': max(0, score),
            'grade': 'A' if score >= 90 else 'B' if score >= 75 else 'C' if score >= 60 else 'D' if score >= 40 else 'F'
        }

        return jsonify(results)

    except Exception as e:
        logger.exception(f"Performance analyze error for {url}")
        return jsonify({'error': str(e), 'url': url}), 500

# =============================================================================
# API Routes - SEO Analysis
# =============================================================================

@app.route('/api/seo/analyze', methods=['POST'])
@optional_auth
def api_seo_analyze():
    """SEO and meta tag analysis"""
    data = request.get_json() or {}
    url = normalize_url(data.get('url'))

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        response = requests.get(
            url,
            timeout=30,
            headers={'User-Agent': 'WebScience.io SEO Analyzer/1.0'}
        )

        html = response.text
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')

        meta = extract_meta_tags(html)
        seo_score = calculate_seo_score(meta, html)

        # H1 count via BS4
        h1_tags = soup.find_all('h1')
        h1_count = len(h1_tags)
        if h1_count == 0:
            seo_score['issues'].append('No H1 tag found')
        elif h1_count > 1:
            seo_score['warnings'].append(f'Multiple H1 tags ({h1_count}) — use only one per page')

        # Image alt audit via BS4
        images = soup.find_all('img')
        images_without_alt = sum(1 for img in images if not img.get('alt'))
        if images_without_alt > 0:
            seo_score['warnings'].append(f'{images_without_alt} image{"s" if images_without_alt>1 else ""} missing alt attribute')

        results = {
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'meta': meta,
            'score': seo_score,
            'content': {
                'h1_count': h1_count,
                'total_images': len(images),
                'images_without_alt': images_without_alt
            }
        }

        return jsonify(results)

    except Exception as e:
        logger.exception(f"SEO analyze error for {url}")
        return jsonify({'error': str(e), 'url': url}), 500

# =============================================================================
# API Routes - Full Analysis (All Tools)
# =============================================================================

@app.route('/api/analyze', methods=['POST'])
@optional_auth
def api_full_analyze():
    """Run all analysis tools on a URL"""
    data = request.get_json() or {}
    url = normalize_url(data.get('url'))
    tools = data.get('tools', ['http', 'security', 'performance', 'seo'])

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    results = {
        'url': url,
        'timestamp': datetime.utcnow().isoformat(),
        'results': {}
    }

    # Run requested analyses
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}

        if 'http' in tools:
            futures['http'] = executor.submit(
                lambda: requests.post(
                    request.host_url + 'api/http/analyze',
                    json={'url': url}
                ).json()
            )

        if 'security' in tools:
            futures['security'] = executor.submit(
                lambda: requests.post(
                    request.host_url + 'api/security/analyze',
                    json={'url': url}
                ).json()
            )

        if 'performance' in tools:
            futures['performance'] = executor.submit(
                lambda: requests.post(
                    request.host_url + 'api/performance/analyze',
                    json={'url': url}
                ).json()
            )

        if 'seo' in tools:
            futures['seo'] = executor.submit(
                lambda: requests.post(
                    request.host_url + 'api/seo/analyze',
                    json={'url': url}
                ).json()
            )

        for tool, future in futures.items():
            try:
                results['results'][tool] = future.result(timeout=60)
            except Exception as e:
                results['results'][tool] = {'error': str(e)}

    return jsonify(results)

# =============================================================================
# API Routes - Technology Fingerprinting
# =============================================================================

@app.route('/api/tech/analyze', methods=['POST'])
@optional_auth
def api_tech_analyze():
    """Detect server, CDN, CMS, frameworks, analytics, and JS libraries"""
    data = request.get_json() or {}
    url = normalize_url(data.get('url'))
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    try:
        response = requests.get(
            url, timeout=30,
            headers={'User-Agent': 'WebScience.io Tech Analyzer/1.0'}
        )
        result = detect_technologies(response.headers, response.text)
        result['url'] = url
        result['timestamp'] = datetime.utcnow().isoformat()
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Tech analyze error for {url}")
        return jsonify({'error': str(e), 'url': url}), 500


# =============================================================================
# API Routes - Cookie Inspector
# =============================================================================

@app.route('/api/cookies/analyze', methods=['POST'])
@optional_auth
def api_cookies_analyze():
    """Inspect cookies for security attributes and grade each one"""
    data = request.get_json() or {}
    url = normalize_url(data.get('url'))
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    try:
        response = requests.get(
            url, timeout=30,
            headers={'User-Agent': 'WebScience.io Cookie Inspector/1.0'},
            allow_redirects=True
        )
        cookies = parse_cookies(response)
        return jsonify({
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'cookies': cookies,
            'count': len(cookies),
        })
    except Exception as e:
        logger.exception(f"Cookie analyze error for {url}")
        return jsonify({'error': str(e), 'url': url}), 500


# =============================================================================
# API Routes - Domain Intel (WHOIS + DNS + robots + sitemap + links)
# =============================================================================

@app.route('/api/intel/analyze', methods=['POST'])
@optional_auth
def api_intel_analyze():
    """Domain intelligence: WHOIS, DNS records, robots.txt, sitemap, link analysis"""
    data = request.get_json() or {}
    url = normalize_url(data.get('url'))
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    parsed = urlparse(url)
    hostname = parsed.netloc
    # Strip port if present
    hostname = hostname.split(':')[0]
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    result = {
        'url': url,
        'hostname': hostname,
        'timestamp': datetime.utcnow().isoformat(),
        'whois': None,
        'dns': None,
        'robots': None,
        'sitemap': None,
        'links': None,
    }

    # Run WHOIS + DNS in parallel with page fetch
    with ThreadPoolExecutor(max_workers=4) as ex:
        # Extract registrable domain for WHOIS (strip subdomains)
        parts = hostname.split('.')
        domain = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

        f_whois  = ex.submit(get_whois_info, domain)
        f_dns    = ex.submit(get_dns_intel, hostname)
        f_page   = ex.submit(requests.get, url, timeout=30,
                             headers={'User-Agent': 'WebScience.io Intel/1.0'})
        f_robots = ex.submit(requests.get, f"{base_url}/robots.txt", timeout=10,
                             headers={'User-Agent': 'WebScience.io Intel/1.0'})

        result['whois'] = f_whois.result()
        result['dns']   = f_dns.result()

        # robots.txt
        try:
            robots_resp = f_robots.result()
            result['robots'] = {
                'found':   robots_resp.status_code == 200,
                'content': robots_resp.text if robots_resp.status_code == 200 else None,
            }
        except Exception:
            result['robots'] = {'found': False, 'content': None}

        # Page HTML for link analysis
        try:
            page_resp = f_page.result()
            soup = BeautifulSoup(page_resp.text, 'lxml')
            links = soup.find_all('a', href=True)
            internal, external = 0, 0
            ext_domains = {}
            for a in links:
                href = a['href'].strip()
                if not href or href.startswith('#') or href.startswith('mailto:') or href.startswith('tel:'):
                    continue
                abs_href = urljoin(url, href)
                link_parsed = urlparse(abs_href)
                if link_parsed.netloc == parsed.netloc or not link_parsed.netloc:
                    internal += 1
                else:
                    external += 1
                    ext_domains[link_parsed.netloc] = ext_domains.get(link_parsed.netloc, 0) + 1

            top_ext = sorted(ext_domains.items(), key=lambda x: -x[1])
            result['links'] = {
                'internal': internal,
                'external': external,
                'total':    internal + external,
                'external_domains': [d for d, _ in top_ext[:20]],
            }
        except Exception:
            result['links'] = None

    # Sitemap (try common paths)
    sitemap_found = False
    for path in ['/sitemap.xml', '/sitemap_index.xml', '/sitemap/sitemap.xml']:
        try:
            sr = requests.get(f"{base_url}{path}", timeout=10,
                              headers={'User-Agent': 'WebScience.io Intel/1.0'})
            if sr.status_code == 200 and '<url' in sr.text.lower():
                url_count = sr.text.lower().count('<url>')
                result['sitemap'] = {
                    'found': True,
                    'url': f"{base_url}{path}",
                    'url_count': url_count if url_count > 0 else None,
                }
                sitemap_found = True
                break
        except Exception:
            pass
    if not sitemap_found:
        result['sitemap'] = {'found': False, 'url': None, 'url_count': None}

    return jsonify(result)


# =============================================================================
# API Routes - Screenshot (Placeholder)
# =============================================================================

@app.route('/api/screenshot/capture', methods=['POST'])
@optional_auth
def api_screenshot():
    """Capture screenshot of a URL (requires Playwright/Selenium backend)"""
    data = request.get_json() or {}
    url = normalize_url(data.get('url'))

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # This would integrate with Playwright or similar
    return jsonify({
        'message': 'Screenshot service requires Playwright backend',
        'url': url,
        'status': 'pending_implementation'
    })

# =============================================================================
# API Routes - Uptime Monitor
# =============================================================================

@app.route('/api/monitor/check', methods=['POST'])
@optional_auth
def api_monitor_check():
    """Single uptime check"""
    data = request.get_json() or {}
    url = normalize_url(data.get('url'))

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    try:
        start = time.time()
        response = requests.get(
            url,
            timeout=30,
            headers={'User-Agent': 'WebScience.io Uptime Monitor/1.0'}
        )
        elapsed = (time.time() - start) * 1000

        return jsonify({
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'up' if response.status_code < 400 else 'down',
            'status_code': response.status_code,
            'response_time_ms': round(elapsed, 2),
            'headers': {
                'server': response.headers.get('Server'),
                'content_type': response.headers.get('Content-Type')
            }
        })

    except requests.exceptions.Timeout:
        return jsonify({
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'timeout',
            'error': 'Request timeout'
        })
    except Exception as e:
        return jsonify({
            'url': url,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'error',
            'error': str(e)
        })

# =============================================================================
# Run
# =============================================================================

if __name__ == '__main__':
    app.run(debug=True, port=5003)
