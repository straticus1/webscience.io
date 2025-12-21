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

# Shared authentication with DNSScience ecosystem
import sys
sys.path.insert(0, '/Users/ryan/development/afterdarksys.com/subdomains/dnsscience')
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
    """Extract meta tags from HTML"""
    meta = {
        'title': None,
        'description': None,
        'keywords': None,
        'author': None,
        'viewport': None,
        'robots': None,
        'canonical': None,
        'og': {},
        'twitter': {},
        'structured_data': []
    }

    # Title
    title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
    if title_match:
        meta['title'] = title_match.group(1).strip()

    # Meta tags
    meta_pattern = r'<meta\s+([^>]+)>'
    for match in re.finditer(meta_pattern, html, re.IGNORECASE):
        attrs = match.group(1)

        name_match = re.search(r'name=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        property_match = re.search(r'property=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        content_match = re.search(r'content=["\']([^"\']*)["\']', attrs, re.IGNORECASE)

        content = content_match.group(1) if content_match else None

        if name_match:
            name = name_match.group(1).lower()
            if name == 'description':
                meta['description'] = content
            elif name == 'keywords':
                meta['keywords'] = content
            elif name == 'author':
                meta['author'] = content
            elif name == 'viewport':
                meta['viewport'] = content
            elif name == 'robots':
                meta['robots'] = content
            elif name.startswith('twitter:'):
                meta['twitter'][name.replace('twitter:', '')] = content

        if property_match:
            prop = property_match.group(1).lower()
            if prop.startswith('og:'):
                meta['og'][prop.replace('og:', '')] = content

    # Canonical
    canonical_match = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if not canonical_match:
        canonical_match = re.search(r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']canonical["\']', html, re.IGNORECASE)
    if canonical_match:
        meta['canonical'] = canonical_match.group(1)

    # Structured data (JSON-LD)
    ld_pattern = r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>([^<]+)</script>'
    for match in re.finditer(ld_pattern, html, re.IGNORECASE):
        try:
            data = json.loads(match.group(1))
            meta['structured_data'].append(data)
        except:
            pass

    return meta

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
    return render_template('index.html', tools=TOOLS)

@app.route('/analyze')
@optional_auth
def analyze():
    url = request.args.get('url', '')
    return render_template('analyze.html', url=url, tools=TOOLS)

@app.route('/http')
@optional_auth
def http_tool():
    return render_template('tools/http.html', tool=TOOLS['http'])

@app.route('/security')
@optional_auth
def security_tool():
    return render_template('tools/security.html', tool=TOOLS['security'])

@app.route('/performance')
@optional_auth
def performance_tool():
    return render_template('tools/performance.html', tool=TOOLS['performance'])

@app.route('/seo')
@optional_auth
def seo_tool():
    return render_template('tools/seo.html', tool=TOOLS['seo'])

@app.route('/screenshot')
@optional_auth
def screenshot_tool():
    return render_template('tools/screenshot.html', tool=TOOLS['screenshot'])

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

        # Parse HTML for resources
        html = content.decode('utf-8', errors='ignore')

        # Count resources
        scripts = len(re.findall(r'<script[^>]+src=', html, re.IGNORECASE))
        stylesheets = len(re.findall(r'<link[^>]+stylesheet', html, re.IGNORECASE))
        images = len(re.findall(r'<img[^>]+src=', html, re.IGNORECASE))

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
        meta = extract_meta_tags(html)
        seo_score = calculate_seo_score(meta, html)

        # Additional checks
        h1_count = len(re.findall(r'<h1[^>]*>', html, re.IGNORECASE))
        if h1_count == 0:
            seo_score['issues'].append('No H1 tag found')
        elif h1_count > 1:
            seo_score['warnings'].append(f'Multiple H1 tags ({h1_count}) - consider using only one')

        # Check for alt tags on images
        images = re.findall(r'<img[^>]+>', html, re.IGNORECASE)
        images_without_alt = sum(1 for img in images if 'alt=' not in img.lower())
        if images_without_alt > 0:
            seo_score['warnings'].append(f'{images_without_alt} images missing alt attributes')

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
