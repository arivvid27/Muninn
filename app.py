from flask import Flask, render_template, request, redirect, url_for, session
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import json
import time
import random
import html
import hashlib
import logging

app = Flask(__name__)
app.secret_key = "secure_vulnerability_scanner_key"

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'
        }
        self.vulnerabilities = []
        self.discovered_urls = set()
        self.visited_urls = set()
        self.max_urls_to_scan = 10  # Limit to prevent excessive scanning

    def scan(self):
        try:
            logger.info(f"Starting scan of {self.url}")
            
            response = self.session.get(self.url, headers=self.headers, timeout=10)
            if response.status_code != 200:
                self.vulnerabilities.append({
                    "type": "Connection Issue",
                    "description": f"Received status code {response.status_code} from the server",
                    "severity": "medium",
                    "location": self.url,
                    "details": "Could not establish a proper connection to the target website."
                })
                return self.vulnerabilities

            # Add base URL to visited
            self.visited_urls.add(self.url)
            
            # Get links for limited crawling
            self._discover_links(self.url, response.text)
            
            # Scan the base URL first
            self._scan_url(self.url, response)
            
            # Scan a limited number of discovered URLs
            scan_count = 1  # Already scanned the base URL
            for url in self.discovered_urls:
                if url in self.visited_urls or scan_count >= self.max_urls_to_scan:
                    continue
                    
                try:
                    logger.info(f"Scanning discovered URL: {url}")
                    sub_response = self.session.get(url, headers=self.headers, timeout=5)
                    self._scan_url(url, sub_response)
                    self.visited_urls.add(url)
                    scan_count += 1
                except Exception as e:
                    logger.error(f"Error scanning {url}: {str(e)}")
                
            # Perform directory enumeration
            self._directory_enumeration(self.url)
            
            if not self.vulnerabilities:
                self.vulnerabilities.append({
                    "type": "Security Assessment",
                    "description": "No obvious vulnerabilities detected",
                    "severity": "info",
                    "location": self.url,
                    "details": "No common vulnerabilities were detected during the scan. However, this does not guarantee the site is completely secure. More thorough testing is recommended."
                })

            return self.vulnerabilities

        except Exception as e:
            logger.error(f"Scanner error: {str(e)}")
            self.vulnerabilities.append({
                "type": "Scanner Error",
                "description": f"Error during scanning: {str(e)}",
                "severity": "high",
                "location": self.url,
                "details": "The scanner encountered an error while processing the website."
            })
            return self.vulnerabilities

    def _discover_links(self, base_url, html_content):
        """Find links within the same domain for limited crawling"""
        try:
            base_domain = urlparse(base_url).netloc
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(base_url, href)
                
                parsed_href = urlparse(href)
                if parsed_href.netloc == base_domain:
                    self.discovered_urls.add(href)
        except Exception as e:
            logger.error(f"Error discovering links: {str(e)}")

    def _scan_url(self, url, response):
        """Scan a specific URL for vulnerabilities"""
        try:
            soup = BeautifulSoup(response.text, 'html.parser')

            self._check_ssl(url)
            self._check_xss(soup, response.text, url)
            self._check_csrf(soup, url)
            self._check_open_redirects(soup, url)
            self._check_sql_injection_forms(soup, url, response)
            self._check_header_security(response.headers, url)
            self._check_information_disclosure(response.text, response.headers, url)
            self._check_insecure_cookies(response.headers, url)
        except Exception as e:
            logger.error(f"Error in _scan_url for {url}: {str(e)}")

    def _check_ssl(self, url):
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            try:
                http_url = f"http://{parsed_url.netloc}{parsed_url.path}"
                redirect_resp = self.session.get(http_url, headers=self.headers, timeout=5, allow_redirects=False)
                
                if redirect_resp.status_code in (301, 302, 307, 308):
                    redirect_location = redirect_resp.headers.get('Location', '')
                    if redirect_location.startswith('https://'):
                        return
            except Exception:
                pass
                
            self.vulnerabilities.append({
                "type": "Insecure Connection",
                "description": "Website does not use HTTPS",
                "severity": "high",
                "location": url,
                "details": "The website is using an unencrypted HTTP connection. This makes user data vulnerable to interception by attackers."
            })

    def _check_xss(self, soup, html_content, url):
        """Enhanced XSS detection with reduced false positives and more precise checks"""
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            test_payloads = ["<script>console.log(1)</script>", "test\" onload=\"console.log(1)", "'-console.log(1)-'"]
            
            for param, values in query_params.items():
                for value in values:
                    if len(value) < 3:
                        continue
                        
                    test_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}{urlparse(url).path}?{param}={test_payloads[0]}"
                    try:
                        test_response = self.session.get(test_url, headers=self.headers, timeout=5)
                        if test_payloads[0] in test_response.text and '<script>' in test_response.text:
                            self.vulnerabilities.append({
                                "type": "Reflected XSS",
                                "description": f"Parameter '{param}' reflects script tags without encoding",
                                "severity": "critical",
                                "location": url,
                                "details": "User input is reflected in the response without proper HTML encoding, allowing script execution."
                            })
                            return
                    except Exception as e:
                        logger.error(f"Error testing reflected XSS: {str(e)}")
                        
            scripts = soup.find_all('script')
            dangerous_sinks = [
                (r'document\.write\s*\(\s*.*?(document\.URL|location\.hash|location\.search)', "document.write sink"),
            ]
            
            for script in scripts:
                if script.string:
                    for pattern, sink_type in dangerous_sinks:
                        if re.search(pattern, script.string, re.IGNORECASE):
                            if not re.search(r'(encodeURIComponent|escape|sanitize|filterXSS)', script.string, re.IGNORECASE):
                                self.vulnerabilities.append({
                                    "type": "DOM-based XSS",
                                    "description": f"Unsafe {sink_type} with unvalidated input",
                                    "severity": "high",
                                    "location": url,
                                    "details": f"JavaScript uses {sink_type} with unvalidated URL input, potentially allowing XSS."
                                })
                                break
            
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input', type=['text', 'search', 'url', None])
                for input_field in inputs:
                    input_id = input_field.get('id', '')
                    input_name = input_field.get('name', '')
                    
                    for script in scripts:
                        if script.string and (input_id or input_name):
                            vuln_pattern = rf"{input_id or input_name}\.value\s*.*?(innerHTML|document\.write|eval)"
                            if re.search(vuln_pattern, script.string, re.IGNORECASE):
                                if not re.search(r'(sanitize|escape|encode)', script.string, re.IGNORECASE):
                                    self.vulnerabilities.append({
                                        "type": "Potential XSS",
                                        "description": "Form input used unsafely in DOM manipulation",
                                        "severity": "medium",
                                        "location": f"{url} - Input: {input_name or input_id}",
                                        "details": "Form input appears to be used directly in a DOM sink without sanitization."
                                    })
                                    break
        except Exception as e:
            logger.error(f"Error in XSS check: {str(e)}")

    def _check_csrf(self, soup, url):
        forms = soup.find_all('form', method=lambda x: x and x.lower() == 'post')
        for form in forms:
            form_action = form.get('action', '').lower()
            if 'login' in form_action or 'search' in form_action:
                continue
                
            has_csrf_token = False
            inputs = form.find_all('input', type='hidden')
            for input_field in inputs:
                name = input_field.get('name', '').lower()
                value = input_field.get('value', '')
                if any(token_name in name for token_name in ['csrf', 'token', '_token', 'nonce', 'authenticity']):
                    if value and len(value) >= 8 and not value.isalnum():
                        has_csrf_token = True
                        break
            
            meta_csrf = soup.find('meta', attrs={'name': lambda x: x and 'csrf' in x.lower()})
            if meta_csrf and meta_csrf.get('content'):
                has_csrf_token = True
            
            scripts = soup.find_all('script')
            header_csrf_patterns = [
                r'X-CSRF-Token',
                r'csrf[_-]token',
                r'\.headers\s*\[\s*[\'"]X-CSRF',
                r'\.setRequestHeader\s*\(\s*[\'"]X-CSRF'
            ]
            
            for script in scripts:
                if script.string and any(re.search(pattern, script.string, re.IGNORECASE) for pattern in header_csrf_patterns):
                    has_csrf_token = True
                    break
            
            if not has_csrf_token:
                action_words = ['update', 'delete', 'create', 'edit', 'add', 'remove', 'submit', 'change', 'modify']
                form_purpose_indicates_state_change = (
                    any(word in form_action for word in action_words) or
                    any(word in form.get('class', '') for word in action_words) or
                    any(word in form.get('id', '') for word in action_words)
                )
                
                if form_purpose_indicates_state_change:
                    self.vulnerabilities.append({
                        "type": "CSRF Vulnerability",
                        "description": "Form that changes state lacks CSRF protection",
                        "severity": "high",
                        "location": f"{url} - {str(form)[:100]}...",
                        "details": "This form modifies server state but lacks CSRF protection, allowing potential malicious requests."
                    })

    def _check_open_redirects(self, soup, url):
        links = soup.find_all('a', href=True)
        redirect_params = ['url', 'redirect', 'next', 'target', 'redir', 'return', 'destination', 'go', 'goto']

        for link in links:
            href = link['href']
            parsed = urlparse(href)
            query_params = parse_qs(parsed.query)
            
            for param in redirect_params:
                if param in query_params:
                    redirect_value = query_params[param][0]
                    if redirect_value.startswith(('http://', 'https://')):
                        try:
                            full_url = urljoin(url, href)
                            redirect_response = self.session.get(full_url, headers=self.headers, timeout=5, allow_redirects=False)
                            
                            if redirect_response.status_code in (301, 302, 307, 308):
                                location = redirect_response.headers.get('Location', '')
                                if location.startswith(('http://', 'https://')) and urlparse(location).netloc != urlparse(url).netloc:
                                    self.vulnerabilities.append({
                                        "type": "Open Redirect",
                                        "description": f"Confirmed open redirect in link parameter '{param}'",
                                        "severity": "high",
                                        "location": f"{url} - {href}",
                                        "details": "This link accepts and follows external URLs, exploitable for phishing."
                                    })
                        except Exception:
                            if redirect_value.startswith(('http://', 'https://')) and urlparse(redirect_value).netloc != urlparse(url).netloc:
                                self.vulnerabilities.append({
                                    "type": "Potential Open Redirect",
                                    "description": f"Potential open redirect in link parameter '{param}'",
                                    "severity": "medium",
                                    "location": f"{url} - {href}",
                                    "details": "This link may allow redirection to external sites if not validated."
                                })
                    break

    def _check_sql_injection_forms(self, soup, url, response):
        """Enhanced SQL injection detection with active testing and error analysis"""
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '').lower()
            if 'search' in form_action or 'newsletter' in form_action:
                continue
                
            inputs = form.find_all('input', type=['text', 'search', None])
            if not inputs:
                continue
                
            method = form.get('method', 'get').lower()
            action_url = urljoin(url, form.get('action', '')) if form.get('action') else url
            
            test_payloads = ["' OR 1=1 --", "1; DROP TABLE users --", "' UNION SELECT NULL --"]
            for input_field in inputs:
                input_name = input_field.get('name')
                if not input_name:
                    continue
                    
                try:
                    if method == 'get':
                        test_params = {input_name: test_payloads[0]}
                        test_url = f"{action_url}?{urlencode(test_params)}"
                        test_response = self.session.get(test_url, headers=self.headers, timeout=5)
                    else:
                        test_response = self.session.post(action_url, data={input_name: test_payloads[0]}, headers=self.headers, timeout=5)
                        
                    sql_errors = [
                        (r'SQL syntax.*MySQL', "MySQL error"),
                        (r'ORA-\d+', "Oracle error"),
                        (r'Microsoft SQL Server.*error', "SQL Server error"),
                        (r'PostgreSQL.*ERROR', "PostgreSQL error"),
                        (r'sqlite3\.', "SQLite error"),
                        (r'unclosed quotation mark', "Generic SQL error"),
                        (r'valid MySQL result', "MySQL fetch error")
                    ]
                    
                    for pattern, db_type in sql_errors:
                        if re.search(pattern, test_response.text, re.IGNORECASE):
                            self.vulnerabilities.append({
                                "type": "SQL Injection Vulnerability",
                                "description": f"{db_type} detected in form input '{input_name}'",
                                "severity": "critical",
                                "location": f"{url} - Form action: {form_action}",
                                "details": "Input triggered a database error, indicating unsanitized SQL queries."
                            })
                            return
                            
                    if 'login' in form_action and 'welcome' in test_response.text.lower():
                        self.vulnerabilities.append({
                            "type": "SQL Injection Vulnerability",
                            "description": "Successful authentication bypass",
                            "severity": "critical",
                            "location": f"{url} - Form action: {form_action}",
                            "details": "SQL injection payload bypassed authentication."
                        })
                        return
                        
                except Exception as e:
                    logger.error(f"Error testing SQL injection: {str(e)}")
                    
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and any(keyword in script.string.lower() for keyword in ['query', 'sql', 'execute']):
                    if not re.search(r'(prepare|bind|sanitize|escape)', script.string, re.IGNORECASE):
                        self.vulnerabilities.append({
                            "type": "Potential SQL Injection",
                            "description": "Possible unsanitized database interaction",
                            "severity": "medium",
                            "location": f"{url} - Form action: {form_action}",
                            "details": "Script suggests database interaction without clear sanitization."
                        })
                        break

    def _check_header_security(self, headers, url):
        security_headers = {
            'Strict-Transport-Security': {
                'missing': True,
                'severity': 'medium',
                'description': 'Missing HSTS header',
                'details': 'HSTS forces browsers to use HTTPS, protecting against downgrade attacks.'
            },
            'Content-Security-Policy': {
                'missing': True,
                'severity': 'medium',
                'description': 'Missing Content-Security-Policy',
                'details': 'CSP helps prevent XSS by specifying allowed resources.'
            },
            'X-Frame-Options': {
                'missing': True,
                'severity': 'low',
                'description': 'Missing X-Frame-Options header',
                'details': 'Prevents clickjacking by disallowing framing.'
            },
            'X-Content-Type-Options': {
                'missing': True,
                'severity': 'low',
                'description': 'Missing X-Content-Type-Options header',
                'details': 'Prevents MIME type sniffing vulnerabilities.'
            }
        }

        if urlparse(url).scheme == 'https':
            for header, info in security_headers.items():
                if header in headers:
                    info['missing'] = False
                    
                    if header == 'Strict-Transport-Security':
                        hsts_value = headers[header].lower()
                        if 'max-age=' in hsts_value:
                            try:
                                max_age = int(re.search(r'max-age=(\d+)', hsts_value).group(1))
                                if max_age < 10886400:
                                    self.vulnerabilities.append({
                                        "type": "Weak HSTS Configuration",
                                        "description": "HSTS max-age is too short",
                                        "severity": "low",
                                        "location": url,
                                        "details": f"HSTS max-age ({max_age} seconds) is less than 126 days."
                                    })
                            except Exception:
                                pass

                    if header == 'Content-Security-Policy':
                        csp_value = headers[header].lower()
                        if "unsafe-inline" in csp_value and "script-src" in csp_value:
                            self.vulnerabilities.append({
                                "type": "Weak CSP Configuration",
                                "description": "CSP allows unsafe-inline scripts",
                                "severity": "medium",
                                "location": url,
                                "details": "CSP allows 'unsafe-inline', reducing XSS protection."
                            })

                if info['missing'] and self._is_sensitive_page(url):
                    self.vulnerabilities.append({
                        "type": "Security Header Missing",
                        "description": info['description'],
                        "severity": info['severity'],
                        "location": url,
                        "details": info['details']
                    })

    def _is_sensitive_page(self, url):
        path = urlparse(url).path.lower()
        sensitive_indicators = [
            '/login', '/admin', '/account', '/profile', '/user',
            '/checkout', '/payment', '/cart', '/order', '/settings',
            '/dashboard', '/member', '/secure', '/auth', '/private'
        ]
        return any(indicator in path for indicator in sensitive_indicators)

    def _check_information_disclosure(self, content, headers, url):
        if 'Server' in headers and headers['Server'] != '':
            server_info = headers['Server']
            version_pattern = r'[0-9]+\.[0-9]+(\.[0-9]+)?'
            if re.search(version_pattern, server_info):
                self.vulnerabilities.append({
                    "type": "Information Disclosure",
                    "description": f"Server header discloses software version: {server_info}",
                    "severity": "low",
                    "location": url,
                    "details": "Server version information helps attackers target specific vulnerabilities."
                })

        comment_pattern = re.compile(r'<!--(.+?)-->', re.DOTALL)
        comments = comment_pattern.findall(content)

        for comment in comments:
            comment = comment.strip()
            sensitive_patterns = [
                (r'password\s*[=:]\s*[\'"][^\'"]{4,}[\'"]', "Password in comment"),
                (r'username\s*[=:]\s*[\'"][^\'"]{4,}[\'"]', "Username in comment"),
                (r'api[_\s]*key\s*[=:]\s*[\'"][^\'"]{10,}[\'"]', "API key in comment"),
                (r'secret\s*[=:]\s*[\'"][^\'"]{10,}[\'"]', "Secret in comment"),
                (r'token\s*[=:]\s*[\'"][^\'"]{10,}[\'"]', "Token in comment"),
                (r'aws_access_key_id', "AWS credential"),
                (r'aws_secret_access_key', "AWS credential"),
                (r'database\s*connection', "Database connection info")
            ]
            
            for pattern, description in sensitive_patterns:
                if re.search(pattern, comment.lower()):
                    short_comment = comment[:50] + '...' if len(comment) > 50 else comment
                    sanitized_comment = html.escape(short_comment)
                    self.vulnerabilities.append({
                        "type": "Information Disclosure",
                        "description": f"{description} found in HTML comment",
                        "severity": "high",
                        "location": url,
                        "details": f"Sensitive info found: '{sanitized_comment}'"
                    })
                    break

        error_patterns = [
            (r'stack trace:', "Stack trace disclosure"),
            (r'Traceback \(most recent call last\)', "Python traceback"),
            (r'at [\w$.]+\([\w$.]+\.java:\d+\)', "Java stack trace"),
            (r'Microsoft OLE DB Provider for SQL Server', "SQL Server error")
        ]
        
        for pattern, description in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.vulnerabilities.append({
                    "type": "Information Disclosure",
                    "description": description,
                    "severity": "medium",
                    "location": url,
                    "details": "Technical error messages reveal application details."
                })
                break

    def _check_insecure_cookies(self, headers, url):
        """Enhanced cookie security check with better context awareness"""
        if 'Set-Cookie' not in headers:
            return
            
        cookies = headers.getall('Set-Cookie') if hasattr(headers, 'getall') else [headers['Set-Cookie']]
        is_https = urlparse(url).scheme == 'https'
        
        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_attrs = {
                'secure': 'secure' in cookie_lower,
                'httponly': 'httponly' in cookie_lower,
                'samesite': 'samesite' in cookie_lower,
                'samesite_value': 'lax' if 'samesite=lax' in cookie_lower else 'strict' if 'samesite=strict' in cookie_lower else None
            }
            
            sensitive_names = ['sess', 'auth', 'token', 'id', 'user', 'login', 'admin', 'account']
            is_sensitive = any(name in cookie_lower for name in sensitive_names)
            
            if is_https and not cookie_attrs['secure'] and is_sensitive:
                self.vulnerabilities.append({
                    "type": "Insecure Cookie",
                    "description": "Sensitive cookie missing Secure flag",
                    "severity": "high",
                    "location": url,
                    "details": "A sensitive cookie lacks the Secure flag over HTTPS, risking interception."
                })
            
            if is_sensitive and not cookie_attrs['httponly']:
                self.vulnerabilities.append({
                    "type": "Insecure Cookie",
                    "description": "Sensitive cookie missing HttpOnly flag",
                    "severity": "high",
                    "location": url,
                    "details": "A sensitive cookie lacks HttpOnly, increasing XSS impact."
                })
            
            if is_sensitive and not cookie_attrs['samesite']:
                self.vulnerabilities.append({
                    "type": "Insecure Cookie",
                    "description": "Sensitive cookie missing SameSite attribute",
                    "severity": "medium",
                    "location": url,
                    "details": "A sensitive cookie lacks SameSite, exposing it to CSRF attacks."
                })
            elif is_sensitive and cookie_attrs['samesite'] and cookie_attrs['samesite_value'] == 'lax':
                if self._has_post_forms(url):
                    self.vulnerabilities.append({
                        "type": "Weak Cookie Configuration",
                        "description": "Sensitive cookie uses SameSite=Lax in POST-heavy context",
                        "severity": "low",
                        "location": url,
                        "details": "SameSite=Lax may not fully protect against CSRF in POST-heavy apps."
                    })


    def _deduplicate_vulnerabilities(self):
        """Remove duplicate vulnerability reports"""
        unique_vulns = []
        vuln_hashes = set()
        
        for vuln in self.vulnerabilities:
            vuln_hash = hashlib.md5(f"{vuln['type']}:{vuln['location']}".encode()).hexdigest()
            if vuln_hash not in vuln_hashes:
                unique_vulns.append(vuln)
                vuln_hashes.add(vuln_hash)
                
        self.vulnerabilities = unique_vulns


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url', '')

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        scanner = VulnerabilityScanner(url)
        time.sleep(0.5)

        results = scanner.scan()
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        results.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 999))
        
        scanner._deduplicate_vulnerabilities()
        
        time.sleep(1.5)

        session['scan_results'] = results
        session['target_url'] = url
        session['scan_date'] = time.strftime("%Y-%m-%d %H:%M:%S")

        return redirect(url_for('results'))

    except Exception as e:
        logger.error(f"Error in scan route: {str(e)}")
        error_message = f"Error scanning URL: {str(e)}"
        return render_template('index.html', error=error_message)


@app.route('/results')
def results():
    scan_results = session.get('scan_results', [])
    target_url = session.get('target_url', '')
    scan_date = session.get('scan_date', '')
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in scan_results:
        severity = vuln.get("severity", "info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return render_template(
        'results.html',
        results=scan_results,
        target_url=target_url,
        scan_date=scan_date,
        severity_counts=severity_counts
    )

@app.template_filter('truncate_url')
def truncate_url(url, length=50):
    if len(url) <= length:
        return url
    return url[:length] + '...'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7000, debug=True)