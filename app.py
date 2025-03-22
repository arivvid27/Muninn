from flask import Flask, render_template, request, redirect, url_for, session
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
import json
import time
import random
import html
import concurrent.futures
import socket
import ssl
from requests.exceptions import RequestException, Timeout, ConnectionError

app = Flask(__name__)
app.secret_key = "secure_vulnerability_scanner_key"


class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.base_url = self._get_base_url(url)
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'
        }
        self.vulnerabilities = []
        self.visited_urls = set()
        self.max_pages_to_scan = 5
        self.request_timeout = 15
        
    def _get_base_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def scan(self):
        try:
            self.visited_urls.add(self.url)
            response = self._safe_request(self.url)
            
            if not response:
                return self.vulnerabilities
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Run core security checks on main page
            self._run_security_checks(self.url, response, soup)
            
            # Extract additional pages to scan (up to max limit)
            urls_to_scan = self._extract_additional_urls(soup, response.url)
            
            # Use a thread pool to scan additional pages concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = {executor.submit(self._scan_additional_page, url): url for url in urls_to_scan}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        url = futures[future]
                        self.vulnerabilities.append({
                            "type": "Scan Error",
                            "description": f"Error scanning page: {url}",
                            "severity": "low",
                            "location": url,
                            "details": f"The scanner encountered an error: {str(e)}"
                        })
            
            if not self.vulnerabilities:
                self.vulnerabilities.append({
                    "type": "Security Assessment",
                    "description": "No obvious vulnerabilities detected",
                    "severity": "info",
                    "location": self.url,
                    "details": "No common vulnerabilities were detected during the scan. However, this does not guarantee the site is completely secure. More thorough testing is recommended."
                })

            # Sort vulnerabilities by severity
            severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
            self.vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 4))
            
            return self.vulnerabilities

        except Exception as e:
            self.vulnerabilities.append({
                "type": "Scanner Error",
                "description": f"Error during scanning: {str(e)}",
                "severity": "high",
                "location": self.url,
                "details": "The scanner encountered an error while processing the website."
            })
            return self.vulnerabilities
    
    def _safe_request(self, url, method='get', data=None, allow_redirects=True):
        """Make a request with proper error handling and timeouts"""
        try:
            if method.lower() == 'post':
                response = self.session.post(
                    url, 
                    headers=self.headers, 
                    data=data, 
                    timeout=self.request_timeout,
                    allow_redirects=allow_redirects
                )
            else:
                response = self.session.get(
                    url, 
                    headers=self.headers, 
                    timeout=self.request_timeout,
                    allow_redirects=allow_redirects
                )
                
            if response.status_code != 200:
                self.vulnerabilities.append({
                    "type": "Connection Issue",
                    "description": f"Received status code {response.status_code} from the server",
                    "severity": "medium" if response.status_code >= 500 else "low",
                    "location": url,
                    "details": f"The server responded with status code {response.status_code}. This could indicate misconfiguration or access control issues."
                })
                if response.status_code >= 400:
                    return None
            
            return response
            
        except Timeout:
            self.vulnerabilities.append({
                "type": "Connection Issue",
                "description": f"Request timed out after {self.request_timeout} seconds",
                "severity": "medium",
                "location": url,
                "details": "The server took too long to respond, which may indicate performance issues."
            })
            return None
        except ConnectionError:
            self.vulnerabilities.append({
                "type": "Connection Issue",
                "description": "Failed to establish connection",
                "severity": "medium",
                "location": url,
                "details": "Could not establish a connection to the target website. The server might be down or blocking the scanner."
            })
            return None
        except RequestException as e:
            self.vulnerabilities.append({
                "type": "Connection Issue",
                "description": f"Request error: {str(e)}",
                "severity": "medium",
                "location": url,
                "details": "An error occurred while making the request to the target website."
            })
            return None
    
    def _extract_additional_urls(self, soup, current_url):
        """Extract additional URLs to scan from the current page"""
        if len(self.visited_urls) >= self.max_pages_to_scan:
            return []
            
        parsed_base = urlparse(self.base_url)
        parsed_current = urlparse(current_url)
        
        urls = set()
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            # Handle relative URLs
            if href.startswith('/'):
                full_url = f"{self.base_url}{href}"
            elif href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            elif not href.startswith(('http://', 'https://')):
                # Handle relative path without leading slash
                path = '/'.join(parsed_current.path.split('/')[:-1]) if '/' in parsed_current.path else ''
                full_url = f"{self.base_url}{path}/{href}"
            else:
                full_url = href
                
            # Only include URLs from the same domain
            parsed_url = urlparse(full_url)
            if parsed_url.netloc != parsed_base.netloc:
                continue
                
            # Remove fragments
            full_url = full_url.split('#')[0]
            
            if full_url not in self.visited_urls:
                urls.add(full_url)
                
        # Limit the number of additional URLs
        remaining = self.max_pages_to_scan - len(self.visited_urls)
        return list(urls)[:remaining]
    
    def _scan_additional_page(self, url):
        """Scan an additional page found during crawling"""
        if url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        response = self._safe_request(url)
        
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            self._run_security_checks(url, response, soup)
    
    def _run_security_checks(self, url, response, soup):
        """Run all security checks on a given page"""
        self._check_ssl(url)
        self._check_xss(soup, response.text, url)
        self._check_csrf(soup, url)
        self._check_open_redirects(soup, url)
        self._check_sql_injection_forms(soup, url)
        self._check_header_security(response.headers, url)
        self._check_information_disclosure(response.text, response.headers, url)
        self._check_insecure_cookies(response.headers, url)
        self._check_cors_policy(response.headers, url)
        self._check_clickjacking(response.headers, url)
        self._check_ssl_configuration(url)

    def _check_ssl(self, url):
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            self.vulnerabilities.append({
                "type": "Insecure Connection",
                "description": "Website does not use HTTPS",
                "severity": "high",
                "location": url,
                "details": "The website is using an unencrypted HTTP connection. This makes user data vulnerable to interception by attackers. All websites should use HTTPS to encrypt data in transit."
            })
    
    def _check_ssl_configuration(self, url):
        """Check for weak SSL/TLS configuration"""
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            return
            
        try:
            hostname = parsed_url.netloc.split(':')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    
                    # Check for outdated protocols
                    if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.vulnerabilities.append({
                            "type": "Weak SSL/TLS",
                            "description": f"Server using outdated protocol: {protocol}",
                            "severity": "high",
                            "location": url,
                            "details": f"The server is using {protocol}, which is considered insecure. The server should be configured to use TLSv1.2 or TLSv1.3 only."
                        })
                        
                    # Check certificate expiration
                    if 'notAfter' in cert:
                        import datetime
                        expires = ssl.cert_time_to_seconds(cert['notAfter'])
                        remaining = expires - time.time()
                        days_remaining = remaining / (24*60*60)
                        
                        if days_remaining < 30:
                            self.vulnerabilities.append({
                                "type": "SSL Certificate",
                                "description": f"SSL certificate expiring soon ({int(days_remaining)} days)",
                                "severity": "medium",
                                "location": url,
                                "details": "The SSL certificate is about to expire. Expired certificates cause browser warnings and prevent secure connections."
                            })
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError):
            # Don't add a vulnerability for connection issues here as _check_ssl already covers this
            pass
        except Exception:
            # Ignore other exceptions for this specific check
            pass

    def _check_xss(self, soup, html_content, url):
        """Enhanced XSS detection"""
        # Check for reflected parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param, values in query_params.items():
            for value in values:
                if value and value in html_content:
                    self.vulnerabilities.append({
                        "type": "Potential Reflected XSS",
                        "description": f"URL parameter '{param}' is reflected in the response",
                        "severity": "high",
                        "location": f"{url} - parameter: {param}",
                        "details": "URL parameters that are reflected in the page without proper encoding could allow Cross-Site Scripting attacks. An attacker could craft malicious URLs that execute JavaScript when visited by victims."
                    })
                    break
        
        # Check forms for XSS vulnerabilities
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for input_field in inputs:
                input_type = input_field.get('type', '').lower()
                input_name = input_field.get('name', '')
                
                if input_type in ['text', 'search', 'url', 'email', 'tel', None, '']:
                    # Check if there's any client-side validation
                    has_pattern = input_field.has_attr('pattern')
                    has_maxlength = input_field.has_attr('maxlength')
                    
                    # Check if sensitive input fields are properly protected
                    if input_name and any(term in input_name.lower() for term in ['search', 'query', 'q', 'find']):
                        if not (has_pattern or has_maxlength):
                            self.vulnerabilities.append({
                                "type": "Potential XSS",
                                "description": f"Poorly protected input field: {input_name}",
                                "severity": "high",
                                "location": f"{url} - {str(input_field)[:100]}...",
                                "details": "Text input fields without proper client-side validation or restrictions can be vulnerable to Cross-Site Scripting (XSS) attacks, especially for search or query inputs which are commonly reflected in the response."
                            })
                            break
        
        # Check for unsafe JavaScript patterns
        scripts = soup.find_all('script')
        dangerous_patterns = [
            (r'document\.write\s*\(', "document.write()"),
            (r'\.innerHTML\s*=', "innerHTML assignment"),
            (r'eval\s*\(', "eval()"),
            (r'setTimeout\s*\(\s*[\'"`]', "setTimeout with string"),
            (r'setInterval\s*\(\s*[\'"`]', "setInterval with string"),
            (r'new\s+Function\s*\(', "new Function()"),
            (r'location\.href\s*=', "location.href assignment"),
            (r'\.src\s*=\s*[^;]*\+', "Dynamic script source")
        ]
        
        for script in scripts:
            script_content = script.string if script.string else ""
            
            for pattern, name in dangerous_patterns:
                if re.search(pattern, script_content):
                    self.vulnerabilities.append({
                        "type": "Dangerous JavaScript",
                        "description": f"Use of potentially unsafe JavaScript: {name}",
                        "severity": "medium",
                        "location": f"{url}",
                        "details": f"The page uses potentially unsafe JavaScript functions like {name} which can lead to XSS vulnerabilities if they process unvalidated data. These functions should be avoided or used with proper input sanitization."
                    })
                    break

    def _check_csrf(self, soup, url):
        forms = soup.find_all('form', method=lambda x: x and x.lower() == 'post')
        
        for form in forms:
            has_csrf_token = False
            action = form.get('action', '')
            
            # Look for common CSRF token patterns
            inputs = form.find_all('input', type='hidden')
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                input_value = input_field.get('value', '')
                
                if (any(term in input_name for term in ['csrf', 'token', '_token', 'nonce', 'verify']) and 
                    input_value and len(input_value) > 8):
                    has_csrf_token = True
                    break
                    
            # Check form action - if it's a sensitive action
            sensitive_actions = ['login', 'register', 'password', 'update', 'delete', 'create', 'edit', 'admin']
            is_sensitive = action and any(term in action.lower() for term in sensitive_actions)
            
            if not has_csrf_token and (is_sensitive or not action):
                self.vulnerabilities.append({
                    "type": "CSRF Vulnerability",
                    "description": "Form lacks CSRF protection",
                    "severity": "high",
                    "location": f"{url}",
                    "details": "This form does not appear to include a CSRF token. Without Cross-Site Request Forgery protection, attackers can trick users into submitting malicious requests without their knowledge, potentially leading to account takeover or data modification."
                })

    def _check_open_redirects(self, soup, url):
        # Check URL parameters for redirect vectors
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        redirect_params = ['url', 'redirect', 'next', 'target', 'redir', 'return', 'destination', 'go', 'goto', 'link', 'to']
        
        for param in redirect_params:
            if param in query_params:
                values = query_params[param]
                for value in values:
                    # Check if value is an external URL or just a path
                    if value.startswith(('http://', 'https://', '//')):
                        self.vulnerabilities.append({
                            "type": "Open Redirect",
                            "description": f"URL parameter '{param}' could allow open redirects",
                            "severity": "medium",
                            "location": f"{url}",
                            "details": "The URL contains a redirect parameter that could be exploited to redirect users to malicious websites. This can be used in phishing attacks where users believe they're still on the trusted site."
                        })
                        break
        
        # Check links with redirect parameters
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            parsed = urlparse(href)
            query = parsed.query
            
            for param in redirect_params:
                if f"{param}=" in query:
                    # Get the redirect value
                    redirect_value = parse_qs(query).get(param, [''])[0]
                    
                    # Check if it's an external redirect
                    if redirect_value.startswith(('http://', 'https://', '//')):
                        self.vulnerabilities.append({
                            "type": "Open Redirect",
                            "description": f"Potential open redirect in link parameter '{param}'",
                            "severity": "medium",
                            "location": f"{url} - {href}",
                            "details": "Links with redirect parameters can be manipulated to send users to malicious websites. Attackers could modify these parameters to redirect users to phishing pages that mimic legitimate sites."
                        })
                        break

    def _check_sql_injection_forms(self, soup, url):
        forms = soup.find_all('form')
        
        for form in forms:
            # Check for sensitive form actions or names
            form_action = form.get('action', '').lower()
            form_name = form.get('name', '').lower()
            form_id = form.get('id', '').lower()
            
            sensitive_terms = ['login', 'admin', 'search', 'query', 'user', 'account', 'profile', 'member', 'database']
            is_sensitive_form = any(term in form_action or term in form_name or term in form_id for term in sensitive_terms)
            
            # Check input fields that are most likely to be database-connected
            inputs = form.find_all(['input', 'select', 'textarea'])
            sensitive_inputs = []
            
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                input_id = input_field.get('id', '').lower()
                
                sensitive_input_terms = ['id', 'user', 'name', 'pass', 'login', 'search', 'query', 'email', 'key']
                if any(term in input_name or term in input_id for term in sensitive_input_terms):
                    sensitive_inputs.append(input_name or input_id)
            
            # Only report if the form appears to interact with a database
            if is_sensitive_form or sensitive_inputs:
                vulnerability_details = "Form submissions without proper input validation and parameterized queries can be vulnerable to SQL injection attacks. "
                
                if sensitive_inputs:
                    vulnerability_details += f"Potentially vulnerable inputs: {', '.join(sensitive_inputs)}. "
                
                vulnerability_details += "This could allow attackers to access, modify, or delete data from databases, or even execute commands on the database server."
                
                self.vulnerabilities.append({
                    "type": "Potential SQL Injection",
                    "description": "Form inputs might be vulnerable to SQL injection",
                    "severity": "high",
                    "location": f"{url}",
                    "details": vulnerability_details
                })

    def _check_header_security(self, headers, url):
        security_headers = {
            'Strict-Transport-Security': {
                'missing': True,
                'severity': 'medium',
                'description': 'Missing HSTS header',
                'details': 'HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS, protecting against downgrade attacks and cookie hijacking.'
            },
            'Content-Security-Policy': {
                'missing': True,
                'severity': 'medium',
                'description': 'Missing Content-Security-Policy',
                'details': 'Content Security Policy helps prevent XSS attacks by specifying which dynamic resources are allowed to load.'
            },
            'X-Frame-Options': {
                'missing': True,
                'severity': 'low',
                'description': 'Missing X-Frame-Options header',
                'details': 'X-Frame-Options prevents clickjacking attacks by ensuring the page cannot be embedded in frames on other sites.'
            },
            'X-Content-Type-Options': {
                'missing': True,
                'severity': 'low',
                'description': 'Missing X-Content-Type-Options header',
                'details': 'X-Content-Type-Options prevents MIME type sniffing, which can lead to security vulnerabilities.'
            },
            'Referrer-Policy': {
                'missing': True,
                'severity': 'low',
                'description': 'Missing Referrer-Policy header',
                'details': 'Referrer-Policy controls how much referrer information is included with requests. Without this header, sensitive information might leak through referrers.'
            },
            'Permissions-Policy': {
                'missing': True,
                'severity': 'low',
                'description': 'Missing Permissions-Policy header', 
                'details': 'Permissions-Policy (formerly Feature-Policy) allows control over browser features like camera, microphone, and geolocation.'
            }
        }

        # Check for header presence
        for header, info in security_headers.items():
            normalized_header = header.lower()
            
            # Case-insensitive header check
            for actual_header in headers:
                if actual_header.lower() == normalized_header:
                    info['missing'] = False
                    
                    # Validate HSTS settings if present
                    if normalized_header == 'strict-transport-security':
                        hsts_value = headers[actual_header].lower()
                        if 'max-age=' in hsts_value:
                            try:
                                max_age = int(re.search(r'max-age=(\d+)', hsts_value).group(1))
                                if max_age < 31536000:  # Less than 1 year
                                    self.vulnerabilities.append({
                                        "type": "Weak HSTS Configuration",
                                        "description": f"HSTS max-age is too short: {max_age} seconds",
                                        "severity": "low",
                                        "location": url,
                                        "details": "The HSTS max-age should be at least 1 year (31536000 seconds) to ensure proper protection."
                                    })
                            except (AttributeError, ValueError):
                                pass
                                
                        if 'includesubdomains' not in hsts_value:
                            self.vulnerabilities.append({
                                "type": "Incomplete HSTS Configuration",
                                "description": "HSTS missing includeSubDomains directive",
                                "severity": "low",
                                "location": url,
                                "details": "The HSTS header should include the 'includeSubDomains' directive to protect all subdomains."
                            })
                    
                    # Validate CSP settings if present
                    if normalized_header == 'content-security-policy':
                        csp_value = headers[actual_header].lower()
                        if "unsafe-inline" in csp_value or "unsafe-eval" in csp_value:
                            self.vulnerabilities.append({
                                "type": "Weak CSP Configuration",
                                "description": "CSP allows unsafe-inline or unsafe-eval",
                                "severity": "medium",
                                "location": url,
                                "details": "The Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval' directives, which weaken protection against XSS attacks."
                            })
                    break

        # Add vulnerabilities for missing headers
        for header, info in security_headers.items():
            if info['missing']:
                # Only report the absence of non-critical headers for HTTPS sites
                if header in ['Strict-Transport-Security']:
                    parsed_url = urlparse(url)
                    if parsed_url.scheme != "https":
                        continue
                        
                self.vulnerabilities.append({
                    "type": "Security Header Missing",
                    "description": info['description'],
                    "severity": info['severity'],
                    "location": url,
                    "details": info['details']
                })

    def _check_information_disclosure(self, content, headers, url):
        # Check for server information disclosure
        if 'Server' in headers and headers['Server'] != '':
            server_header = headers['Server']
            if re.search(r'[a-zA-Z]+/[0-9.]+', server_header):  # Matches patterns like Apache/2.4.41
                self.vulnerabilities.append({
                    "type": "Information Disclosure",
                    "description": f"Server header discloses software/version: {server_header}",
                    "severity": "medium",
                    "location": url,
                    "details": "The server is revealing its software and version information. This helps attackers target specific vulnerabilities in the disclosed software versions."
                })
            else:
                self.vulnerabilities.append({
                    "type": "Information Disclosure",
                    "description": f"Server header discloses software: {server_header}",
                    "severity": "low",
                    "location": url,
                    "details": "The server is revealing its software. While not disclosing version information, this still provides attackers with information on what software to target."
                })
        
        # Check for X-Powered-By header
        if 'X-Powered-By' in headers:
            self.vulnerabilities.append({
                "type": "Information Disclosure",
                "description": f"X-Powered-By header reveals: {headers['X-Powered-By']}",
                "severity": "low",
                "location": url,
                "details": "The X-Powered-By header reveals information about the technologies used on the server. This can help attackers identify specific vulnerabilities to target."
            })
        
        # Check HTML comments for sensitive information
        comment_pattern = re.compile(r'<!--(.+?)-->', re.DOTALL)
        comments = comment_pattern.findall(content)

        sensitive_terms = [
            'password', 'pass', 'pwd', 'todo', 'fix', 'bug', 'hack', 'workaround', 'temporary', 
            'secret', 'key', 'token', 'api', 'auth', 'admin', 'backdoor', 'dev', 'debug', 
            'remove', 'not secure', 'credentials', 'prod', 'production', 'test'
        ]
        
        for comment in comments:
            comment = comment.strip()
            if len(comment) > 10:  # Ignore very short comments
                comment_lower = comment.lower()
                found_terms = [term for term in sensitive_terms if term in comment_lower]
                
                if found_terms:
                    short_comment = comment[:50] + '...' if len(comment) > 50 else comment
                    sanitized_comment = html.escape(short_comment)
                    found_terms_str = ', '.join(found_terms)

                    self.vulnerabilities.append({
                        "type": "Information Disclosure",
                        "description": f"HTML comment may contain sensitive information ({found_terms_str})",
                        "severity": "medium",
                        "location": url,
                        "details": f"HTML comments sometimes contain sensitive information, debugging data, or internal notes that could help attackers. Found comment with sensitive terms: '{sanitized_comment}'"
                    })
        
        # Check for debug information or error messages
        error_patterns = [
            r'(?:sql|mysql|postgresql|database) error',
            r'(?:warning|notice|deprecated):\s+\[?php\]?',
            r'exception (?:in|at) .+?\\.(?:js|php|py|rb)',
            r'stack trace:',
            r'syntax error',
            r'undefined (?:variable|index|offset)',
            r'fatal error',
            r'traceback \(most recent call last\)',
            r'<b>(?:warning|fatal|notice|parse error|error)</b>'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.vulnerabilities.append({
                    "type": "Information Disclosure",
                    "description": "Page contains error messages or debug information",
                    "severity": "medium",
                    "location": url,
                    "details": "Error messages or debug information were detected in the page content. These can reveal sensitive details about the application's inner workings, potentially helping attackers identify vulnerabilities."
                })
                break

    def _check_insecure_cookies(self, headers, url):
        if 'Set-Cookie' not in headers:
            return
            
        parsed_url = urlparse(url)
        is_https = parsed_url.scheme == "https"
        
        cookies = headers.getall('Set-Cookie') if hasattr(headers, 'getall') else [headers['Set-Cookie']]
        
        for cookie in cookies:
            cookie_lower = cookie.lower()
            
            # Check for Secure flag
            if is_https and 'secure' not in cookie_lower:
                self.vulnerabilities.append({
                    "type": "Insecure Cookie",
                    "description": "Cookie set without Secure flag",
                    "severity": "medium",
                    "location": url,
                    "details": "Cookies without the Secure flag can be transmitted over unencrypted HTTP connections, making them vulnerable to interception. The Secure flag ensures cookies are only sent over HTTPS connections."
                })
            
            # Check for HttpOnly flag
            if 'httponly' not in cookie_lower:
                # Try to identify if it's a session or auth cookie
                is_sensitive = any(name in cookie_lower for name in ['session', 'auth', 'token', 'user', 'login', 'secure', 'jsessionid', 'phpsessid', 'aspsessionid'])
                
                if is_sensitive:
                    self.vulnerabilities.append({
                        "type": "Insecure Cookie",
                        "description": "Sensitive cookie set without HttpOnly flag",
                        "severity": "medium",
                        "location": url,
                        "details": "Cookies without the HttpOnly flag can be accessed by malicious JavaScript. The HttpOnly flag prevents client-side scripts from accessing cookies, providing protection against certain XSS attacks."
                    })
            
            # Check for SameSite attribute
            if 'samesite' not in cookie_lower:
                self.vulnerabilities.append({
                    "type": "Insecure Cookie",
                    "description": "Cookie set without SameSite attribute",
                    "severity": "low",
                    "location": url,
                    "details": "Cookies without the SameSite attribute can be sent in cross-site requests, potentially enabling CSRF attacks. Modern browsers require the SameSite attribute for better security."
                })
            elif 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
                self.vulnerabilities.append({
                    "type": "Insecure Cookie",
                    "description": "Cookie with SameSite=None but without Secure flag",
                    "severity": "medium",
                    "location": url,
                    "details": "Cookies with SameSite=None must also have the Secure flag. Without the Secure flag, the cookie can be sent over unencrypted connections, negating the security benefits."
                })
            
            # Check for expiration
            has_expires = 'expires=' in cookie_lower
            has_max_age = 'max-age=' in cookie_lower
            
            if not (has_expires or has_max_age):
                self.vulnerabilities.append({
                    "type": "Session Cookie",
                    "description": "Cookie without expiration time",
                    "severity": "low",
                    "location": url,
                    "details": "Cookies without an expiration time become session cookies and persist until the browser is closed. For sensitive operations, cookies should have an appropriate expiration time."
                })
    
    def _check_cors_policy(self, headers, url):
        """Check for insecure CORS configuration"""
        if 'Access-Control-Allow-Origin' in headers:
            allowed_origin = headers['Access-Control-Allow-Origin']
            
            if allowed_origin == '*':
                self.vulnerabilities.append({
                    "type": "Insecure CORS",
                    "description": "CORS allows any origin (*)",
                    "severity": "medium",
                    "location": url,
                    "details": "The Access-Control-Allow-Origin header is set to '*', allowing any domain to make cross-origin requests. This can lead to data theft if the responses contain sensitive information."
                })
            
            # Check if credentials are allowed with a broad origin
            if (allowed_origin == '*' or allowed_origin.startswith('http')) and 'Access-Control-Allow-Credentials' in headers:
                if headers['Access-Control-Allow-Credentials'].lower() == 'true':
                    self.vulnerabilities.append({
                        "type": "Insecure CORS",
                        "description": "CORS allows credentials with non-specific origin",
                        "severity": "high",
                        "location": url,
                        "details": "The site allows credentials (cookies, authorization) in cross-origin requests while not restricting the allowed origins correctly. This can lead to CSRF attacks or unauthorized data access."
                    })
    
    def _check_clickjacking(self, headers, url):
        """Check for clickjacking protection"""
        has_xfo = False
        has_csp_frame = False
        
        # Check X-Frame-Options
        for header in headers:
            if header.lower() == 'x-frame-options':
                has_xfo = True
                xfo_value = headers[header].lower()
                
                if xfo_value not in ['deny', 'sameorigin']:
                    self.vulnerabilities.append({
                        "type": "Clickjacking Protection",
                        "description": f"Invalid X-Frame-Options value: {headers[header]}",
                        "severity": "medium",
                        "location": url,
                        "details": "The X-Frame-Options header has an invalid value. Valid values are 'DENY' or 'SAMEORIGIN' to prevent clickjacking attacks."
                    })
        
        # Check CSP frame-ancestors
        if 'Content-Security-Policy' in headers:
            csp = headers['Content-Security-Policy']
            if 'frame-ancestors' in csp:
                has_csp_frame = True
                
                # Check if frame-ancestors is too permissive
                if "frame-ancestors 'none'" not in csp and "frame-ancestors 'self'" not in csp:
                    if "*" in csp or "http:" in csp:
                        self.vulnerabilities.append({
                            "type": "Clickjacking Protection",
                            "description": "CSP frame-ancestors is too permissive",
                            "severity": "medium",
                            "location": url,
                            "details": "The Content-Security-Policy header has a frame-ancestors directive that is too permissive, potentially allowing clickjacking attacks."
                        })
        
        # No clickjacking protection at all
        if not has_xfo and not has_csp_frame:
            self.vulnerabilities.append({
                "type": "Clickjacking Protection",
                "description": "Missing clickjacking protection",
                "severity": "medium",
                "location": url,
                "details": "The page does not use X-Frame-Options or CSP frame-ancestors to prevent clickjacking attacks. Without these protections, the page could be embedded in an iframe on a malicious site."
            })


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
        # Add slight delay to show scanning progress to user
        time.sleep(0.5)

        results = scanner.scan()
        
        # Add small delay so it doesn't seem too fast (improves user confidence)
        time.sleep(1.5)

        session['scan_results'] = results
        session['target_url'] = url
        session['scan_date'] = time.strftime("%Y-%m-%d %H:%M:%S")

        return redirect(url_for('results'))

    except Exception as e:
        error_message = f"Error scanning URL: {str(e)}"
        return render_template('index.html', error=error_message)


@app.route('/results')
def results():
    scan_results = session.get('scan_results', [])
    target_url = session.get('target_url', '')
    scan_date = session.get('scan_date', '')
    severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
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
    app.run(host='0.0.0.0', port=7000, debug=True) # Change this when we're hosting (Dev purposes)