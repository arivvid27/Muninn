from flask import Flask, render_template, request, redirect, url_for, session
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import json
import time
import random
import html

app = Flask(__name__)
app.secret_key = "secure_vulnerability_scanner_key"


class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'
        }
        self.vulnerabilities = []

    def scan(self):
        try:
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

            soup = BeautifulSoup(response.text, 'html.parser')

            self._check_ssl(self.url)
            self._check_xss(soup, response.text)
            self._check_csrf(soup)
            self._check_open_redirects(soup)
            self._check_sql_injection_forms(soup)
            self._check_header_security(response.headers)
            self._check_information_disclosure(response.text, response.headers)
            self._check_insecure_cookies(response.headers)

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
            self.vulnerabilities.append({
                "type": "Scanner Error",
                "description": f"Error during scanning: {str(e)}",
                "severity": "high",
                "location": self.url,
                "details": "The scanner encountered an error while processing the website."
            })
            return self.vulnerabilities

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

    def _check_xss(self, soup, html_content):
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for input_field in inputs:
                if input_field.get('type') in ['text', 'search', 'url', 'email', 'tel', None]:
                    self.vulnerabilities.append({
                        "type": "Potential XSS",
                        "description": "Form input field could be vulnerable to XSS",
                        "severity": "high",
                        "location": f"{self.url} - {str(input_field)[:100]}...",
                        "details": "Text input fields without proper sanitization can be vulnerable to Cross-Site Scripting (XSS) attacks. An attacker could inject malicious JavaScript that executes in users' browsers, stealing cookies or performing actions on their behalf."
                    })
                    break

        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and (
                    'document.write' in script.string or 'innerHTML' in script.string or 'eval(' in script.string):
                self.vulnerabilities.append({
                    "type": "Dangerous JavaScript",
                    "description": "Use of potentially unsafe JavaScript functions",
                    "severity": "medium",
                    "location": f"{self.url} - {str(script)[:100]}...",
                    "details": "The page uses JavaScript functions like document.write(), innerHTML, or eval() which can be unsafe when handling user input. These functions can lead to XSS vulnerabilities if they process unvalidated data."
                })
                break

    def _check_csrf(self, soup):
        forms = soup.find_all('form', method=lambda x: x and x.lower() == 'post')
        for form in forms:
            has_csrf_token = False

            inputs = form.find_all('input', type='hidden')
            for input_field in inputs:
                name = input_field.get('name', '').lower()
                if 'csrf' in name or 'token' in name or '_token' in name:
                    has_csrf_token = True
                    break

            if not has_csrf_token:
                self.vulnerabilities.append({
                    "type": "CSRF Vulnerability",
                    "description": "Form lacks CSRF protection",
                    "severity": "high",
                    "location": f"{self.url} - {str(form)[:100]}...",
                    "details": "This form does not appear to include a CSRF token. Without Cross-Site Request Forgery protection, attackers can trick users into submitting malicious requests without their knowledge, potentially leading to account takeover or data modification."
                })

    def _check_open_redirects(self, soup):
        links = soup.find_all('a', href=True)
        redirect_params = ['url', 'redirect', 'next', 'target', 'redir', 'return', 'destination', 'go', 'goto']

        for link in links:
            href = link['href']
            parsed = urlparse(href)
            query = parsed.query

            for param in redirect_params:
                if f"{param}=" in query:
                    self.vulnerabilities.append({
                        "type": "Open Redirect",
                        "description": f"Potential open redirect in link parameter '{param}'",
                        "severity": "medium",
                        "location": f"{self.url} - {href}",
                        "details": "Links with redirect parameters can be manipulated to send users to malicious websites. Attackers could modify these parameters to redirect users to phishing pages that mimic legitimate sites."
                    })
                    break

    def _check_sql_injection_forms(self, soup):
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            if inputs:
                self.vulnerabilities.append({
                    "type": "Potential SQL Injection",
                    "description": "Form inputs might be vulnerable to SQL injection",
                    "severity": "medium",
                    "location": f"{self.url} - {str(form)[:100]}...",
                    "details": "Form submissions without proper input validation and parameterized queries can be vulnerable to SQL injection attacks. This could allow attackers to access, modify, or delete data from databases, or even execute commands on the database server."
                })
                break

    def _check_header_security(self, headers):
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
            }
        }

        for header, info in security_headers.items():
            if header in headers:
                info['missing'] = False

            if info['missing']:
                self.vulnerabilities.append({
                    "type": "Security Header Missing",
                    "description": info['description'],
                    "severity": info['severity'],
                    "location": self.url,
                    "details": info['details']
                })

    def _check_information_disclosure(self, content, headers):
        if 'Server' in headers and headers['Server'] != '':
            self.vulnerabilities.append({
                "type": "Information Disclosure",
                "description": f"Server header discloses software/version: {headers['Server']}",
                "severity": "low",
                "location": self.url,
                "details": "The server is revealing its software and potentially version information. This helps attackers target specific vulnerabilities in the disclosed software versions."
            })

        comment_pattern = re.compile(r'<!--(.+?)-->', re.DOTALL)
        comments = comment_pattern.findall(content)

        for comment in comments:
            comment = comment.strip()
            sensitive_terms = ['password', 'todo', 'fix', 'bug', 'hack', 'workaround', 'temporary', 'secret', 'key',
                               'token', 'api']
            if any(term in comment.lower() for term in sensitive_terms) and len(comment) > 10:
                short_comment = comment[:50] + '...' if len(comment) > 50 else comment
                sanitized_comment = html.escape(short_comment)

                self.vulnerabilities.append({
                    "type": "Information Disclosure",
                    "description": "HTML comment may contain sensitive information",
                    "severity": "medium",
                    "location": self.url,
                    "details": f"HTML comments sometimes contain sensitive information, debugging data, or internal notes that could help attackers. Found comment: '{sanitized_comment}'"
                })
                break

    def _check_insecure_cookies(self, headers):
        if 'Set-Cookie' in headers:
            cookies = headers.getall('Set-Cookie') if hasattr(headers, 'getall') else [headers['Set-Cookie']]

            for cookie in cookies:
                if 'secure' not in cookie.lower():
                    self.vulnerabilities.append({
                        "type": "Insecure Cookie",
                        "description": "Cookie set without Secure flag",
                        "severity": "medium",
                        "location": self.url,
                        "details": "Cookies without the Secure flag can be transmitted over unencrypted HTTP connections, making them vulnerable to interception. The Secure flag ensures cookies are only sent over HTTPS connections."
                    })
                    break

            for cookie in cookies:
                if 'httponly' not in cookie.lower():
                    self.vulnerabilities.append({
                        "type": "Insecure Cookie",
                        "description": "Cookie set without HttpOnly flag",
                        "severity": "medium",
                        "location": self.url,
                        "details": "Cookies without the HttpOnly flag can be accessed by malicious JavaScript. The HttpOnly flag prevents client-side scripts from accessing cookies, providing protection against certain XSS attacks."
                    })
                    break


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
        time.sleep(2.5)

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
