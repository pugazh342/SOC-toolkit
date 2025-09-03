# RedOpsSuite/modules/cookiesnatcher.py
import requests
import time
import logging
import http.cookies # For parsing Set-Cookie headers
from urllib.parse import urlparse
import json

# --- Setup basic logging for standalone execution ---
logger = logging.getLogger(__name__)
logger.propagate = False
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
# --- End logging setup ---

class CookieSnatcher:
    """
    A basic tool for managing, analyzing, and testing HTTP cookies.
    Can load/store cookies and test them in requests.
    """

    def __init__(self, user_agent=None):
        """
        Initializes the CookieSnatcher.

        Args:
            user_agent (str, optional): Custom User-Agent string. If None, uses requests' default.
        """
        self.session = requests.Session()
        if user_agent:
            self.session.headers.update({'User-Agent': user_agent})
        self.captured_cookies = {} # Store cookies: { 'domain/path/name': {attrs} }
        logger.info("CookieSnatcher module initialized.")

    def _parse_set_cookie_header(self, set_cookie_string, source_url):
        """
        Parses a single Set-Cookie header string into a dictionary of attributes.

        Args:
            set_cookie_string (str): The raw Set-Cookie header value.
            source_url (str): The URL from which the cookie was received (for default domain/path).

        Returns:
            dict: A dictionary representing the cookie and its attributes, or None on error.
        """
        try:
            # Use http.cookies.SimpleCookie which handles parsing well
            cookie_obj = http.cookies.SimpleCookie(set_cookie_string)
            # SimpleCookie creates a dict-like object where keys are cookie names
            # and values are Morsel objects containing the cookie data
            for name, morsel in cookie_obj.items():
                cookie_data = {
                    'name': name,
                    'value': morsel.value,
                    'domain': morsel.get('domain') or urlparse(source_url).netloc,
                    'path': morsel.get('path') or '/',
                    'expires': morsel.get('expires'),
                    'max-age': morsel.get('max-age'),
                    'secure': 'Secure' in morsel,
                    'httponly': 'HttpOnly' in morsel,
                    'samesite': morsel.get('samesite'),
                    'source_url': source_url,
                    # Internal key for easy lookup
                    'key': f"{morsel.get('domain') or urlparse(source_url).netloc}{morsel.get('path') or '/'}{name}"
                }
                return cookie_data
        except Exception as e:
            logger.error(f"CookieSnatcher: Error parsing Set-Cookie header '{set_cookie_string[:50]}...': {e}")
        return None

    def add_cookie(self, cookie_dict):
        """
        Adds a cookie dictionary to the internal storage.

        Args:
            cookie_dict (dict): A dictionary containing cookie data.
                               Expected keys: 'name', 'value', 'domain', 'path'.
                               Optional keys: 'expires', 'max-age', 'secure', 'httponly', 'samesite', 'source_url'.
        """
        required_keys = ['name', 'value', 'domain', 'path']
        if not all(key in cookie_dict for key in required_keys):
            logger.error("CookieSnatcher: Provided cookie dictionary is missing required keys (name, value, domain, path).")
            return

        # Create internal key for storage
        key = f"{cookie_dict['domain']}{cookie_dict['path']}{cookie_dict['name']}"
        cookie_dict['key'] = key
        self.captured_cookies[key] = cookie_dict
        logger.debug(f"CookieSnatcher: Added cookie {cookie_dict['name']} for domain {cookie_dict['domain']}.")

    def load_cookies_from_headers(self, headers_dict, source_url=""):
        """
        Loads cookies from a dictionary of HTTP headers (e.g., from a response).

        Args:
            headers_dict (dict): Dictionary of response headers (key: value).
            source_url (str): The URL associated with these headers.
        """
        set_cookie_headers = headers_dict.get('Set-Cookie')
        if set_cookie_headers:
            # Handle case where there might be multiple Set-Cookie headers (list) or a single one (string)
            if isinstance(set_cookie_headers, str):
                set_cookie_headers = [set_cookie_headers]
            elif not isinstance(set_cookie_headers, list):
                 logger.warning(f"CookieSnatcher: Unexpected type for Set-Cookie header: {type(set_cookie_headers)}. Expected str or list.")
                 return

            for set_cookie_header in set_cookie_headers:
                cookie_data = self._parse_set_cookie_header(set_cookie_header, source_url)
                if cookie_data:
                    self.add_cookie(cookie_data)
        else:
            logger.debug("CookieSnatcher: No Set-Cookie header found in provided headers.")

    def load_cookies_from_file(self, filepath):
        """
        Loads cookies from a JSON file.

        Args:
            filepath (str): Path to the JSON file containing a list of cookie dictionaries.
        """
        try:
            with open(filepath, 'r') as f:
                cookies_data = json.load(f)
            if isinstance(cookies_data, list):
                for cookie_dict in cookies_data:
                    self.add_cookie(cookie_dict)
                logger.info(f"CookieSnatcher: Loaded {len(cookies_data)} cookies from file {filepath}.")
            else:
                logger.error(f"CookieSnatcher: Invalid format in {filepath}. Expected a JSON list of cookie objects.")
        except FileNotFoundError:
            logger.error(f"CookieSnatcher: Cookie file not found: {filepath}")
        except json.JSONDecodeError as e:
            logger.error(f"CookieSnatcher: Error decoding JSON from {filepath}: {e}")
        except Exception as e:
            logger.error(f"CookieSnatcher: Unexpected error loading cookies from {filepath}: {e}")

    def save_cookies_to_file(self, filepath):
        """
        Saves all captured cookies to a JSON file.

        Args:
            filepath (str): Path to the output JSON file.
        """
        try:
            cookies_list = list(self.captured_cookies.values())
            with open(filepath, 'w') as f:
                json.dump(cookies_list, f, indent=4)
            logger.info(f"CookieSnatcher: Saved {len(cookies_list)} cookies to file {filepath}.")
        except Exception as e:
            logger.error(f"CookieSnatcher: Error saving cookies to {filepath}: {e}")

    def get_cookies_for_domain(self, domain):
        """
        Retrieves cookies relevant to a specific domain.

        Args:
            domain (str): The target domain (e.g., 'example.com').

        Returns:
            list: A list of cookie dictionaries relevant to the domain.
        """
        matching_cookies = []
        # Basic domain matching (doesn't handle Public Suffix List perfectly,
        # but works for simple cases like example.com matching www.example.com)
        for cookie in self.captured_cookies.values():
            cookie_domain = cookie.get('domain', '')
            # Check if cookie domain is a suffix of the target domain
            # or if the target domain is a suffix of the cookie domain (for .example.com cookies)
            if domain.endswith(cookie_domain) or cookie_domain.endswith(domain) or cookie_domain == domain:
                matching_cookies.append(cookie)
        logger.debug(f"CookieSnatcher: Found {len(matching_cookies)} cookies for domain {domain}.")
        return matching_cookies

    def get_all_cookies(self):
        """Returns a list of all captured cookies."""
        return list(self.captured_cookies.values())

    def clear_cookies(self):
        """Clears the internal cookie storage."""
        self.captured_cookies.clear()
        logger.info("CookieSnatcher: Cleared all captured cookies.")

    def test_cookie_in_request(self, url, cookie_name=None, cookie_value=None, cookie_dict=None, method='GET', additional_headers=None, expected_status_codes=None):
        """
        Sends a request to a URL using a specific cookie or set of cookies to test access/privileges.

        Args:
            url (str): The target URL.
            cookie_name (str, optional): Name of a single cookie to test.
            cookie_value (str, optional): Value of the single cookie to test.
                                         Must be used with `cookie_name`.
            cookie_dict (dict, optional): A dictionary of multiple cookies to send
                                          (e.g., {'sessionid': 'abc123', 'user': 'admin'}).
                                          Ignored if `cookie_name` and `cookie_value` are provided.
            method (str): HTTP method ('GET', 'POST', etc.). Default 'GET'.
            additional_headers (dict, optional): Additional headers to send with the request.
            expected_status_codes (list, optional): List of status codes considered 'successful'. Defaults to [200].

        Returns:
            dict: A dictionary containing the request details, response, and test result.
        """
        if expected_status_codes is None:
            expected_status_codes = [200]

        result = {
            "url": url,
            "method": method.upper(),
            "test_type": "single_cookie" if cookie_name and cookie_value else "multiple_cookies" if cookie_dict else "captured_cookies",
            "cookies_sent": {},
            "request_headers": additional_headers or {},
            "response": {
                "status_code": None,
                "headers": {},
                "body_preview": "",
                "time_elapsed": None
            },
            "indicators": {
                "access_granted": False,
                "status_code_match": False,
                "size_difference": None # Compared to baseline if available (future enhancement)
            },
            "notes": "",
            "error": None
        }

        # Prepare cookies for the request
        cookies_to_send = {}
        if cookie_name and cookie_value:
            cookies_to_send[cookie_name] = cookie_value
            result['test_type'] = "named_cookie"
        elif cookie_dict and isinstance(cookie_dict, dict):
            cookies_to_send.update(cookie_dict)
            result['test_type'] = "provided_dict"
        # Note: Testing captured cookies requires knowing the domain, which isn't directly available here.
        # A user would typically call get_cookies_for_domain first and then pass the result.
        # Or, this function could be modified to accept a domain and fetch relevant cookies automatically.
        # For now, we focus on explicit cookie provision.

        result['cookies_sent'] = cookies_to_send

        try:
            start_time = time.time()
            # Prepare request arguments
            req_kwargs = {
                "url": url,
                "headers": additional_headers,
                "timeout": 30, # Default timeout for test
                "cookies": cookies_to_send # Attach cookies
            }

            # Send request based on method
            if method.upper() == 'GET':
                resp = self.session.get(**req_kwargs)
            elif method.upper() == 'POST':
                # Assume data might be needed for POST, but it's not provided here.
                # The caller can pass data via additional_headers or modify req_kwargs.
                # For simplicity, we'll proceed without data for now.
                resp = self.session.post(**req_kwargs)
            else:
                resp = self.session.request(method.upper(), **req_kwargs)

            end_time = time.time()

            result['response']['status_code'] = resp.status_code
            result['response']['headers'] = dict(resp.headers)
            result['response']['body_preview'] = resp.text[:500] + ("..." if len(resp.text) > 500 else "")
            result['response']['time_elapsed'] = end_time - start_time

            # --- Basic Test Indicator Analysis ---
            # 1. Check if status code matches expected successful codes
            if resp.status_code in expected_status_codes:
                result['indicators']['status_code_match'] = True
                result['indicators']['access_granted'] = True # Preliminary indicator
                result['notes'] += f"Status code {resp.status_code} matched expected success codes {expected_status_codes}. "
                logger.debug(f"CookieSnatcher: Test request to {url} returned status {resp.status_code}.")

            logger.info(f"CookieSnatcher: Tested cookie access to {url} ({method.upper()}). Status: {resp.status_code}. Access Granted (preliminary): {result['indicators']['access_granted']}")

        except requests.exceptions.Timeout:
            result['error'] = "Request timed out"
            logger.warning(f"CookieSnatcher: Request to {url} ({method}) timed out during cookie test.")
        except requests.exceptions.RequestException as e:
            result['error'] = f"Request failed: {str(e)}"
            logger.error(f"CookieSnatcher: Request to {url} ({method}) failed during cookie test: {e}")
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            logger.error(f"CookieSnatcher: Unexpected error testing cookie access to {url} ({method}): {e}", exc_info=True)

        return result

    def analyze_cookies(self):
        """
        Performs basic analysis on captured cookies (e.g., check for missing flags).

        Returns:
            dict: A summary of the analysis.
        """
        if not self.captured_cookies:
            logger.info("CookieSnatcher: No cookies to analyze.")
            return {"summary": "No cookies available for analysis.", "findings": []}

        logger.info("CookieSnatcher: Analyzing captured cookies...")
        findings = []
        total_cookies = len(self.captured_cookies)
        insecure_cookies = []
        httponly_missing = []

        for cookie in self.captured_cookies.values():
            name = cookie.get('name')
            domain = cookie.get('domain')
            path = cookie.get('path')
            secure = cookie.get('secure', False)
            httponly = cookie.get('httponly', False)

            # Check for potentially insecure cookies
            if not secure:
                insecure_cookies.append(cookie)
                findings.append({
                    "type": "missing_secure_flag",
                    "cookie": name,
                    "domain": domain,
                    "path": path,
                    "description": f"Cookie '{name}' is missing the 'Secure' flag, making it potentially vulnerable to theft over HTTP."
                })

            # Check for cookies missing HttpOnly flag (often desired for session tokens)
            if not httponly:
                httponly_missing.append(cookie)
                findings.append({
                    "type": "missing_httponly_flag",
                    "cookie": name,
                    "domain": domain,
                    "path": path,
                    "description": f"Cookie '{name}' is missing the 'HttpOnly' flag, making it accessible to client-side scripts (XSS)."
                })

        summary = {
            "total_cookies": total_cookies,
            "cookies_missing_secure": len(insecure_cookies),
            "cookies_missing_httponly": len(httponly_missing),
        }

        logger.info(f"CookieSnatcher: Cookie analysis complete. Summary: {summary}")
        return {"summary": summary, "findings": findings}


# Example usage (if run directly)
if __name__ == '__main__':
    # Example: Load some mock cookies and test one
    snatcher = CookieSnatcher(user_agent="Mozilla/5.0 (CookieSnatcher Test)")

    # Mock captured cookies (as if loaded from a response or file)
    mock_cookies = [
        {
            "name": "sessionid",
            "value": "abc123xyz",
            "domain": "example.com",
            "path": "/",
            "secure": True,
            "httponly": True,
            "samesite": "Lax",
            "source_url": "https://example.com/login"
        },
        {
            "name": "user_pref",
            "value": "theme_dark",
            "domain": "example.com",
            "path": "/",
            "secure": False, # Missing Secure flag
            "httponly": False, # Missing HttpOnly flag
            "expires": "Wed, 21 Oct 2099 07:28:00 GMT",
            "source_url": "https://example.com/settings"
        },
        {
            "name": "tracking_id",
            "value": "track987",
            "domain": ".example.com", # Valid for subdomains
            "path": "/",
            "secure": True,
            "httponly": False, # Missing HttpOnly flag
            "source_url": "https://www.example.com/"
        }
    ]

    # Add mock cookies
    for cookie in mock_cookies:
        snatcher.add_cookie(cookie)

    print("--- CookieSnatcher Basic Demo ---")
    print(f"Added {len(snatcher.get_all_cookies())} mock cookies.")
    print("-" * 30)

    # Analyze cookies
    analysis = snatcher.analyze_cookies()
    print("\n--- Cookie Analysis ---")
    print(analysis['summary'])
    print("\nFindings:")
    if analysis['findings']:
        for finding in analysis['findings']:
            print(f"- {finding['description']} (Cookie: {finding['cookie']}, Domain: {finding['domain']})")
    else:
        print("No basic security issues found in mock cookies.")

    print("-" * 30)

    # Test a cookie (simulate using the sessionid)
    test_url = "https://example.com/dashboard" # Example protected resource
    session_cookie = next((c for c in snatcher.get_all_cookies() if c['name'] == 'sessionid'), None)
    if session_cookie:
        print(f"\n--- Testing Cookie Access ---")
        print(f"Testing access to {test_url} using cookie: {session_cookie['name']}={session_cookie['value'][:10]}...")
        test_result = snatcher.test_cookie_in_request(
            url=test_url,
            cookie_name=session_cookie['name'],
            cookie_value=session_cookie['value'],
            method='GET',
            expected_status_codes=[200, 302] # 200 OK, 302 Found (redirect)
        )
        print(f"Test Result:")
        print(f"  Status Code: {test_result['response']['status_code']}")
        print(f"  Access Granted (preliminary): {test_result['indicators']['access_granted']}")
        print(f"  Notes: {test_result['notes']}")
        if test_result['error']:
            print(f"  Error: {test_result['error']}")

    print("-" * 30)
    print("CookieSnatcher demo completed.")
