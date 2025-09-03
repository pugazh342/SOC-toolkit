# RedOpsSuite/modules/injector.py
import requests
import urllib.parse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

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

class Injector:
    """
    A basic payload injection engine for RedOpsSuite.
    Tests for vulnerabilities like XSS, SQLi, LFI by injecting payloads.
    """

    def __init__(self, default_timeout=10, default_delay=0, max_workers=5):
        """
        Initializes the Injector.

        Args:
            default_timeout (int): Default timeout for HTTP requests (seconds). Default 10.
            default_delay (float): Default delay between requests (seconds). Default 0.
            max_workers (int): Maximum number of concurrent workers for scanning. Default 5.
        """
        self.default_timeout = default_timeout
        self.default_delay = default_delay
        self.max_workers = max_workers
        self.session = requests.Session() # Reuse session for connection pooling
        self.results = [] # Store results of injections
        logger.info(f"Injector module initialized with timeout={default_timeout}s, delay={default_delay}s, max_workers={max_workers}")

    def _send_request(self, url, method='GET', params=None, data=None, headers=None, cookies=None, payload="", injection_point=""):
        """
        Sends a single HTTP request with optional payload injection.

        Args:
            url (str): The target URL.
            method (str): HTTP method ('GET', 'POST'). Default 'GET'.
            params (dict): Query parameters (for GET).
            data (dict): Form data (for POST).
            headers (dict): HTTP headers.
            cookies (dict): HTTP cookies.
            payload (str): The payload string to inject.
            injection_point (str): Indicates where the payload was injected ('param:<name>', 'header:<name>', 'cookie:<name>').

        Returns:
            dict: A dictionary containing request details, response, timing, and potential indicators.
        """
        result = {
            "url": url,
            "method": method.upper(),
            "payload": payload,
            "injection_point": injection_point,
            "request": {
                "headers": headers or {},
                "params": params or {},
                "data": data or {}
            },
            "response": {
                "status_code": None,
                "headers": {},
                "body": "",
                "time_elapsed": None
            },
            "indicators": {
                "reflected": False,
                "error_keywords": [],
                "time_delayed": False # Placeholder for time-based checks
            },
            "error": None
        }

        # Inject payload
        # This is a simplified injection. A real one would be more context-aware.
        # For GET params
        if params and injection_point.startswith("param:"):
            param_name = injection_point.split(":", 1)[1]
            if param_name in params:
                params[param_name] = payload
                result['request']['params'] = params # Update in result
        # For POST data
        elif data and injection_point.startswith("param:"):
             param_name = injection_point.split(":", 1)[1]
             if param_name in data:
                 data[param_name] = payload
                 result['request']['data'] = data # Update in result
        # For Headers (basic example)
        elif headers and injection_point.startswith("header:"):
             header_name = injection_point.split(":", 1)[1]
             headers[header_name] = payload
             result['request']['headers'] = headers # Update in result
        # For Cookies (basic example)
        elif cookies and injection_point.startswith("cookie:"):
             cookie_name = injection_point.split(":", 1)[1]
             cookies[cookie_name] = payload
             # Cookies are handled separately in requests

        try:
            start_time = time.time()
            if method.upper() == 'GET':
                resp = self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    cookies=cookies,
                    timeout=self.default_timeout
                )
            elif method.upper() == 'POST':
                resp = self.session.post(
                    url,
                    params=params, # Query params can still be present
                    data=data,
                    headers=headers,
                    cookies=cookies,
                    timeout=self.default_timeout
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            end_time = time.time()
            result['response']['status_code'] = resp.status_code
            result['response']['headers'] = dict(resp.headers)
            result['response']['body'] = resp.text
            result['response']['time_elapsed'] = end_time - start_time

            # --- Basic Indicator Analysis ---
            # 1. Check for payload reflection
            if payload in resp.text:
                result['indicators']['reflected'] = True
                logger.debug(f"Payload reflected in response for {url} with payload '{payload[:50]}...'")

            # 2. Check for common error keywords (very basic)
            error_keywords = ['sql syntax', 'mysql', 'postgresql', 'oracle', 'microsoft odbc', 'unclosed quotation mark']
            lower_body = resp.text.lower()
            found_errors = [kw for kw in error_keywords if kw in lower_body]
            if found_errors:
                result['indicators']['error_keywords'] = found_errors
                logger.debug(f"Error keywords found for {url}: {found_errors}")

            # 3. Check for time delay (basic placeholder)
            # A real implementation would compare expected vs actual time for time-based payloads
            # if result['response']['time_elapsed'] > (self.default_timeout * 0.8): # Arbitrary threshold
            #     result['indicators']['time_delayed'] = True
            #     logger.debug(f"Possibly time-delayed response for {url} (took {result['response']['time_elapsed']:.2f}s)")

            logger.info(f"Injected payload to {method.upper()} {url} ({injection_point}). Status: {resp.status_code}")
        except requests.exceptions.Timeout:
            result['error'] = "Request timed out"
            logger.warning(f"Request to {url} timed out.")
        except requests.exceptions.RequestException as e:
            result['error'] = f"Request failed: {str(e)}"
            logger.error(f"Request to {url} failed: {e}")
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            logger.error(f"Unexpected error injecting to {url}: {e}", exc_info=True)

        return result

    def inject_payloads(self, base_url, payloads, injection_points, method='GET', params=None, data=None, headers=None, cookies=None):
        """
        Injects a list of payloads into specified injection points and sends requests.

        Args:
            base_url (str): The base target URL.
            payloads (list): A list of payload strings to inject.
            injection_points (list): A list of injection point identifiers (e.g., ['param:id', 'header:User-Agent']).
            method (str): HTTP method ('GET', 'POST'). Default 'GET'.
            params (dict, optional): Base query parameters.
            data (dict, optional): Base form data for POST.
            headers (dict, optional): Base HTTP headers.
            cookies (dict, optional): Base HTTP cookies.

        Returns:
            list: A list of result dictionaries for each injection attempt.
        """
        logger.info(f"Injector: Starting injection scan on {base_url} with {len(payloads)} payloads and {len(injection_points)} injection points.")
        all_results = []

        # Use ThreadPoolExecutor for concurrency
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit tasks
            future_to_task = {}
            for payload in payloads:
                for inj_point in injection_points:
                    # Submit a task for each payload/injection point combination
                    future = executor.submit(
                        self._send_request,
                        base_url,
                        method,
                        params.copy() if params else None, # Pass copies to avoid mutation issues
                        data.copy() if data else None,
                        headers.copy() if headers else None,
                        cookies.copy() if cookies else None,
                        payload,
                        inj_point
                    )
                    task_desc = f"{inj_point} -> '{payload[:30]}...'" if len(payload) > 30 else f"{inj_point} -> '{payload}'"
                    future_to_task[future] = task_desc

            # Collect results as they complete
            for future in as_completed(future_to_task):
                task_desc = future_to_task[future]
                try:
                    result = future.result()
                    all_results.append(result)
                    # Optional: Add a small delay between requests submitted by the pool
                    if self.default_delay > 0:
                        time.sleep(self.default_delay)
                except Exception as e:
                    logger.error(f"Injector: Task {task_desc} generated an exception: {e}")
                    # Append a result indicating the task failure
                    all_results.append({
                        "url": base_url,
                        "method": method,
                        "payload": "N/A (Task Error)",
                        "injection_point": "N/A (Task Error)",
                        "error": f"Task execution failed: {str(e)}",
                        "response": {},
                        "indicators": {}
                    })

        logger.info(f"Injector: Injection scan on {base_url} completed. Analyzed {len(all_results)} injection points.")
        self.results.extend(all_results)
        return all_results

    def load_payloads_from_list(self, payload_list):
        """
        Loads payloads from a provided Python list.

        Args:
            payload_list (list): A list of payload strings.

        Returns:
            list: The provided list of payloads.
        """
        logger.info(f"Injector: Loaded {len(payload_list)} payloads from list.")
        return payload_list

    def load_payloads_from_file(self, filepath):
        """
        Loads payloads from a text file (one payload per line).

        Args:
            filepath (str): Path to the payload file.

        Returns:
            list: A list of payload strings.
        """
        payloads = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    payload = line.strip()
                    if payload and not payload.startswith('#'): # Skip empty lines and comments
                        payloads.append(payload)
            logger.info(f"Injector: Loaded {len(payloads)} payloads from file {filepath}.")
        except FileNotFoundError:
            logger.error(f"Injector: Payload file not found: {filepath}")
        except Exception as e:
            logger.error(f"Injector: Error reading payload file {filepath}: {e}")
        return payloads

    def analyze_results(self, results=None):
        """
        Performs a basic analysis of injection results to highlight potential findings.

        Args:
            results (list, optional): List of results to analyze. Uses `self.results` if None.

        Returns:
            dict: A summary of the analysis.
        """
        if results is None:
            results = self.results

        if not results:
            logger.info("Injector: No results to analyze.")
            return {"summary": "No results available.", "findings": []}

        logger.info("Injector: Analyzing injection results...")
        findings = []
        total_requests = len(results)
        reflected_count = sum(1 for r in results if r.get('indicators', {}).get('reflected'))
        error_count = sum(1 for r in results if r.get('indicators', {}).get('error_keywords'))

        summary = {
            "total_requests": total_requests,
            "reflected_payloads": reflected_count,
            "responses_with_errors": error_count
        }

        # Flag results with interesting indicators
        for result in results:
            if result.get('indicators', {}).get('reflected') or result.get('indicators', {}).get('error_keywords'):
                findings.append(result)

        logger.info(f"Injector: Analysis complete. Summary: {summary}")
        return {"summary": summary, "findings": findings}

    def get_results(self):
        """Returns the results from the last injection run."""
        return self.results

    def clear_results(self):
        """Clears the stored results."""
        self.results = []


# Example usage (if run directly)
if __name__ == '__main__':
    # Example: Test a simple GET parameter for XSS
    injector = Injector(default_timeout=15, max_workers=3) # Slower timeout, fewer workers for example

    target_url = "http://testphp.vulnweb.com/search.php" # Example target (Deliberately Vulnerable Web App)
    # Payloads (XSS examples)
    test_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        # Add more payloads as needed
    ]
    # Injection points (GET parameter 'test')
    test_injection_points = ["param:test"]

    print("--- Injector Basic XSS Test ---")
    print(f"Target URL: {target_url}")
    print(f"Payloads: {test_payloads}")
    print(f"Injection Points: {test_injection_points}")
    print("-" * 30)

    # Run the injection
    results = injector.inject_payloads(
        base_url=target_url,
        payloads=test_payloads,
        injection_points=test_injection_points,
        method='GET',
        params={"test": "initial_value"} # Base param that will be overwritten
    )

    # Analyze results
    analysis = injector.analyze_results(results)
    print("\n--- Analysis Summary ---")
    print(analysis['summary'])
    print("\n--- Potential Findings ---")
    if analysis['findings']:
        for finding in analysis['findings']:
            print(f"URL: {finding['url']}")
            print(f"Method: {finding['method']}")
            print(f"Payload: {finding['payload']}")
            print(f"Injection Point: {finding['injection_point']}")
            print(f"Reflected: {finding['indicators'].get('reflected', False)}")
            print(f"Error Keywords: {finding['indicators'].get('error_keywords', [])}")
            print(f"Status Code: {finding['response'].get('status_code', 'N/A')}")
            print("-" * 20)
    else:
        print("No obvious indicators of vulnerability found in this basic test.")
