# RedOpsSuite/modules/bypasser.py
import requests
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import product

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

class Bypasser:
    """
    A basic bypass testing tool for RedOpsSuite.
    Tests for common bypass techniques like default credentials and method tampering.
    """

    def __init__(self, default_timeout=10, max_workers=5, delay=0.1):
        """
        Initializes the Bypasser.

        Args:
            default_timeout (int): Default timeout for HTTP requests (seconds). Default 10.
            max_workers (int): Maximum number of concurrent workers for scanning. Default 5.
            delay (float): Delay (in seconds) between requests to be polite/rate-limit aware. Default 0.1.
        """
        self.default_timeout = default_timeout
        self.max_workers = max_workers
        self.delay = delay
        self.session = requests.Session() # Reuse session for connection pooling
        self.results = [] # Store results of bypass attempts
        logger.info(f"Bypasser module initialized with timeout={default_timeout}s, max_workers={max_workers}, delay={self.delay}s")

    def _send_bypass_request(self, url, method='GET', auth=None, headers=None, data=None, expected_status_codes=None):
        """
        Sends a single HTTP request for bypass testing.

        Args:
            url (str): The target URL.
            method (str): HTTP method to use.
            auth (tuple, optional): Authentication tuple (user, pass).
            headers (dict, optional): HTTP headers to send.
            data (dict, optional): Data to send in the request body.
            expected_status_codes (list, optional): List of status codes considered 'successful'. Defaults to [200].

        Returns:
            dict: A dictionary containing request details, response, and potential bypass indicators.
        """
        if expected_status_codes is None:
            expected_status_codes = [200]

        result = {
            "url": url,
            "method": method.upper(),
            "auth": auth,
            "headers": headers or {},
            "data": data or {},
            "request_sent": False,
            "response": {
                "status_code": None,
                "headers": {},
                "body_preview": "", # Preview only
                "time_elapsed": None
            },
            "indicators": {
                "bypass_success": False,
                "status_code_match": False,
                "size_difference": None, # Compared to baseline if available (future enhancement)
                "redirect_occurred": False
            },
            "notes": "",
            "error": None
        }

        try:
            start_time = time.time()
            # Prepare request arguments
            req_kwargs = {
                "url": url,
                "headers": headers,
                "timeout": self.default_timeout,
                "allow_redirects": True # Follow redirects to see final destination
            }
            if auth:
                req_kwargs["auth"] = auth
            if data is not None:
                req_kwargs["data"] = data

            # Send request based on method
            if method.upper() == 'GET':
                resp = self.session.get(**req_kwargs)
            elif method.upper() == 'POST':
                resp = self.session.post(**req_kwargs)
            elif method.upper() == 'PUT':
                resp = self.session.put(**req_kwargs)
            elif method.upper() == 'DELETE':
                resp = self.session.delete(**req_kwargs)
            elif method.upper() == 'HEAD':
                resp = self.session.head(**req_kwargs)
            elif method.upper() == 'OPTIONS':
                resp = self.session.options(**req_kwargs)
            else:
                # For less common methods, use requests.request
                resp = self.session.request(method.upper(), **req_kwargs)

            end_time = time.time()

            result['request_sent'] = True
            result['response']['status_code'] = resp.status_code
            result['response']['headers'] = dict(resp.headers)
            # Preview body (first 500 chars)
            result['response']['body_preview'] = resp.text[:500] + ("..." if len(resp.text) > 500 else "")
            result['response']['time_elapsed'] = end_time - start_time

            # --- Basic Bypass Indicator Analysis ---
            # 1. Check if status code matches expected successful codes
            if resp.status_code in expected_status_codes:
                result['indicators']['status_code_match'] = True
                result['indicators']['bypass_success'] = True # Preliminary indicator
                result['notes'] += f"Status code {resp.status_code} matched expected success codes {expected_status_codes}. "
                logger.debug(f"Bypasser: Request {method.upper()} {url} returned status {resp.status_code}.")

            # 2. Check for redirects (simple check)
            # This is a very basic check. A more robust one would compare the final URL.
            if len(resp.history) > 0:
                 result['indicators']['redirect_occurred'] = True
                 result['notes'] += f"Redirect(s) occurred (final status: {resp.status_code}). "
                 logger.debug(f"Bypasser: Redirect(s) detected for {method.upper()} {url}.")

            # 3. Size Difference (Placeholder - needs baseline)
            # result['indicators']['size_difference'] = len(resp.content) - baseline_size

            logger.info(f"Bypasser: Tested {method.upper()} {url}. Status: {resp.status_code}. Bypass Success (preliminary): {result['indicators']['bypass_success']}")

        except requests.exceptions.Timeout:
            result['error'] = "Request timed out"
            result['request_sent'] = True # Request was attempted
            logger.warning(f"Bypasser: Request to {url} ({method}) timed out.")
        except requests.exceptions.RequestException as e:
            result['error'] = f"Request failed: {str(e)}"
            result['request_sent'] = True # Request was attempted
            logger.error(f"Bypasser: Request to {url} ({method}) failed: {e}")
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            logger.error(f"Bypasser: Unexpected error testing {url} ({method}): {e}", exc_info=True)

        # Apply inter-request delay
        if self.delay > 0:
            time.sleep(self.delay)

        return result

    def test_default_credentials(self, base_url, credentials_list, paths=None, methods=None, expected_status_codes=None):
        """
        Tests a list of default credentials against a target URL/path(s).

        Args:
            base_url (str): The base target URL (e.g., http://target.com).
            credentials_list (list): A list of tuples (username, password).
            paths (list, optional): Specific paths to test (e.g., ['/login', '/admin']).
                                     If None, defaults to [''] (the base URL itself).
            methods (list, optional): HTTP methods to test (e.g., ['GET', 'POST']).
                                      If None, defaults to ['POST'] (common for logins).
            expected_status_codes (list, optional): List of status codes considered 'successful'. Defaults to [200].

        Returns:
            list: A list of result dictionaries for each credential/method/path combination tested.
        """
        if paths is None:
            paths = ['']
        if methods is None:
            methods = ['POST'] # Default for login forms
        if expected_status_codes is None:
            expected_status_codes = [200]

        logger.info(f"Bypasser: Starting default credential test on {base_url} with {len(credentials_list)} credential(s), paths {paths}, methods {methods}.")
        all_results = []

        # Generate all combinations of credentials, paths, and methods
        test_combinations = list(product(credentials_list, paths, methods))
        total_tests = len(test_combinations)
        logger.debug(f"Bypasser: Generated {total_tests} test combinations.")

        # Use ThreadPoolExecutor for concurrency (respecting max_workers)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit tasks
            future_to_desc = {}
            for cred_tuple, path, method in test_combinations:
                username, password = cred_tuple
                full_url = base_url.rstrip('/') + '/' + path.lstrip('/')
                desc = f"{method} {full_url} [{username}:{password}]"

                # For login forms (POST), data is usually in the body.
                # For HTTP Basic Auth (any method), it's in the auth tuple.
                # This example focuses on form-based logins (POST data).
                # You could add logic to differentiate based on method/path if needed.
                data = {"username": username, "password": password} # Simplified assumption
                # For HTTP Basic Auth, you would pass auth=(username, password) instead of data

                future = executor.submit(
                    self._send_bypass_request,
                    full_url,
                    method=method,
                    auth=None, # Assuming form data, not Basic Auth for now
                    headers=None,
                    data=data,
                    expected_status_codes=expected_status_codes
                )
                future_to_desc[future] = desc

            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_desc):
                desc = future_to_desc[future]
                completed += 1
                try:
                    result = future.result()
                    all_results.append(result)
                    logger.debug(f"Bypasser: Completed test ({completed}/{total_tests}): {desc}")
                except Exception as e:
                    logger.error(f"Bypasser: Task {desc} generated an exception: {e}")
                    # Append a result indicating the task failure
                    all_results.append({
                        "url": "N/A (Task Error)",
                        "method": "N/A (Task Error)",
                        "auth": None,
                        "headers": {},
                        "data": {},
                        "request_sent": False,
                        "response": {},
                        "indicators": {"bypass_success": False},
                        "notes": "",
                        "error": f"Task execution failed: {str(e)}"
                    })

        logger.info(f"Bypasser: Default credential test on {base_url} completed. Analyzed {len(all_results)} combinations.")
        self.results.extend(all_results)
        return all_results

    def test_method_tampering(self, base_url, base_method='GET', base_data=None, base_headers=None, methods_to_test=None, expected_status_codes=None):
        """
        Tests different HTTP methods against a target URL to check for access control bypasses.

        Args:
            base_url (str): The target URL.
            base_method (str): The baseline method used for comparison (e.g., 'GET', 'POST').
                               The test methods will be applied to the same URL/endpoint.
            base_data (dict, optional): Baseline data to send with the base request.
            base_headers (dict, optional): Baseline headers for the base request.
            methods_to_test (list, optional): List of HTTP methods to test.
                                               If None, defaults to common methods.
            expected_status_codes (list, optional): List of status codes considered 'successful'. Defaults to [200].

        Returns:
            list: A list of result dictionaries for each method tested.
        """
        if methods_to_test is None:
            # Common methods to test for tampering
            methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        # Remove the base method from the list to avoid redundant test
        methods_to_test = [m for m in methods_to_test if m.upper() != base_method.upper()]

        if expected_status_codes is None:
            expected_status_codes = [200]

        logger.info(f"Bypasser: Starting HTTP method tampering test on {base_url}. Base method: {base_method}. Testing methods: {methods_to_test}.")
        all_results = []

        # --- 1. Send baseline request ---
        logger.debug(f"Bypasser: Sending baseline {base_method} request to {base_url}.")
        baseline_result = self._send_bypass_request(
            base_url,
            method=base_method,
            headers=base_headers,
            data=base_data,
            expected_status_codes=expected_status_codes
        )
        baseline_status = baseline_result['response'].get('status_code')
        baseline_body_preview = baseline_result['response'].get('body_preview', '')
        logger.debug(f"Bypasser: Baseline {base_method} request result - Status: {baseline_status}")

        # --- 2. Test other methods ---
        logger.debug(f"Bypasser: Testing {len(methods_to_test)} alternative methods.")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_method = {}
            for method in methods_to_test:
                future = executor.submit(
                    self._send_bypass_request,
                    base_url,
                    method=method,
                    headers=base_headers,
                    data=base_data, # Send same data with different methods
                    expected_status_codes=expected_status_codes
                )
                future_to_method[future] = method

            # Collect results
            for future in as_completed(future_to_method):
                method = future_to_method[future]
                try:
                    result = future.result()
                    # Compare result to baseline for enhanced analysis (basic)
                    result_status = result['response'].get('status_code')
                    result_body_preview = result['response'].get('body_preview', '')

                    # Simple comparison: Different status code might indicate bypass
                    # Same status but different body might also be interesting
                    # This is a very basic heuristic.
                    if baseline_status is not None:
                        if result_status != baseline_status:
                            result['indicators']['bypass_success'] = True
                            result['notes'] += f"Different status code ({result_status}) compared to baseline ({baseline_status}). "
                            logger.debug(f"Bypasser: Potential bypass found for method {method} (Status: {result_status} vs Baseline: {baseline_status}).")
                        # elif result_body_preview != baseline_body_preview: # This comparison is very rough
                        #     result['notes'] += f"Same status ({result_status}) but body preview differs from baseline. "
                        #     logger.debug(f"Bypasser: Method {method} returned same status but different body preview.")

                    all_results.append(result)
                except Exception as e:
                    logger.error(f"Bypasser: Method tampering task for {method} generated an exception: {e}")
                    all_results.append({
                        "url": base_url,
                        "method": method,
                        "auth": None,
                        "headers": base_headers or {},
                        "data": base_data or {},
                        "request_sent": False,
                        "response": {},
                        "indicators": {"bypass_success": False},
                        "notes": "",
                        "error": f"Method tampering task execution failed: {str(e)}"
                    })

        logger.info(f"Bypasser: HTTP method tampering test on {base_url} completed.")
        self.results.extend(all_results)
        # Also include the baseline result in the overall results for context
        self.results.append(baseline_result)
        return all_results # Return only the test results, not the baseline

    def analyze_results(self, results=None):
        """
        Performs a basic analysis of bypass test results to highlight potential successes.

        Args:
            results (list, optional): List of results to analyze. Uses `self.results` if None.

        Returns:
            dict: A summary of the analysis.
        """
        if results is None:
            results = self.results

        if not results:
            logger.info("Bypasser: No results to analyze.")
            return {"summary": "No results available.", "findings": []}

        logger.info("Bypasser: Analyzing bypass test results...")
        findings = []
        total_tests = len(results)
        # Count successful bypass indicators
        bypass_success_count = sum(1 for r in results if r.get('indicators', {}).get('bypass_success'))

        summary = {
            "total_tests": total_tests,
            "potential_bypasses": bypass_success_count,
        }

        # Flag results with positive bypass indicators
        for result in results:
            if result.get('indicators', {}).get('bypass_success'):
                findings.append(result)

        logger.info(f"Bypasser: Analysis complete. Summary: {summary}")
        return {"summary": summary, "findings": findings}

    def get_results(self):
        """Returns the results from the last bypass run."""
        return self.results

    def clear_results(self):
        """Clears the stored results."""
        self.results = []


# Example usage (if run directly)
if __name__ == '__main__':
    # Example: Test default credentials on a hypothetical login page
    # Note: Running this against real targets without permission is illegal.
    # This uses a non-existent example URL.
    bypasser = Bypasser(default_timeout=15, max_workers=3, delay=0.2) # Slower, fewer workers, polite delay

    target_url = "http://nonexistent-target.com/login" # Example target
    # Common default credentials (example list)
    default_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("administrator", "password"),
        ("user", "user"),
        # Add more from a comprehensive default password list
    ]
    test_paths = ["", "/login", "/admin"] # Paths to test
    test_methods = ["POST"] # Methods to test

    print("--- Bypasser Default Credential Test ---")
    print(f"Target URL: {target_url}")
    print(f"Credentials to test: {default_creds[:3]}... (showing first 3)") # Truncate for display
    print(f"Paths: {test_paths}")
    print(f"Methods: {test_methods}")
    print("-" * 30)

    # Run the default credential test
    dc_results = bypasser.test_default_credentials(
        base_url=target_url,
        credentials_list=default_creds,
        paths=test_paths,
        methods=test_methods,
        expected_status_codes=[200, 302] # 200 OK, 302 Found (redirect after login)
    )

    # Analyze results
    dc_analysis = bypasser.analyze_results(dc_results)
    print("\n--- Default Credential Test Analysis Summary ---")
    print(dc_analysis['summary'])
    print("\n--- Potential Default Credential Bypasses ---")
    if dc_analysis['findings']:
        for finding in dc_analysis['findings']:
            print(f"URL: {finding['url']}")
            print(f"Method: {finding['method']}")
            print(f"Data Sent: {finding['data']}")
            print(f"Status Code: {finding['response'].get('status_code', 'N/A')}")
            print(f"Notes: {finding['notes']}")
            print("-" * 20)
    else:
        print("No obvious default credential bypasses found in this basic test.")

    print("\n" + "="*50 + "\n")

    # Example: Test HTTP method tampering
    tamper_url = "http://nonexistent-target.com/api/resource"
    base_method = "GET"
    print("--- Bypasser HTTP Method Tampering Test ---")
    print(f"Target URL: {tamper_url}")
    print(f"Base Method: {base_method}")
    print("-" * 30)

    # Run the method tampering test
    mt_results = bypasser.test_method_tampering(
        base_url=tamper_url,
        base_method=base_method,
        methods_to_test=['POST', 'PUT', 'DELETE', 'OPTIONS'],
        expected_status_codes=[200, 405] # 200 OK, 405 Method Not Allowed (interesting to compare)
    )

    # Analyze results
    mt_analysis = bypasser.analyze_results(mt_results)
    print("\n--- HTTP Method Tampering Test Analysis Summary ---")
    print(mt_analysis['summary'])
    print("\n--- Potential Method Tampering Bypasses ---")
    if mt_analysis['findings']:
        for finding in mt_analysis['findings']:
            print(f"URL: {finding['url']}")
            print(f"Method Tested: {finding['method']}")
            print(f"Status Code: {finding['response'].get('status_code', 'N/A')}")
            print(f"Notes: {finding['notes']}")
            print("-" * 20)
    else:
        print("No obvious method tampering bypasses found in this basic test.")
