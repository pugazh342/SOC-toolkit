# RedOpsSuite/modules/pathcrawler.py
import requests
import time
import urllib.parse
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

class PathCrawler:
    """
    A basic directory and file discovery tool (DirBuster-like) for RedOpsSuite.
    Performs wordlist-based fuzzing to find hidden web resources.
    """

    def __init__(self, default_timeout=10, max_workers=10, delay=0.1, follow_redirects=False, user_agent=None):
        """
        Initializes the PathCrawler.

        Args:
            default_timeout (int): Default timeout for HTTP requests (seconds). Default 10.
            max_workers (int): Maximum number of concurrent workers for scanning. Default 10.
            delay (float): Delay (in seconds) between requests to be polite/rate-limit aware. Default 0.1.
            follow_redirects (bool): Whether to follow HTTP redirects. Default False.
            user_agent (str, optional): Custom User-Agent string. If None, uses requests' default.
        """
        self.default_timeout = default_timeout
        self.max_workers = max_workers
        self.delay = delay
        self.follow_redirects = follow_redirects
        self.session = requests.Session() # Reuse session for connection pooling
        if user_agent:
            self.session.headers.update({'User-Agent': user_agent})
        self.results = [] # Store crawl results
        self.wordlist = [] # Store loaded wordlist
        logger.info(f"PathCrawler module initialized with timeout={default_timeout}s, max_workers={max_workers}, delay={self.delay}s, follow_redirects={follow_redirects}")

    def _send_crawl_request(self, base_url, path):
        """
        Sends a single HTTP GET request to test a path.

        Args:
            base_url (str): The base target URL (e.g., http://example.com).
            path (str): The path component to append (e.g., /admin, backup.txt).

        Returns:
            dict: A dictionary containing the request details, response, and status.
        """
        # Properly join base URL and path, handling trailing slashes
        # urllib.parse.urljoin is good for this
        full_url = urllib.parse.urljoin(base_url, path)

        result = {
            "url": full_url,
            "status_code": None,
            "response_size": None,
            "location_header": None, # If redirected
            "response_time": None,
            "error": None
        }

        try:
            start_time = time.time()
            # Send GET request
            # Use stream=True to potentially save memory if we only need status/headers
            resp = self.session.get(
                full_url,
                timeout=self.default_timeout,
                allow_redirects=self.follow_redirects,
                stream=True # Important: Don't download the full body unless needed
            )
            end_time = time.time()

            result['status_code'] = resp.status_code
            # Get content length from header first, fallback to len(content) if needed and small
            content_length = resp.headers.get('Content-Length')
            if content_length and content_length.isdigit():
                result['response_size'] = int(content_length)
            else:
                # Only read body if size is small or we need it for other checks
                # For now, we'll leave size as None or approximate if header missing
                # Reading large bodies just for size can be inefficient.
                # resp.content reads the whole thing, resp.raw provides raw stream access
                # Let's stick with header for now.
                result['response_size'] = len(resp.content) if len(resp.content) < 1024 * 10 else ">10KB" # Rough estimate or indicator

            result['response_time'] = end_time - start_time

            # Capture redirect location if applicable
            if resp.is_redirect or resp.is_permanent_redirect:
                result['location_header'] = resp.headers.get('Location')

            # Log the finding
            logger.info(f"PathCrawler: Probed {full_url} -> Status: {resp.status_code}, Size: {result['response_size']}")

            # Consume the response body if streamed to release connection
            # Since we used stream=True, we should read the content or close/raise_for_status
            # If we only care about status/headers, closing is sufficient.
            # resp.close() # Explicitly close if not reading content
            # Or read a small part if needed for checks later
            # content_preview = resp.raw.read(512) # Read first 512 bytes
            # For basic dir crawling, status/headers are usually enough.
            resp.close()

        except requests.exceptions.Timeout:
            result['error'] = "Request timed out"
            logger.warning(f"PathCrawler: Request to {full_url} timed out.")
        except requests.exceptions.TooManyRedirects:
            result['error'] = "Too many redirects"
            logger.warning(f"PathCrawler: Too many redirects for {full_url}.")
        except requests.exceptions.RequestException as e:
            result['error'] = f"Request failed: {str(e)}"
            logger.error(f"PathCrawler: Request to {full_url} failed: {e}")
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            logger.error(f"PathCrawler: Unexpected error probing {full_url}: {e}", exc_info=True)

        # Apply inter-request delay
        if self.delay > 0:
            time.sleep(self.delay)

        return result

    def load_wordlist(self, wordlist_source):
        """
        Loads a wordlist from a file path or a Python list.

        Args:
            wordlist_source (str or list): Path to a wordlist file (one word per line)
                                           or a Python list of words.

        Returns:
            list: The loaded wordlist.
        """
        loaded_list = []
        if isinstance(wordlist_source, str):
            # Assume it's a file path
            try:
                with open(wordlist_source, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        word = line.strip()
                        # Skip empty lines and comments (starting with #)
                        if word and not word.startswith('#'):
                            # Ensure path starts with / for proper URL joining
                            if not word.startswith('/'):
                                word = '/' + word
                            loaded_list.append(word)
                logger.info(f"PathCrawler: Loaded {len(loaded_list)} entries from wordlist file {wordlist_source}.")
            except FileNotFoundError:
                logger.error(f"PathCrawler: Wordlist file not found: {wordlist_source}")
            except Exception as e:
                logger.error(f"PathCrawler: Error reading wordlist file {wordlist_source}: {e}")
        elif isinstance(wordlist_source, list):
            # Assume it's a list of words
            for word in wordlist_source:
                if isinstance(word, str):
                    # Ensure path starts with / for proper URL joining
                    formatted_word = word.strip()
                    if not formatted_word.startswith('/'):
                        formatted_word = '/' + formatted_word
                    loaded_list.append(formatted_word)
            logger.info(f"PathCrawler: Loaded {len(loaded_list)} entries from provided list.")
        else:
            logger.error("PathCrawler: Invalid wordlist source. Must be a file path (str) or a list.")
        self.wordlist = loaded_list
        return loaded_list

    def crawl(self, base_url, wordlist_source=None, extensions=None, status_filter=None):
        """
        Crawls the target URL using the loaded or provided wordlist.

        Args:
            base_url (str): The base target URL (e.g., http://example.com).
            wordlist_source (str or list, optional): Wordlist source. If None, uses `self.wordlist`.
            extensions (list, optional): List of file extensions to append to each word
                                        (e.g., ['.bak', '.old', '.txt']). Default None.
            status_filter (list, optional): List of status codes to consider as findings
                                           (e.g., [200, 403]). If None, reports all.

        Returns:
            list: A list of result dictionaries for discovered paths.
        """
        if wordlist_source:
            wordlist_to_use = self.load_wordlist(wordlist_source)
        else:
            wordlist_to_use = self.wordlist

        if not wordlist_to_use:
            logger.error("PathCrawler: No wordlist loaded. Cannot start crawl.")
            return []

        # Prepare the list of paths to test
        paths_to_test = []
        for word in wordlist_to_use:
            # Add the base word
            paths_to_test.append(word)
            # Add the word with extensions if provided
            if extensions:
                for ext in extensions:
                    # Ensure extension starts with a dot
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    paths_to_test.append(word + ext)

        logger.info(f"PathCrawler: Starting crawl on {base_url} with {len(paths_to_test)} paths (extensions: {extensions}).")
        all_results = []

        # Use ThreadPoolExecutor for concurrency
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit tasks
            future_to_path = {executor.submit(self._send_crawl_request, base_url, path): path for path in paths_to_test}

            # Collect results as they complete
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    # Apply status filter if specified
                    if status_filter is None or result.get('status_code') in status_filter:
                        all_results.append(result)
                except Exception as e:
                    logger.error(f"PathCrawler: Task for path {path} generated an exception: {e}")
                    # Append a result indicating the task failure
                    all_results.append({
                        "url": urllib.parse.urljoin(base_url, path),
                        "status_code": None,
                        "response_size": None,
                        "location_header": None,
                        "response_time": None,
                        "error": f"Task execution failed: {str(e)}"
                    })

        logger.info(f"PathCrawler: Crawl on {base_url} completed. Analyzed {len(paths_to_test)} paths. Found {len(all_results)} potential findings (based on filter).")
        self.results.extend(all_results)
        return all_results

    def analyze_results(self, results=None, sort_by='status_code'):
        """
        Performs basic analysis and sorting of crawl results.

        Args:
            results (list, optional): List of results to analyze. Uses `self.results` if None.
            sort_by (str): Key to sort results by ('status_code', 'response_size', 'url'). Default 'status_code'.

        Returns:
            list: The sorted list of results.
        """
        if results is None:
            results = self.results

        if not results:
            logger.info("PathCrawler: No results to analyze.")
            return []

        logger.info("PathCrawler: Analyzing and sorting crawl results...")
        try:
            # Sort results
            # Handle potential None values in the sort key
            if sort_by == 'status_code':
                sorted_results = sorted(results, key=lambda x: (x.get('status_code') is None, x.get('status_code', 0)))
            elif sort_by == 'response_size':
                sorted_results = sorted(results, key=lambda x: (x.get('response_size') is None, x.get('response_size', 0)))
            elif sort_by == 'url':
                sorted_results = sorted(results, key=lambda x: x.get('url', ''))
            else:
                logger.warning(f"PathCrawler: Unknown sort key '{sort_by}'. Sorting by status_code.")
                sorted_results = sorted(results, key=lambda x: (x.get('status_code') is None, x.get('status_code', 0)))

            logger.info(f"PathCrawler: Analysis and sorting complete. Sorted by '{sort_by}'.")
            return sorted_results
        except Exception as e:
            logger.error(f"PathCrawler: Error during result analysis/sorting: {e}")
            return results # Return unsorted results on error

    def get_results(self):
        """Returns the results from the last crawl run."""
        return self.results

    def clear_results(self):
        """Clears the stored results."""
        self.results = []


# Example usage (if run directly)
# Requires a simple wordlist file for demonstration
if __name__ == '__main__':
    # Example: Crawl a test target
    crawler = PathCrawler(default_timeout=15, max_workers=5, delay=0.2, follow_redirects=False)

    target_url = "http://testphp.vulnweb.com/" # Example target (Deliberately Vulnerable Web App)
    # Simple example wordlist (in practice, use a larger one like SecLists/common.txt)
    example_wordlist = [
        "admin",
        "login",
        "backup",
        "config",
        ".git",
        "robots.txt",
        "sitemap.xml"
    ]
    # Extensions to test
    test_extensions = [".bak", ".old", ".txt", "~"]

    print("--- PathCrawler Basic Test ---")
    print(f"Target URL: {target_url}")
    print(f"Wordlist: {example_wordlist}")
    print(f"Extensions: {test_extensions}")
    print("-" * 30)

    # Run the crawl
    results = crawler.crawl(
        base_url=target_url,
        wordlist_source=example_wordlist,
        extensions=test_extensions,
        status_filter=[200, 301, 302, 401, 403, 500] # Filter interesting statuses
    )

    # Analyze and sort results
    sorted_results = crawler.analyze_results(results, sort_by='status_code')

    print("\n--- Crawl Results ---")
    if sorted_results:
        # Print a simple table
        print(f"{'Status':<8} {'Size':<10} {'URL'}")
        print("-" * 50)
        for result in sorted_results:
            status = result.get('status_code', 'ERR')
            size = result.get('response_size', 'N/A')
            url = result.get('url', 'N/A')
            print(f"{status:<8} {size:<10} {url}")
    else:
        print("No paths found matching the criteria in this basic test.")

    print("-" * 30)
    print("Crawl completed.")
