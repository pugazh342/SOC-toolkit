# BlueDefenderX/webgui/tabs_controller_redops.py
import streamlit as st
import pandas as pd
import json
import os
# Import RedOpsSuite modules from st.session_state if needed within tabs
# They are already initialized in app.py if available.

def render_recon_tab():
    """Renders the Reconnaissance tab for RedOpsSuite."""
    st.header("📡 Reconnaissance (ReconX)")
    st.markdown("""
    Perform information gathering tasks like DNS lookups, Whois queries, and port scans.
    """)

    # Access the initialized ReconX instance from session state
    if 'recon_tool' in st.session_state:
        recon = st.session_state.recon_tool

        target = st.text_input("Enter target (domain or IP):", value="example.com")
        task = st.selectbox("Select Recon Task:", ["Basic Recon", "DNS Lookup", "Whois Lookup", "Port Scan (Basic)"])

        if st.button("Start Recon"):
            if target:
                with st.spinner(f"Running {task} on {target}..."):
                    try:
                        if task == "Basic Recon":
                            results = recon.run_basic_recon(target)
                            st.session_state.redops_recon_results = results
                            st.success(f"Basic recon on {target} completed.")
                        elif task == "DNS Lookup":
                            # Assuming ReconX has a resolve_domain method
                            result = recon.resolve_domain(target)
                            st.session_state.redops_recon_results = [result] # Store as list for consistency
                            st.success(f"DNS lookup for {target} completed.")
                        elif task == "Whois Lookup":
                            # Assuming ReconX has a whois_lookup method
                            result = recon.whois_lookup(target)
                            st.session_state.redops_recon_results = [result]
                            st.success(f"Whois lookup for {target} completed.")
                        elif task == "Port Scan (Basic)":
                             st.info("Basic port scan placeholder. This would use a simple connect scan.")
                             # Placeholder for port scan logic
                             # You could integrate a basic scanner or call nmap if available
                             st.session_state.redops_recon_results = [{"type": "port_scan", "target": target, "status": "placeholder", "open_ports": ["22", "80", "443"]}]
                             st.success("Basic port scan (placeholder) completed.")

                    except Exception as e:
                        st.error(f"An error occurred during recon: {e}")
                        st.session_state.redops_recon_results = []
            else:
                st.warning("Please enter a target.")

        # Display results if available
        if 'redops_recon_results' in st.session_state and st.session_state.redops_recon_results:
            st.subheader("Recon Results")
            results = st.session_state.redops_recon_results
            for result in results:
                # Display result in an expander or card-like structure
                result_type = result.get('type', 'Unknown')
                result_target = result.get('target', 'N/A')
                with st.expander(f"{result_type.replace('_', ' ').title()} - {result_target}"):
                    # Use st.json for complex nested data, or st.write/st.markdown for simpler display
                    st.json(result) # Shows full result details

    else:
        st.error("ReconX module is not available. Please check initialization logs.")
        # This case should ideally not happen if REDOPS_AVAILABLE check passes in app.py


def render_injector_tab():
    """Renders the Payload Injection tab for RedOpsSuite."""
    st.header("💉 Payload Injection (Injector)")
    st.markdown("""
    Test for vulnerabilities like XSS, SQLi by injecting payloads.
    """)

    if 'injector_tool' in st.session_state:
        injector = st.session_state.injector_tool

        target_url = st.text_input("Target URL (with parameter):", value="http://testphp.vulnweb.com/search.php?test=query")
        # Example: http://testphp.vulnweb.com/search.php?test=query
        # The 'test' parameter will be the injection point

        # Simple payload input for demo
        payloads_input = st.text_area("Payloads (one per line):", value="<script>alert('XSS')</script>\njavascript:alert(1)")
        payloads = [p.strip() for p in payloads_input.split('\n') if p.strip()]

        # Simple injection point specification
        injection_points_input = st.text_area("Injection Points (e.g., param:test, header:User-Agent):", value="param:test")
        injection_points = [ip.strip() for ip in injection_points_input.split('\n') if ip.strip()]

        method = st.selectbox("HTTP Method:", ["GET", "POST"])

        # Basic parameter extraction for GET/POST
        parsed_url = st.experimental_get_query_params() # Gets query params from current URL in browser, not target URL
        # For simplicity in demo, we'll assume the user knows the param name or uses 'param:param_name'
        # A full implementation would parse the target URL and allow selecting params or specifying custom ones.

        if st.button("Inject Payloads"):
            if target_url and payloads and injection_points:
                with st.spinner("Injecting payloads..."):
                    try:
                        # Parse target URL to get base and params if needed for GET
                        from urllib.parse import urlparse, parse_qs
                        parsed_target = urlparse(target_url)
                        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}{parsed_target.path}"
                        initial_params = parse_qs(parsed_target.query) # This gets dict like {'test': ['value']}
                        # Flatten params for injector (injector expects a dict like {'test': 'value'})
                        flat_params = {k: v[0] if v else '' for k, v in initial_params.items()}

                        # For POST data, we need a separate input or assume it's part of the injection point logic
                        # Let's keep it simple for now, assume GET params are handled via injection points like 'param:test'
                        # and POST data is handled if method is POST and injection point is 'param:something'

                        results = injector.inject_payloads(
                            base_url=base_url,
                            payloads=payloads,
                            injection_points=injection_points,
                            method=method,
                            params=flat_params if method.upper() == 'GET' else None,
                            data=flat_params if method.upper() == 'POST' else None, # Simplification
                            # headers={}, cookies={} # Add if needed
                        )
                        st.session_state.redops_injector_results = results
                        st.success("Payload injection completed.")
                    except Exception as e:
                        st.error(f"An error occurred during injection: {e}")
                        st.session_state.redops_injector_results = []
            else:
                st.warning("Please provide Target URL, Payloads, and Injection Points.")

        # Display results
        if 'redops_injector_results' in st.session_state and st.session_state.redops_injector_results:
            st.subheader("Injection Results")
            results = st.session_state.redops_injector_results
            # Analyze results
            analysis = injector.analyze_results(results)
            st.write("**Analysis Summary:**")
            st.json(analysis['summary'])

            st.write("**Findings (Potential Vulnerabilities):**")
            if analysis['findings']:
                for finding in analysis['findings']:
                    st.write(f"- **URL:** {finding['url']}")
                    st.write(f"  - **Method:** {finding['method']}")
                    st.write(f"  - **Payload:** {finding['payload']}")
                    st.write(f"  - **Injection Point:** {finding['injection_point']}")
                    st.write(f"  - **Reflected:** {finding['indicators'].get('reflected', False)}")
                    st.write(f"  - **Error Keywords:** {finding['indicators'].get('error_keywords', [])}")
                    st.markdown("---")
            else:
                st.info("No obvious indicators of vulnerability found in this scan.")

    else:
        st.error("Injector module is not available. Please check initialization logs.")


def render_bypasser_tab():
    """Renders the Auth & Path Bypass tab for RedOpsSuite."""
    st.header("🛡️ Auth & Path Bypass (Bypasser)")
    st.markdown("""
    Test for authentication bypasses and path traversal vulnerabilities.
    """)

    if 'bypasser_tool' in st.session_state:
        bypasser = st.session_state.bypasser_tool

        target_url = st.text_input("Target URL (e.g., login page):", value="http://testphp.vulnweb.com/login")
        test_type = st.selectbox("Test Type:", ["Default Credentials", "Method Tampering"])

        if test_type == "Default Credentials":
            # Example default credentials list (should be loaded from a file in reality)
            default_creds_input = st.text_area(
                "Default Credentials (user:pass, one per line):",
                value="admin:admin\nadmin:password\nroot:root\nadministrator:password\nuser:user"
            )
            credentials_list = []
            for line in default_creds_input.split('\n'):
                if ':' in line:
                    user, passwd = line.strip().split(':', 1)
                    credentials_list.append((user, passwd))

            paths_to_test = st.text_input("Paths to Test (comma-separated):", value="/login,/admin").split(',')
            paths_to_test = [p.strip() for p in paths_to_test if p.strip()]
            methods_to_test = st.multiselect("HTTP Methods to Test:", ["GET", "POST", "PUT", "DELETE"], default=["POST"])

            if st.button("Test Default Credentials"):
                if target_url and credentials_list:
                    with st.spinner("Testing default credentials..."):
                        try:
                            results = bypasser.test_default_credentials(
                                base_url=target_url,
                                credentials_list=credentials_list,
                                paths=paths_to_test,
                                methods=methods_to_test
                            )
                            st.session_state.redops_bypasser_results = results
                            st.success("Default credential test completed.")
                        except Exception as e:
                            st.error(f"An error occurred: {e}")
                            st.session_state.redops_bypasser_results = []
                else:
                    st.warning("Please provide a Target URL and at least one credential.")

        elif test_type == "Method Tampering":
            base_method = st.selectbox("Base Method (for comparison):", ["GET", "POST"], index=1) # Default POST
            methods_to_test = st.multiselect(
                "Methods to Test:",
                ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
                default=["GET", "PUT", "DELETE"]
            )

            if st.button("Test Method Tampering"):
                if target_url:
                    with st.spinner("Testing HTTP method tampering..."):
                        try:
                            results = bypasser.test_method_tampering(
                                base_url=target_url,
                                base_method=base_method,
                                methods_to_test=methods_to_test
                            )
                            st.session_state.redops_bypasser_results = results
                            st.success("HTTP method tampering test completed.")
                        except Exception as e:
                            st.error(f"An error occurred: {e}")
                            st.session_state.redops_bypasser_results = []
                else:
                    st.warning("Please provide a Target URL.")

        # Display results
        if 'redops_bypasser_results' in st.session_state and st.session_state.redops_bypasser_results:
            st.subheader("Bypass Test Results")
            results = st.session_state.redops_bypasser_results
            # Analyze results
            analysis = bypasser.analyze_results(results)
            st.write("**Analysis Summary:**")
            st.json(analysis['summary'])

            st.write("**Potential Bypasses Found:**")
            if analysis['findings']:
                for finding in analysis['findings']:
                    st.write(f"- **URL:** {finding['url']}")
                    st.write(f"  - **Method:** {finding['method']}")
                    st.write(f"  - **Status Code:** {finding['response'].get('status_code', 'N/A')}")
                    st.write(f"  - **Notes:** {finding['notes']}")
                    st.markdown("---")
            else:
                st.info("No obvious bypasses found in this test.")

    else:
        st.error("Bypasser module is not available. Please check initialization logs.")


def render_crawler_tab():
    """Renders the Directory & File Discovery tab for RedOpsSuite."""
    st.header("🕷️ Directory & File Discovery (PathCrawler)")
    st.markdown("""
    Discover hidden directories and files using wordlist-based fuzzing.
    """)

    if 'crawler_tool' in st.session_state:
        crawler = st.session_state.crawler_tool

        target_url = st.text_input("Target Base URL:", value="http://testphp.vulnweb.com/")
        # Wordlist selection
        wordlist_option = st.radio("Wordlist Source:", ["Use Built-in List", "Upload Wordlist File"])

        wordlist_to_use = []
        if wordlist_option == "Use Built-in List":
            # Provide a small built-in list for demo
            builtin_words = ["admin", "login", "backup", "config", ".git", "robots.txt", "sitemap.xml", "secret"]
            st.multiselect("Select from Built-in Words (demo):", options=builtin_words, default=builtin_words, key="builtin_wordlist_selection")
            # The actual wordlist will be loaded later based on user interaction or default
            # For simplicity, we'll pass the builtin list directly to crawl if selected
            wordlist_to_use = builtin_words # This will be used if no file is uploaded

        uploaded_wordlist = None
        if wordlist_option == "Upload Wordlist File":
            uploaded_wordlist = st.file_uploader("Choose a wordlist file (txt)", type="txt")
            # If a file is uploaded, we need to process it. Let's do that inside the crawl button logic.

        # Extensions to test
        extensions_input = st.text_input("File Extensions (comma-separated, e.g., .bak,.old):", value=".bak,.old")
        extensions = [ext.strip() for ext in extensions_input.split(',') if ext.strip()]
        # Add leading dot if missing
        extensions = [ext if ext.startswith('.') else f".{ext}" for ext in extensions]

        # Crawl settings
        status_filter_input = st.text_input("Status Codes to Report (comma-separated):", value="200,301,302,401,403,500")
        status_filter = [int(code.strip()) for code in status_filter_input.split(',') if code.strip().isdigit()]

        if st.button("Start Crawl"):
            if target_url:
                with st.spinner("Starting directory crawl..."):
                    try:
                        # Determine wordlist source
                        final_wordlist_source = None
                        if wordlist_option == "Use Built-in List":
                            final_wordlist_source = wordlist_to_use
                        elif wordlist_option == "Upload Wordlist File" and uploaded_wordlist:
                            # Process uploaded file
                            try:
                                # Read lines from uploaded file
                                content = uploaded_wordlist.read().decode("utf-8")
                                final_wordlist_source = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
                                st.info(f"Loaded {len(final_wordlist_source)} entries from uploaded wordlist.")
                            except Exception as e:
                                st.error(f"Error reading uploaded wordlist: {e}")
                                final_wordlist_source = None # Fail gracefully
                        else:
                            st.warning("No valid wordlist source selected or file upload failed.")
                            final_wordlist_source = None

                        if final_wordlist_source is not None:
                            # Perform the crawl
                            results = crawler.crawl(
                                base_url=target_url,
                                wordlist_source=final_wordlist_source,
                                extensions=extensions,
                                status_filter=status_filter
                            )
                            st.session_state.redops_crawler_results = results
                            st.success("Directory crawl completed.")
                        else:
                            st.session_state.redops_crawler_results = []

                    except Exception as e:
                        st.error(f"An error occurred during crawl: {e}")
                        st.session_state.redops_crawler_results = []
            else:
                st.warning("Please provide a Target Base URL.")

        # Display results
        if 'redops_crawler_results' in st.session_state and st.session_state.redops_crawler_results:
            st.subheader("Crawl Results")
            results = st.session_state.redops_crawler_results

            # Analyze and sort results
            sorted_results = crawler.analyze_results(results, sort_by='status_code')

            if sorted_results:
                # Display as a table
                df_results = pd.DataFrame(sorted_results)
                # Select relevant columns for display
                display_columns = ['status_code', 'response_size', 'url']
                available_display_columns = [col for col in display_columns if col in df_results.columns]
                if available_display_columns:
                    st.dataframe(df_results[available_display_columns], use_container_width=True)
                else:
                    # Fallback if columns are missing
                    st.write("Results (showing first 10):")
                    st.json(sorted_results[:10])

                # Option to download results
                csv = df_results.to_csv(index=False)
                st.download_button(
                    label="📥 Download Results (CSV)",
                    data=csv,
                    file_name=f"redops_crawl_results_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime='text/csv',
                )
            else:
                st.info("No crawl results to display based on the filter.")

    else:
        st.error("PathCrawler module is not available. Please check initialization logs.")


def render_cookiesnatcher_tab():
    """Renders the Cookie Snatcher tab for RedOpsSuite."""
    st.header("🍪 Cookie Snatcher")
    st.markdown("""
    Manage and test HTTP cookies for session hijacking or fixation tests.
    *(Note: This demo focuses on managing/loading cookies. Actual stealing requires specific exploits like XSS.)*
    """)

    if 'cookie_snatcher_tool' in st.session_state:
        snatcher = st.session_state.cookie_snatcher_tool

        st.subheader("Load Cookies")
        cookie_source = st.radio("Load Cookies From:", ["Manual Entry", "JSON File Upload"])

        if cookie_source == "Manual Entry":
            st.markdown("**Enter Cookie Details:**")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                name = st.text_input("Name", key="manual_cookie_name")
            with col2:
                value = st.text_input("Value", key="manual_cookie_value")
            with col3:
                domain = st.text_input("Domain", key="manual_cookie_domain")
            with col4:
                path = st.text_input("Path", value="/", key="manual_cookie_path")

            if st.button("Add Manual Cookie"):
                if name and value and domain:
                    cookie_dict = {
                        "name": name,
                        "value": value,
                        "domain": domain,
                        "path": path,
                        "secure": st.checkbox("Secure", key="manual_cookie_secure"),
                        "httponly": st.checkbox("HttpOnly", key="manual_cookie_httponly"),
                        # Add more attributes as needed
                    }
                    snatcher.add_cookie(cookie_dict)
                    st.success(f"Added cookie: {name}")
                    # Clear inputs after adding (optional, might require session state management)
                else:
                    st.warning("Please fill in Name, Value, and Domain for the cookie.")

        elif cookie_source == "JSON File Upload":
            uploaded_cookie_file = st.file_uploader("Choose a cookies JSON file", type="json")
            if st.button("Load Cookies from File") and uploaded_cookie_file:
                try:
                    # Save uploaded file temporarily
                    temp_filename = "temp_uploaded_cookies.json"
                    with open(temp_filename, "wb") as f:
                        f.write(uploaded_cookie_file.getbuffer())

                    snatcher.load_cookies_from_file(temp_filename)
                    st.success("Cookies loaded from file.")
                    # Clean up
                    import os
                    if os.path.exists(temp_filename):
                        os.remove(temp_filename)
                except Exception as e:
                    st.error(f"Error loading cookies: {e}")

        st.subheader("Captured/Loaded Cookies")
        all_cookies = snatcher.get_all_cookies()
        if all_cookies:
            df_cookies = pd.DataFrame(all_cookies)
            # Display relevant columns
            display_cols = ['name', 'value', 'domain', 'path', 'secure', 'httponly']
            available_cols = [col for col in display_cols if col in df_cookies.columns]
            if available_cols:
                st.dataframe(df_cookies[available_cols], use_container_width=True)
            else:
                st.json(all_cookies) # Fallback

            if st.button("Clear All Cookies"):
                snatcher.clear_cookies()
                st.success("All cookies cleared.")
        else:
            st.info("No cookies loaded or captured yet.")

        st.subheader("Analyze Cookies")
        if st.button("Run Cookie Analysis"):
            analysis = snatcher.analyze_cookies()
            st.write("**Analysis Summary:**")
            st.json(analysis['summary'])
            if analysis['findings']:
                st.write("**Findings:**")
                for finding in analysis['findings']:
                    st.markdown(f"- **{finding['type'].replace('_', ' ').title()}:** {finding['description']}")

        st.subheader("Test Cookie Access")
        test_url = st.text_input("Target URL for Test:", value="http://testphp.vulnweb.com/")
        # Select a cookie to test (simplified: use first one or let user pick if multiple)
        if all_cookies:
            selected_cookie_name = st.selectbox("Select Cookie to Test:", options=[c['name'] for c in all_cookies])
            selected_cookie = next((c for c in all_cookies if c['name'] == selected_cookie_name), None)

            if st.button("Test Selected Cookie"):
                if selected_cookie:
                    with st.spinner("Testing cookie access..."):
                        try:
                            test_result = snatcher.test_cookie_in_request(
                                url=test_url,
                                cookie_name=selected_cookie['name'],
                                cookie_value=selected_cookie['value'],
                                method='GET', # Default method
                                expected_status_codes=[200, 302] # Common success codes
                            )
                            st.session_state.redops_cookie_test_result = test_result
                            st.success("Cookie access test completed.")
                        except Exception as e:
                            st.error(f"Error during test: {e}")
                            st.session_state.redops_cookie_test_result = None
                else:
                    st.warning("No cookie selected for testing.")
        else:
            st.info("Load or capture cookies first.")

        # Display test result
        if 'redops_cookie_test_result' in st.session_state and st.session_state.redops_cookie_test_result:
            st.subheader("Cookie Test Result")
            result = st.session_state.redops_cookie_test_result
            st.write(f"**Tested URL:** {result['url']}")
            st.write(f"**Method:** {result['method']}")
            st.write(f"**Status Code:** {result['response'].get('status_code', 'N/A')}")
            st.write(f"**Access Granted (Preliminary):** {result['indicators'].get('access_granted', False)}")
            st.write(f"**Notes:** {result['notes']}")
            if result['error']:
                st.error(f"**Error:** {result['error']}")
            # Optionally show response preview
            with st.expander("Response Preview"):
                st.text_area("Body Preview", value=result['response'].get('body_preview', ''), height=200, key="cookie_test_response_preview")


    else:
        st.error("CookieSnatcher module is not available. Please check initialization logs.")


def render_obfuscator_tab():
    """Renders the Payload Obfuscation tab for RedOpsSuite."""
    st.header("🥷 Payload Obfuscation (Obfuscator)")
    st.markdown("""
    Encode, encrypt, or obfuscate payloads to evade filters and WAFs.
    """)

    if 'obfuscator_tool' in st.session_state:
        obfuscator = st.session_state.obfuscator_tool

        payload = st.text_area("Enter Payload to Obfuscate:", value="calc.exe", height=100)
        techniques = st.multiselect(
            "Select Obfuscation Techniques:",
            options=obfuscator.list_techniques(),
            default=['base64']
        )

        # Simple wrapper selection (conceptual)
        wrapper_option = st.selectbox(
            "Apply Wrapper (Conceptual):",
            options=["None", "eval(base64_decode(...))", "exec(base64.b64decode(...))", "Custom..."]
        )
        custom_wrapper = ""
        if wrapper_option == "Custom...":
            custom_wrapper = st.text_input("Enter Custom Wrapper (use {encoded_payload}):", value="eval('{encoded_payload}');")

        if st.button("Obfuscate Payload"):
            if payload and techniques:
                with st.spinner("Obfuscating payload..."):
                    try:
                        # Determine wrapper
                        wrapper_to_use = None
                        if "base64_decode" in wrapper_option:
                            wrapper_to_use = obfuscator.generate_wrapper('powershell') # Example
                        elif "b64decode" in wrapper_option:
                            wrapper_to_use = obfuscator.generate_wrapper('python') # Example
                        elif wrapper_option == "Custom...":
                            wrapper_to_use = custom_wrapper
                        # Add more wrapper logic as needed

                        result = obfuscator.obfuscate(
                            payload=payload,
                            techniques=techniques,
                            wrapper=wrapper_to_use
                        )
                        st.session_state.redops_obfuscator_result = result
                        st.success("Payload obfuscation completed.")
                    except Exception as e:
                        st.error(f"Error during obfuscation: {e}")
                        st.session_state.redops_obfuscator_result = None
            else:
                st.warning("Please provide a payload and select at least one technique.")

        # Display result
        if 'redops_obfuscator_result' in st.session_state and st.session_state.redops_obfuscator_result:
            st.subheader("Obfuscation Result")
            result = st.session_state.redops_obfuscator_result
            st.write(f"**Original Payload:** `{result['original_payload']}`")
            st.write(f"**Final Obfuscated Payload:**")
            st.code(result['final_obfuscated'], language='text') # Use 'text' or specific language if known
            st.write(f"**Applied Techniques:** {', '.join([t.get('encoding', 'N/A') for t in result['applied_techniques']])}")
            if result['wrapper_used']:
                st.write(f"**Wrapper Applied:** `{result['wrapper_used']}`")
            if result['errors']:
                st.error("**Errors:**")
                for err in result['errors']:
                    st.write(f"  - {err}")

            # Option to copy to clipboard (Streamlit 1.28+)
            # st.markdown(f"**Final Payload (Copy):**")
            # st.code(result['final_obfuscated'], language='text')
            # st_copy_to_clipboard(result['final_obfuscated']) # Requires st_copy_to_clipboard package

    else:
        st.error("Obfuscator module is not available. Please check initialization logs.")


def render_ssrfhunter_tab():
    """Renders the SSRF Hunter tab for RedOpsSuite."""
    st.header("🪤 SSRF Hunter")
    st.markdown("""
    Detect Server-Side Request Forgery vulnerabilities by targeting URL parameters.
    """)

    if 'ssrf_hunter_tool' in st.session_state:
        hunter = st.session_state.ssrf_hunter_tool

        st.subheader("Configure Targets")
        # Simple target definition for demo
        target_url = st.text_input("Target URL (with vulnerable parameter):", value="http://testphp.vulnweb.com/redir.php?url=http://example.com")
        # In a real tool, you'd define method, params, data, headers separately or load from a request file/proxy

        # Payload configuration
        st.subheader("Configure Payloads")
        payload_types = st.multiselect("Payload Types:", ['internal_ip', 'collaborator'], default=['internal_ip'])
        # Note: Collaborator requires setup. For demo, internal IPs are safer.

        # Custom payloads (optional)
        custom_payloads_input = st.text_area("Custom Payload URLs (one per line, optional):")
        custom_payloads = [line.strip() for line in custom_payloads_input.split('\n') if line.strip()]

        # Parameters to test (optional, otherwise test all found)
        params_to_test_input = st.text_input("Specific Parameters to Test (comma-separated, optional):")
        params_to_test = [p.strip() for p in params_to_test_input.split(',') if p.strip()]

        if st.button("Launch SSRF Hunt"):
            if target_url:
                with st.spinner("Launching SSRF hunt..."):
                    try:
                        # Define target in the format expected by SSRFHunter
                        # This is a simplification. A real tool would parse method, params, data, headers.
                        parsed_url = st.experimental_get_query_params() # Gets query params from *current* app URL, not target
                        # Let's assume the user provides the full URL with parameters correctly.

                        # For this demo, let's parse the provided URL to extract base and params
                        from urllib.parse import urlparse, parse_qs
                        parsed_target = urlparse(target_url)
                        base_url_for_hunt = f"{parsed_target.scheme}://{parsed_target.netloc}{parsed_target.path}"
                        initial_params_dict = parse_qs(parsed_target.query)
                        # Flatten params for the hunter (it expects a dict like {'param': 'value'})
                        flattened_params = {k: v[0] if v else '' for k, v in initial_params_dict.items()}

                        # Create a single target dict for the hunter
                        target_definition = {
                            'url': base_url_for_hunt,
                            'method': 'GET', # Assume GET for demo
                            'params': flattened_params,
                            'data': None, # Assume no POST data for demo
                            'headers': {} # Assume no special headers for demo
                        }

                        # Run the hunt
                        results = hunter.hunt(
                            targets=[target_definition],
                            payload_types=payload_types,
                            custom_payloads=custom_payloads if custom_payloads else None,
                            parameters_to_test=params_to_test if params_to_test else None
                        )
                        st.session_state.redops_ssrf_results = results
                        st.success("SSRF hunt initiated.")
                    except Exception as e:
                        st.error(f"Error initiating SSRF hunt: {e}")
                        st.session_state.redops_ssrf_results = []
            else:
                st.warning("Please provide a Target URL.")

        # Display results
        if 'redops_ssrf_results' in st.session_state and st.session_state.redops_ssrf_results:
            st.subheader("SSRF Hunt Results")
            results = st.session_state.redops_ssrf_results
            # Analyze results
            analysis = hunter.analyze_results(results)
            st.write("**Analysis Summary:**")
            st.json(analysis['summary'])

            st.write("**Probe Results (Successful Requests):**")
            if analysis['findings']: # Show findings (requests sent successfully)
                for finding in analysis['findings'][:10]: # Show first 10
                    target_info = finding.get('target', {})
                    payload_info = finding.get('payload', {})
                    response_info = finding.get('response', {})
                    st.write(f"- **Target:** {target_info.get('url', 'N/A')}")
                    st.write(f"  - **Method:** {target_info.get('method', 'N/A')}")
                    st.write(f"  - **Parameter:** {target_info.get('parameter', 'N/A')}")
                    st.write(f"  - **Payload Type:** {payload_info.get('type', 'N/A')}")
                    st.write(f"  - **Payload URL:** {payload_info.get('url', 'N/A')}")
                    st.write(f"  - **Status Code:** {response_info.get('status_code', 'N/A')}")
                    st.write(f"  - **Notes:** {finding.get('notes', 'N/A')}")
                    if finding.get('error'):
                        st.write(f"  - **Error:** {finding['error']}")
                    st.markdown("---")
                if len(analysis['findings']) > 10:
                    st.write(f"... and {len(analysis['findings']) - 10} more probes sent.")
            else:
                st.info("No probes were sent successfully or no basic indicators found in this simple test.")

    else:
        st.error("SSRFHunter module is not available. Please check initialization logs.")


def render_exploitlauncher_tab():
    """Renders the Exploit Launcher tab for RedOpsSuite."""
    st.header("🧨 Exploit Launcher (ExploitX)")
    st.markdown("""
    Launch exploits against known vulnerabilities (PoC or Metasploit).
    """)

    if 'exploit_launcher_tool' in st.session_state:
        exploitx = st.session_state.exploit_launcher_tool

        st.subheader("Available Exploits")
        # List exploits
        exploits = exploitx.list_exploits()
        if exploits:
            exploit_names = [f"{e['id']} - {e['name']}" for e in exploits]
            selected_exploit_name = st.selectbox("Select an Exploit:", options=exploit_names)
            # Find the actual exploit dict
            selected_exploit = None
            if selected_exploit_name:
                selected_id = selected_exploit_name.split(' - ')[0]
                selected_exploit = exploitx.get_exploit_by_id(selected_id)

            if selected_exploit:
                st.write(f"**Description:** {selected_exploit.get('description', 'N/A')}")
                st.write(f"**Type:** {selected_exploit.get('type', 'N/A')}")
                st.write(f"**Target:** {selected_exploit.get('target', {}).get('service', 'N/A')} ({selected_exploit.get('target', {}).get('cve', 'N/A')})")

                st.subheader("Configure Exploit Parameters")
                # Dynamically generate input fields based on exploit parameters
                exploit_params = selected_exploit.get('parameters', {})
                configured_params = {}
                for param_name, param_info in exploit_params.items():
                    param_type = param_info.get('type', 'string')
                    is_required = param_info.get('required', False)
                    default_value = param_info.get('default', '')
                    description = param_info.get('description', '')

                    input_label = f"{param_name} ({'Required' if is_required else 'Optional'})"
                    if description:
                        input_label += f" - {description}"

                    if param_type == 'string':
                        configured_params[param_name] = st.text_input(input_label, value=str(default_value), key=f"param_{param_name}")
                    elif param_type == 'integer':
                        configured_params[param_name] = st.number_input(input_label, value=int(default_value) if str(default_value).isdigit() else 0, key=f"param_{param_name}")
                    elif param_type == 'boolean':
                         configured_params[param_name] = st.checkbox(input_label, value=bool(default_value), key=f"param_{param_name}")
                    # Add more parameter types as needed (list, enum, file path)

                if st.button("Launch Selected Exploit"):
                    with st.spinner(f"Launching exploit {selected_exploit['id']}..."):
                        try:
                            result = exploitx.launch_exploit(selected_exploit['id'], configured_params)
                            st.session_state.redops_exploit_result = result
                            status = result.get('status', 'unknown')
                            success = result.get('success', False)
                            if status == 'completed' and success:
                                st.success(f"Exploit {selected_exploit['id']} completed successfully.")
                            elif status == 'completed' and not success:
                                st.warning(f"Exploit {selected_exploit['id']} completed, but may not have been successful. Check output.")
                            elif status == 'error':
                                st.error(f"Exploit {selected_exploit['id']} failed to launch or encountered an error.")
                            else:
                                st.info(f"Exploit {selected_exploit['id']} status: {status}")
                        except Exception as e:
                            st.error(f"Error launching exploit: {e}")
                            st.session_state.redops_exploit_result = None
            else:
                st.info("Select an exploit from the list.")

        else:
            st.info("No exploits found in the database. Add exploit definitions to `config/exploits.yaml`.")

        # Display exploit result
        if 'redops_exploit_result' in st.session_state and st.session_state.redops_exploit_result:
            st.subheader("Exploit Launch Result")
            result = st.session_state.redops_exploit_result
            st.write(f"**Exploit ID:** {result.get('exploit_id', 'N/A')}")
            st.write(f"**Status:** {result.get('status', 'N/A')}")
            st.write(f"**Success:** {result.get('success', False)}")
            st.write(f"**Target:** {result.get('target', 'N/A')}")
            st.write(f"**Type:** {result.get('type', 'N/A')}")
            st.write("**Output:**")
            # Use st.text_area for potentially long output
            st.text_area("Exploit Output", value=result.get('output', ''), height=300, key="exploit_output_textarea")
            if result.get('error'):
                st.error(f"**Error:** {result['error']}")

    else:
        st.error("ExploitX module is not available. Please check initialization logs.")


def render_payloadforge_tab():
    """Renders the Payload Crafting tab for RedOpsSuite."""
    st.header("🧰 Payload Crafting (PayloadForge)")
    st.markdown("""
    Generate payloads from templates, fuzzing patterns, and apply encodings.
    """)

    if 'payload_forge_tool' in st.session_state:
        forge = st.session_state.payload_forge_tool

        st.subheader("Payload Generation Method")
        gen_method = st.radio("Choose Method:", ["Template", "Fuzzing Pattern"])

        payload = "" # Variable to hold the final generated payload

        if gen_method == "Template":
            st.subheader("Template-Based Generation")
            # List templates
            templates = forge.list_templates()
            if templates:
                selected_template = st.selectbox("Select Template:", options=templates)
                if selected_template:
                    template_content = forge.load_template(selected_template)
                    if template_content:
                        st.text_area("Template Content:", value=template_content, height=150, key="selected_template_content", disabled=True)

                        # Allow user to define substitutions
                        st.markdown("**Define Template Variables:**")
                        # This is a simplified way. A real tool might parse the template for {{VAR}} patterns.
                        # For now, let's allow manual key-value input.
                        substitutions_input = st.text_area(
                            "Variables (key:value, one per line):",
                            value="COMMAND:whoami\nMESSAGE:XSS_Test", # Example vars
                            height=100
                        )
                        substitutions = {}
                        for line in substitutions_input.split('\n'):
                            if ':' in line:
                                k, v = line.split(':', 1)
                                substitutions[k.strip()] = v.strip()

                        if st.button("Generate from Template"):
                            try:
                                payload = forge.generate_from_template(template_content, substitutions)
                                st.session_state.redops_forge_generated_payload = payload
                                st.success("Payload generated from template.")
                            except Exception as e:
                                st.error(f"Error generating payload: {e}")
                    else:
                        st.error("Failed to load selected template.")
            else:
                st.info("No templates found. Add templates to the `config/payload_templates` directory.")

        elif gen_method == "Fuzzing Pattern":
            st.subheader("Fuzzing Pattern Generation")
            pattern_type = st.selectbox(
                "Select Pattern:",
                options=['buffer_overflow', 'format_string', 'directory_traversal', 'long_string', 'special_chars']
            )
            # Parameter input based on pattern type (simplified)
            pattern_param = None
            if pattern_type in ['buffer_overflow', 'format_string', 'long_string']:
                pattern_param = st.number_input("Length/Count:", min_value=1, value=100 if pattern_type == 'buffer_overflow' else 10)
            elif pattern_type == 'directory_traversal':
                col1, col2 = st.columns(2)
                with col1:
                    depth = st.number_input("Traversal Depth:", min_value=1, value=5)
                with col2:
                    prefix = st.text_input("Prefix:", value="../")
                pattern_param = {'depth': depth, 'prefix': prefix}
            elif pattern_type == 'special_chars':
                chars_input = st.text_input("Characters (comma-separated):", value="\\x00,\\n,%00")
                pattern_param = {'chars': [c.strip().encode().decode('unicode_escape') for c in chars_input.split(',')]} # Decode escape sequences

            if st.button("Generate Fuzzing Payloads"):
                try:
                    payloads = forge.generate_fuzzing_payloads(pattern_type, pattern_param)
                    # For simplicity, take the first one or join them. Let's take the first one.
                    if payloads:
                        payload = payloads[0] if isinstance(payloads, list) else str(payloads)
                        st.session_state.redops_forge_generated_payload = payload
                        st.success(f"Generated {len(payloads) if isinstance(payloads, list) else 1} fuzzing payload(s). Showing the first one.")
                    else:
                        st.info("No payloads were generated.")
                        st.session_state.redops_forge_generated_payload = ""
                except Exception as e:
                    st.error(f"Error generating fuzzing payloads: {e}")
                    st.session_state.redops_forge_generated_payload = ""

        # --- Payload Display and Forging ---
        if 'redops_forge_generated_payload' in st.session_state:
            st.subheader("Generated Payload")
            payload = st.session_state.redops_forge_generated_payload
            st.text_area("Payload:", value=payload, height=150, key="generated_payload_textarea")

            # --- Forging Section ---
            st.subheader("Forge Payload (Encoding/Obfuscation)")
            # Select encodings
            encodings = st.multiselect(
                "Select Encodings to Apply:",
                options=forge.supported_encodings,
                default=[]
            )
            # Simple wrapper template (conceptual)
            wrapper_template = st.text_input("Wrapper Template (use {encoded_payload}):", value="eval(base64_decode('{encoded_payload}')); // Forged")

            if st.button("Forge Payload"):
                if payload:
                    with st.spinner("Forging payload..."):
                        try:
                            forge_result = forge.forge(
                                base_payload=payload,
                                encodings=encodings,
                                wrapper_template=wrapper_template if wrapper_template and "{encoded_payload}" in wrapper_template else None
                            )
                            st.session_state.redops_forge_forged_result = forge_result
                            st.success("Payload forging completed.")
                        except Exception as e:
                            st.error(f"Error forging payload: {e}")
                            st.session_state.redops_forge_forged_result = None
                else:
                    st.warning("No payload generated yet.")

            # Display Forged Result
            if 'redops_forge_forged_result' in st.session_state and st.session_state.redops_forge_forged_result:
                st.subheader("Forged Payload")
                forged_result = st.session_state.redops_forge_forged_result
                st.write(f"**Applied Encodings:** {', '.join(forged_result.get('applied_encodings', []))}")
                st.write(f"**Final Forged Payload:**")
                st.code(forged_result.get('final_payload', ''), language='text') # Use 'text' or specific language
                if forged_result.get('errors'):
                    st.error("**Errors during forging:**")
                    for err in forged_result['errors']:
                        st.write(f"  - {err}")

    else:
        st.error("PayloadForge module is not available. Please check initialization logs.")

def render_endpointagent_tab():
    """
    Renders the Endpoint Agent tab in the Streamlit UI.
    """
    st.header("💻 Endpoint Agent (EndpointAgent)")
    st.markdown("""
    Collects telemetry directly from hosts (Windows/Linux).
    This module simulates collecting system, process, network, and user information.
    """)

    # Access the EndpointAgent instance (initialized in app.py)
    if 'endpoint_agent' not in st.session_state:
        st.error("EndpointAgent module is not available. Please check the application initialization logs.")
        return

    agent = st.session_state.endpoint_agent

    st.subheader("Agent Configuration")
    st.write(f"**Hostname:** {agent.hostname}")
    st.write(f"**OS:** {agent.os_info}")
    st.write(f"**Collection Interval:** {getattr(agent,'collection_interval', 'N/A')} seconds")
    st.write(f"**Output Directory:** {getattr(agent,'output_dir','./telemetry_output')}")
    

    st.subheader("Run Telemetry Collection")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Run Single Collection Cycle"):
            with st.spinner("Running single collection cycle..."):
                try:
                    #agent.run_once()
                    agent.collect_and_save_once()
                    st.success("Single collection cycle completed. Check output file.")
                except Exception as e:
                    st.error(f"Error running single collection: {e}")

    with col2:
        # Continuous collection controls
        #if not agent.is_running:
        if not agent.is_collecting:
            if st.button("🟢 Start Continuous Collection"):
                # Get user input for interval and output path before starting
                with st.form("start_continuous_form"):
                    new_interval = st.number_input("Collection Interval (seconds)", min_value=1, value=agent.collection_interval, key="new_interval_input")
                    new_output_path = st.text_input("Output Path", value=agent.output_path, key="new_output_path_input")
                    submit_start = st.form_submit_button("Start")
                    if submit_start:
                        # Update agent config temporarily for this run
                        agent.collection_interval = new_interval
                        agent.output_path = new_output_path
                        # Run in a separate thread to avoid blocking the UI
                        import threading
                        agent_thread = threading.Thread(target=agent.start)
                        agent_thread.daemon = True # Dies when main thread dies
                        agent_thread.start()
                        st.session_state.endpoint_agent_thread = agent_thread
                        st.success("Continuous collection started in background thread.")
        else:
            if st.button("🟥 Stop Continuous Collection"):
                #agent.stop()
                agent.stop_continuous_collection()
                st.success("Stop signal sent to continuous collection.")
                # Wait a bit and check if thread is still alive
                agent_thread = st.session_state.get('endpoint_agent_thread')
                if agent_thread and agent_thread.is_alive():
                    # Thread might take a moment to stop due to sleep
                    st.info("Waiting for background collection thread to finish...")
                    # agent_thread.join(timeout=5) # Wait up to 5 seconds
                    # if agent_thread.is_alive():
                    #     st.warning("Background thread is still running. It will stop after the next collection cycle.")

    # Display status
    status = "🟢 Collecting" if agent.is_collecting else "🟥 Stopped"
    st.write(f"**Status:** {status}")

    st.subheader("View Collected Telemetry")
    import glob
    telemetry_files= glob.glob(os.path.join(agent.output_dir,"endpoint_telemetry_*.json"))
    telemetry_files.sort(key=os.path.getmtime, reverse=True)

    if telemetry_files:
        latest_file = telemetry_files[0]
        st.write(f"**Latest Telemetry File:** `{latest_file}`")
        if os.path.exists(latest_file):
            try:
                with open(latest_file, 'r') as f:
                    lines = f.readlines()
                if lines:
                    st.write(f"**Last {min(5, len(lines))} Entries from {os.path.basename(latest_file)}:**")
                    for line in lines[-5:]:
                        try:
                            data = json.loads(line.strip())
                            with st.expander(f"Entry from {data.get('collection_timestamp','N/A')}"):
                                st.json(data)
                        except json.JSONDecodeError:
                            st.text(line.strip())
                else:
                    st.info(f"The output file {latest_file} is empty.")
            except Exception as e:
                st.error(f"Error reading telemetry file:{latest_file}: {e}")
        else:
            st.info(f"The output file {latest_file} does not exist.")
    else:
        st.info(f"No telemetry files found in {agent.output_dir}. Run a collection cycle first.")
        
    st.subheader("Analyze Collected Telemetry")
    if os.path.exists(agent.output_path):
        if st.button("🔍 Analyze Telemetry Data"):
            with st.spinner("Analyzing telemetry data..."):
                try:
                    # Simple analysis: count entries, show latest timestamp
                    with open(agent.output_path, 'r') as f:
                        lines = f.readlines()
                    entry_count = len(lines)
                    if entry_count > 0:
                        try:
                            latest_entry = json.loads(lines[-1].strip())
                            latest_ts = latest_entry.get('collection_timestamp', 'N/A')
                        except json.JSONDecodeError:
                            latest_ts = "N/A (Invalid JSON)"
                    else:
                        latest_ts = "N/A"
                    
                    st.session_state.endpoint_telemetry_analysis = {
                        "entry_count": entry_count,
                        "latest_timestamp": latest_ts
                    }
                    st.success("Telemetry data analysis complete.")
                except Exception as e:
                    st.error(f"Error analyzing telemetry  {e}")
                    st.session_state.endpoint_telemetry_analysis = {}

        if 'endpoint_telemetry_analysis' in st.session_state and st.session_state.endpoint_telemetry_analysis:
            analysis = st.session_state.endpoint_telemetry_analysis
            st.write("**Analysis Summary:**")
            st.write(f"- **Total Entries Collected:** {analysis['entry_count']}")
            st.write(f"- **Latest Collection Timestamp:** {analysis['latest_timestamp']}")
    else:
        st.info("No telemetry data file found. Run a collection cycle first.")



# --- Main Tab Rendering Logic for RedOpsSuite ---
# This function will be called by app.py when RedOpsSuite mode is active

def render_tabs_redops(view_name):
    """Dispatches rendering to the correct RedOpsSuite tab function."""
    # Map view names to their rendering functions
    # The view_name comes from st.session_state.current_redops_view set by the RedOps sidebar
    tab_functions = {
        'Home': lambda: st.header("🏠 RedOpsSuite Home - Offensive Security Toolkit"),
        'Recon': render_recon_tab,
        'Injector': render_injector_tab,
        'Bypasser': render_bypasser_tab,
        'Crawler': render_crawler_tab,
        'CookieSnatcher': render_cookiesnatcher_tab,
        'Obfuscator': render_obfuscator_tab,
        'SSRFHunter': render_ssrfhunter_tab,
        'ExploitLauncher': render_exploitlauncher_tab,
        'PayloadForge': render_payloadforge_tab,
        'EndpointAgent': render_endpointagent_tab,
        # Add more tab functions as RedOpsSuite grows
        # 'RedOpsDashboard': render_redops_dashboard_tab,
        # 'RedOpsSettings': render_redops_settings_tab,
    }

    render_func = tab_functions.get(view_name)
    if render_func:
        render_func()
    else:
        st.error(f"RedOpsSuite view '{view_name}' is not implemented or the render function is missing.")
