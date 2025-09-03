# BlueDefenderX/webgui/tabs_controller.py
import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
from utils.logger import bd_logger
import os
import json
import yaml

# --- Helper Functions ---
def highlight_anomalies(row):
    """Helper function to highlight anomalies in dataframes."""
    if row.get('is_anomaly', False):
        return ['background-color: #ffcccc'] * len(row)
    else:
        return [''] * len(row)

# --- Tab Rendering Functions ---

def render_home_tab():
    """Renders the Home/Overview tab."""
    st.header("🏠 Welcome to BlueDefenderX!")
    st.markdown("""
    BlueDefenderX is your integrated defensive security automation toolkit.

    **Key Capabilities:**
    - **Log Collection & Parsing:** (`LogDefenderX`) Ingest and normalize logs from various sources.
    - **Lightweight SIEM:** (`SIEMLite`) Correlate events and apply detection rules.
    - **Threat Intelligence:** (`ThreatFeedSync`) Enrich detections with external IOCs.
    - **Anomaly Detection:** (`AnomalyDetector`) Identify unusual behavior patterns.
    - **Incident Response:** (`IncidentRespondr`) Automate and manage security incidents.
    - **MITRE ATT&CK Mapping:** (`MITREMapper`) Understand attacks in the context of common tactics.
    - **... and many more modules!**

    **Get Started:**
    - Use the sidebar to navigate to different modules.
    - Configure settings and rules in the `Settings` section.
    - Monitor `Logs` and `Alerts` for potential threats.
    """)
    # Placeholder for system status or quick stats
    col1, col2, col3 = st.columns(3)
    col1.metric("Alerts (24h)", "0", "0")
    col2.metric("Events Processed", "0", "0")
    col3.metric("Active Rules", "0", "0")

    st.subheader("📈 Recent Activity")
    st.info("No recent activity to display. Start ingesting logs!")

    st.subheader("🛠️ Quick Actions")
    if st.button("🔄 Reload Configuration"):
        st.success("Configuration reloaded (simulated).")
    if st.button("🧪 Run Purple Team Test"):
        st.info("Purple Team testing module not yet implemented or fully integrated here.")

def render_logs_tab():
    """Renders the Log Ingestion & Parsing tab."""
    st.header("📜 Log Ingestion & Parsing")
    
    # Access the instance directly from st.session_state (guaranteed by app.py init)
    ld = st.session_state.log_defender

    uploaded_file = st.file_uploader("Choose a log file (txt)", type="txt")
    log_type = st.selectbox("Select Log Type", ["generic", "ssh"])

    if st.button("Parse Logs") and uploaded_file is not None:
        temp_filename = "temp_uploaded_log.txt"
        try:
            with open(temp_filename, "wb") as f:
                f.write(uploaded_file.getbuffer())

            raw_logs = ld.read_log_file(temp_filename)
            if raw_logs:
                parsed_logs = ld.parse_logs(raw_logs, log_type=log_type)
                st.session_state.parsed_logs_cache = parsed_logs
                st.success(f"Parsed {len(parsed_logs)} log events.")
            else:
                st.error("Failed to read log file or file is empty.")
        except Exception as e:
            st.error(f"Error processing file: {e}")
        finally:
            # Clean up temporary file
            import os
            if os.path.exists(temp_filename):
                os.remove(temp_filename)

    # Display parsed logs if available
    if 'parsed_logs_cache' in st.session_state and st.session_state.parsed_logs_cache:
        df_logs = pd.DataFrame(st.session_state.parsed_logs_cache)
        st.subheader("Parsed Log Events")
        st.dataframe(df_logs, use_container_width=True)
    else:
        st.info("No parsed logs available. Upload a file and click 'Parse Logs'.")

def render_alerts_tab():
    """Renders the Security Alerts tab."""
    st.header("🚨 Security Alerts")
    
    # Access the instances directly from st.session_state
    siem = st.session_state.siem_engine
    tfs = st.session_state.threat_intel_engine
    mm = st.session_state.mitre_mapper
    ir = st.session_state.incident_responder

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Run Correlation Engine"):
            if 'parsed_logs_cache' in st.session_state and st.session_state.parsed_logs_cache:
                with st.spinner('Running correlation engine...'):
                    alerts = siem.correlate_events(st.session_state.parsed_logs_cache)
                    # --- Enrich alerts with Threat Intel ---
                    if alerts:
                        with st.spinner('Enriching alerts with threat intelligence...'):
                            alerts = tfs.enrich_alerts(alerts)
                    # --- Map alerts to MITRE ATT&CK ---
                    if alerts: # Check again if alerts still exist after TI enrichment
                        with st.spinner('Mapping alerts to MITRE ATT&CK...'):
                            alerts = mm.map_alerts_batch(alerts)
                        bd_logger.info(f"Mapped {len(alerts)} alerts to MITRE techniques.")
                    # --- End MITRE Mapping ---
                    st.session_state.alerts_cache = alerts
                st.success(f"Correlation, Enrichment & MITRE Mapping complete. Generated {len(alerts)} alerts.")
            else:
                st.warning("No parsed logs found. Please parse logs first in the 'Logs' tab.")

    with col2:
        if st.button("🔄 Re-Sync Threat Feeds"):
             with st.spinner('Synchronizing threat feeds...'):
                tfs.sync_feeds()
             st.success("Threat feeds synchronized!")

    # Display alerts if available
    if 'alerts_cache' in st.session_state and st.session_state.alerts_cache:
        st.subheader("Triggered Alerts")
        for i, alert in enumerate(st.session_state.alerts_cache):
            # Check for threat intel
            ti_info = alert.get('threat_intel', [])
            ti_indicator = " ⚠️" if ti_info else "" # Add warning icon if TI matched
            
            with st.expander(f"🚨 Alert {i+1}: {alert['title']} ({alert['severity'].upper()}){ti_indicator}"):
                # Display basic alert info
                st.write(f"**Rule ID:** {alert['rule_id']}")
                st.write(f"**Description:** {alert['description']}")
                st.write(f"**Timestamp:** {alert['timestamp']}")
                
                # --- Display MITRE ATT&CK Mapping ---
                mitre_info = alert.get('mitre')
                if mitre_info:
                    st.markdown("**MITRE ATT&CK Mapping:**")
                    st.markdown(f"- **Technique ID:** `{mitre_info.get('technique_id', 'N/A')}`")
                    st.markdown(f"- **Technique Name:** {mitre_info.get('technique_name', 'N/A')}")
                    tactics = mitre_info.get('tactics', [])
                    if tactics:
                        st.markdown(f"- **Tactics:** {', '.join(tactics)}")
                    # Optionally display description
                    # st.markdown(f"- **Description:** {mitre_info.get('description', 'N/A')}")
                else:
                    st.markdown("**MITRE ATT&CK Mapping:** Not available for this alert.")
                # --- End MITRE Display ---
                
                # Display Threat Intel if present
                if ti_info:
                    st.markdown("**Threat Intelligence Match:**")
                    for ti_item in ti_info:
                        st.markdown(f"- **Type:** {ti_item['type']}, **Value:** `{ti_item['value']}`, **Feed:** {ti_item['feed']}")

                # Display alert details
                st.markdown("**Details:**")
                st.json(alert['details'])

                # Display source events (directly, no nested expander)
                source_events = alert.get('source_events', [])
                if source_events:
                    st.markdown("**Source Events (Last 10 shown):**")
                    # Limit displayed events to last 10 for better UI
                    events_to_show = source_events[-10:] if len(source_events) > 10 else source_events
                    # Use st.dataframe for a cleaner table view, or st.json for raw JSON
                    try:
                        df_events = pd.DataFrame(events_to_show)
                        st.dataframe(df_events, use_container_width=True, hide_index=True)
                    except Exception as e: # Catch potential issues with DataFrame creation
                        bd_logger.error(f"Error displaying source events as DataFrame: {e}")
                        st.json(events_to_show) # Fallback to JSON
                    
                    if len(source_events) > 10:
                        st.caption(f"... and {len(source_events) - 10} more events.")

                # --- Add Manual Response Trigger ---
                if st.button("⚡ Respond to this Alert", key=f"respond_alert_{i}"):
                    # responder = st.session_state.incident_responder # Already accessed above
                    with st.spinner("Executing response playbook..."):
                        try:
                            # Pass the alert dictionary to the responder
                            ir.respond_to_incident(alert)
                            st.success("Response playbook executed (simulated). Check logs/terminal for details.")
                        except Exception as e:
                            st.error(f"Error executing response: {e}")
                # --- End Manual Response Trigger ---

    else:
        st.info("No alerts generated. Run the correlation engine after parsing logs.")

def render_threatintel_tab():
    """Renders the Threat Intelligence tab."""
    st.header("🌐 Threat Intelligence")
    
    # Access the instance directly
    tfs = st.session_state.threat_intel_engine

    if st.button("🔄 Sync Threat Feeds"):
        with st.spinner('Synchronizing threat feeds...'):
            tfs.sync_feeds()
        st.success("Threat feeds synchronized!")

    # Display loaded IOCs
    ioc_summary = tfs.get_loaded_iocs() # Corrected function name
    st.subheader("Loaded IOC Summary")
    if ioc_summary:
        df_iocs = pd.DataFrame(list(ioc_summary.items()), columns=['Type', 'Count'])
        st.dataframe(df_iocs, use_container_width=True)
        
        # Optionally, show a sample of IOCs
        st.subheader("Sample IOCs")
        for ioc_type, ioc_set in tfs.iocs.items():
            if ioc_set:
                st.write(f"**{ioc_type.upper()}** (showing up to 10):")
                sample_list = list(ioc_set)[:10]
                # Use st.text for better handling of IPs/newlines
                st.text('\n'.join(sample_list)) 
    else:
        st.info("No IOCs loaded. Click 'Sync Threat Feeds' to load data.")

def render_anomalies_tab():
    """Renders the Behavioral Anomalies tab."""
    st.header("🧠 Behavioral Anomalies")
    st.markdown("""
    This section uses machine learning to identify unusual patterns in log data 
    that might not be caught by rule-based detection.
    """)
    
    # Access the detector and mapper instances (initialized in app.py)
    detector = st.session_state.anomaly_detector
    mapper = st.session_state.mitre_mapper
    ir = st.session_state.incident_responder # For response button

    # --- Check for parsed logs ---
    parsed_logs_available = False
    if 'parsed_logs_cache' in st.session_state:
        cache = st.session_state.parsed_logs_cache
        if cache is not None and isinstance(cache, list) and len(cache) > 0:
            parsed_logs_available = True
        elif isinstance(cache, list) and len(cache) == 0:
             st.info("Parsed logs cache exists but is empty (`[]`). Please ensure logs were successfully parsed and the cache was populated in the '📜 Logs' tab.")
        else:
             st.warning(f"Parsed logs cache exists but is of unexpected type or value: {type(cache)}, Value: {cache}")
    else:
         st.info("Parsed logs cache does not exist in session state. Please parse logs in the '📜 Logs' tab first.")

    if not parsed_logs_available:
        return # Exit the function early if no logs

    # --- Anomaly Detection Logic ---
    if st.button("🔍 Detect Anomalies"):
        with st.spinner("Analyzing log data for anomalies using Isolation Forest..."):
            try:
                detection_results = detector.detect(st.session_state.parsed_logs_cache)
                # --- Map anomalies to MITRE ATT&CK ---
                if detection_results:
                    with st.spinner('Mapping anomalies to MITRE ATT&CK...'):
                        detection_results = mapper.map_anomalies_batch(detection_results)
                    bd_logger.info("Mapped anomaly detection results to MITRE techniques.")
                # --- End MITRE Mapping for Anomalies ---
                st.session_state.anomalies_cache = detection_results
                anomaly_count = sum(1 for r in detection_results if r['is_anomaly'])
                st.success(f"Anomaly detection & MITRE Mapping complete. Found {anomaly_count} potential anomalies.")
            except Exception as e:
                st.error(f"An error occurred during anomaly detection: {e}")
                bd_logger.error("Anomaly detection failed", exc_info=True)
                st.session_state.anomalies_cache = []

    # Display results if available
    if 'anomalies_cache' in st.session_state and st.session_state.anomalies_cache:
        results = st.session_state.anomalies_cache
        anomaly_count = sum(1 for r in results if r['is_anomaly'])
        
        st.subheader(f"Detection Results ({anomaly_count} Anomalies)")
        
        # Summary metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Events", len(results))
        col2.metric("Anomalies Found", anomaly_count)
        # Check if scores are available before calculating average
        scores = [r['anomaly_score'] for r in results if r['anomaly_score'] is not None]
        if scores:
             col3.metric("Avg Anomaly Score", f"{np.mean(scores):.4f}")
        else:
             col3.metric("Avg Anomaly Score", "N/A")
        
        # Filter option
        show_option = st.radio("Show:", ("All Events", "Anomalies Only"), horizontal=True)

        # Prepare data for display
        display_data = []
        for i, result in enumerate(results): # Iterate over results, not display_data
            if show_option == "Anomalies Only" and not result['is_anomaly']:
                continue
                
            raw_event = result['raw_event']
            display_item = raw_event.copy() # Start with raw event data
            display_item['is_anomaly'] = result['is_anomaly']
            display_item['anomaly_score'] = result.get('anomaly_score', 'N/A')
            
            # --- Display MITRE ATT&CK Mapping for Anomalies ---
            mitre_info = result.get('mitre') # Use 'result' (the current item) here
            if mitre_info and result.get('is_anomaly'): # Only show for actual anomalies
                 display_item['mitre_technique_id'] = mitre_info.get('technique_id', 'N/A')
                 display_item['mitre_technique_name'] = mitre_info.get('technique_name', 'N/A')
            # --- End MITRE Display for Anomalies ---
            
            display_data.append(display_item)

            # --- Add Manual Response Trigger for Anomalies ---
            # Place this inside the main loop, after preparing display_item
            if result.get('is_anomaly'): # Only allow responding to actual anomalies
                if st.button("⚡ Respond to this Anomaly", key=f"respond_anomaly_{i}"):
                    # ir = st.session_state.incident_responder # Already accessed above
                    with st.spinner("Executing response playbook..."):
                        try:
                            # Pass the full result dictionary to the responder
                            ir.respond_to_incident(result)
                            st.success("Response playbook executed (simulated). Check logs/terminal for details.")
                        except Exception as e:
                            st.error(f"Error executing response: {e}")
            # --- End Manual Response Trigger for Anomalies ---

        if display_data :# Check if there's data to display after filtering
            df_results = pd.DataFrame(display_data)
            # Sort by anomaly score if available, putting anomalies first
            if 'anomaly_score' in df_results.columns:
                # Handle potential 'N/A' strings in sorting by converting to numeric, NaNs go last
                df_results_sorted = df_results.copy()
                df_results_sorted['anomaly_score'] = pd.to_numeric(df_results_sorted['anomaly_score'], errors='coerce')
                df_results_sorted = df_results_sorted.sort_values(by='anomaly_score', ascending=True, na_position='last')
                df_results = df_results_sorted
            
            # Highlight anomalies in the dataframe
            def highlight_anomalies(row):
                if row['is_anomaly']:
                    return ['background-color: #ffcccc'] * len(row) # Light red
                else:
                    return [''] * len(row)
            
            st.dataframe(
                df_results.style.apply(highlight_anomalies, axis=1),
                use_container_width=True,
                hide_index=True
            )
            
            # Download button for results
            csv = df_results.to_csv(index=False)
            st.download_button(
                label="📥 Download Anomaly Results (CSV)",
                data=csv,
                file_name=f"anomaly_detection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime='text/csv',
            )
        else:
            st.info("No anomalies found based on the current filter.")
    else:
        st.info("Click '🔍 Detect Anomalies' to start the analysis.")

def render_incidents_tab():
    """Renders the Incident Management tab."""
    st.header("⚡ Incident Management")
    st.markdown("This section will manage active security incidents.")
    st.info("IncidentRespondr module integration pending.")

def render_playbooks_tab():
    """
    Renders the Automated Response Playbooks tab.
    Displays loaded playbooks and allows basic management/viewing.
    """
    st.header("🔁 Automated Response Playbooks")
    st.markdown("""
    This section manages automated response workflows (playbooks) triggered by alerts or anomalies.
    Playbooks define a series of actions to take when specific conditions are met.
    """)

    # Access the IncidentRespondr instance (initialized in app.py)
    # Check if it's available in session state (robust access)
    if 'incident_responder' not in st.session_state:
        st.error("IncidentRespondr module is not available. Please check the application initialization logs.")
        bd_logger.error("IncidentRespondr instance not found in st.session_state for Playbooks tab.")
        return

    responder = st.session_state.incident_responder

    # --- Display Loaded Playbooks ---
    st.subheader("Loaded Response Playbooks")

    if not responder.playbooks:
        st.info("No playbooks are currently loaded. Check `config/playbooks.yaml`.")
        return

    # Option 1: Simple list view
    # for pb in responder.playbooks:
    #     with st.expander(f"**{pb.get('name', 'Unnamed Playbook')}**"):
    #         st.write(f"**Description:** {pb.get('description', 'N/A')}")
    #         st.write(f"**Trigger:** {pb.get('trigger', {})}")
    #         st.write("**Actions:**")
    #         for action in pb.get('actions', []):
    #             st.json(action) # Display action config

    # Option 2: Table view (more compact for overview)
    playbook_data = []
    for pb in responder.playbooks:
        playbook_data.append({
            "Name": pb.get('name', 'Unnamed'),
            "Description": pb.get('description', 'N/A')[:100] + "..." if len(pb.get('description', '')) > 100 else pb.get('description', 'N/A'), # Truncate long descriptions
            "Trigger Type": list(pb.get('trigger', {}).keys())[0] if pb.get('trigger') else 'None',
            "Trigger Value": list(pb.get('trigger', {}).values())[0] if pb.get('trigger') else 'N/A',
            "Actions": len(pb.get('actions', [])),
            # Raw data for potential detailed view/expander
            "raw_pb": pb
        })

    if playbook_data:
        df_playbooks = pd.DataFrame(playbook_data)
        # Drop raw data column for main display
        display_df = df_playbooks.drop(columns=['raw_pb'])
        st.dataframe(display_df, use_container_width=True, hide_index=True)

        # --- Optional: Detailed View for Selected Playbook ---
        st.subheader("Playbook Details")
        # Create a selectbox with playbook names
        playbook_names = [pb['Name'] for pb in playbook_data]
        selected_pb_name = st.selectbox("Select a playbook to view details:", options=playbook_names, index=0 if playbook_names else 0)

        # Find the selected playbook data
        selected_pb_data = next((pb for pb in playbook_data if pb['Name'] == selected_pb_name), None)
        if selected_pb_data:
            raw_pb = selected_pb_data.get('raw_pb', {})
            st.write(f"**Full Configuration for '{selected_pb_name}':**")
            # Use st.json for a collapsible, formatted view of the raw playbook config
            st.json(raw_pb)
        else:
            st.write("No playbook selected or details unavailable.")

    else:
        st.write("No playbook data could be prepared for display.")

    # --- Optional: Reload Playbooks Button ---
    st.subheader("Management")
    if st.button("🔄 Reload Playbooks"):
        # Re-initialize to reload config
        # Note: This modifies st.session_state directly
        try:
            # Import the class again (in case logic changed)
            # A more robust way might be to add a reload_config method to the class
            from modules.incidentrespondr import IncidentRespondr
            st.session_state.incident_responder = IncidentRespondr()
            # Update local reference
            responder = st.session_state.incident_responder
            st.success("Playbooks reloaded successfully!")
            bd_logger.info("Playbooks reloaded via UI button.")
            # Rerun the script to refresh the display
            st.experimental_rerun()
        except Exception as e:
            st.error(f"Error reloading playbooks: {e}")
            bd_logger.error(f"Error reloading playbooks via UI: {e}", exc_info=True)

    # --- Optional: Test Manual Trigger (Advanced) ---
    # This is more complex as it requires selecting an alert/anomaly structure.
    # It's likely easier to test via the Alerts/Anomalies tabs where the context exists.
    # st.subheader("Manual Test (Advanced)")
    # st.info("Playbooks are typically triggered automatically. Manual testing requires specific alert/anomaly data structures.")

# --- New Tab Functions for Recently Added Modules ---

def render_uba_tab():
    """Renders the User Behavior Analytics tab."""
    st.header("👥 User Behavior Analytics (UBA)")
    st.markdown("""
    This section monitors and analyzes user activities for suspicious behavior.
    """)

    # Check if necessary data is available
    if 'parsed_logs_cache' not in st.session_state or not st.session_state.parsed_logs_cache:
        st.info("No parsed logs available. Please parse logs containing user activity (e.g., SSH logs) in the '📜 Logs' tab first.")
        return

    # Import and initialize UBAMonitor on demand (lazy loading)
    if 'uba_monitor' not in st.session_state:
         try:
             from modules.uba_monitor import UBAMonitor
             st.session_state.uba_monitor = UBAMonitor()
             bd_logger.info("UBAMonitor initialized and stored in session state.")
         except Exception as e:
             st.error(f"Failed to initialize UBAMonitor: {e}")
             bd_logger.error(f"Failed to initialize UBAMonitor: {e}", exc_info=True)
             return

    uba = st.session_state.uba_monitor

    if st.button("🔍 Analyze User Behavior"):
        with st.spinner("Analyzing user behavior patterns..."):
            try:
                 # Run UBA analysis on parsed logs
                 # Assume analyze method exists and returns anomalies/findings
                 uba_findings = uba.analyze(st.session_state.parsed_logs_cache)
                 st.session_state.uba_findings_cache = uba_findings
                 st.success(f"UBA analysis complete. Found {len(uba_findings)} potential user behavior anomalies.")
                 # Optionally, store user profiles
                 st.session_state.uba_profiles_cache = uba.get_all_profiles()
            except Exception as e:
                st.error(f"An error occurred during UBA analysis: {e}")
                bd_logger.error("UBA analysis failed", exc_info=True)
                st.session_state.uba_findings_cache = []

    # Display findings
    if 'uba_findings_cache' in st.session_state and st.session_state.uba_findings_cache:
        st.subheader("UBA Findings")
        findings = st.session_state.uba_findings_cache
        for finding in findings:
             # Display finding details (adjust based on UBAMonitor output structure)
             st.write(f"**Finding:** {finding.get('title', 'N/A')}")
             st.write(f"**User:** {finding.get('user', 'N/A')}")
             st.write(f"**Reason:** {finding.get('description', 'N/A')}")
             st.json(finding) # Show full details
             st.markdown("---")
    else:
         st.info("No UBA findings available. Click '🔍 Analyze User Behavior' to start analysis.")

    # Display User Profiles (if available)
    if 'uba_profiles_cache' in st.session_state and st.session_state.uba_profiles_cache:
        st.subheader("User Behavior Profiles")
        profiles = st.session_state.uba_profiles_cache
        if profiles:
            df_profiles = pd.DataFrame.from_dict(profiles, orient='index')
            st.dataframe(df_profiles, use_container_width=True)
        else:
             st.write("No user profiles built yet.")

def render_policy_tab():
    """Renders the Compliance Policy Watcher tab."""
    st.header("📋 Compliance Policy Watcher")
    st.markdown("""
    This section tracks system configurations against compliance baselines.
    """)

    # Import and initialize PolicyWatcher on demand
    if 'policy_watcher' not in st.session_state:
         try:
             from modules.policywatcher import PolicyWatcher
             st.session_state.policy_watcher = PolicyWatcher()
             bd_logger.info("PolicyWatcher initialized and stored in session state.")
         except Exception as e:
             st.error(f"Failed to initialize PolicyWatcher: {e}")
             bd_logger.error(f"Failed to initialize PolicyWatcher: {e}", exc_info=True)
             return

    pw = st.session_state.policy_watcher

    baseline_options = list(pw.baselines.keys()) if pw.baselines else []
    selected_baseline = st.selectbox("Select Baseline to Check", options=baseline_options, index=0 if baseline_options else 0)

    if st.button("🔍 Run Compliance Check"):
        with st.spinner(f"Running compliance checks for '{selected_baseline}'..."):
            try:
                # Run checks for the selected baseline
                results = pw.run_checks(baseline_name=selected_baseline if selected_baseline else None)
                st.session_state.policy_check_results_cache = results
                passed = sum(1 for r in results if r['status'] == 'passed')
                failed = sum(1 for r in results if r['status'] == 'failed')
                errors = sum(1 for r in results if r['status'] == 'error')
                st.success(f"Compliance check for '{selected_baseline}' completed. Passed: {passed}, Failed: {failed}, Errors: {errors}")
            except Exception as e:
                st.error(f"An error occurred during compliance check: {e}")
                bd_logger.error("Compliance check failed", exc_info=True)
                st.session_state.policy_check_results_cache = []

    # Display results
    if 'policy_check_results_cache' in st.session_state and st.session_state.policy_check_results_cache:
        st.subheader("Compliance Check Results")
        results = st.session_state.policy_check_results_cache
        
        # Summary
        passed = sum(1 for r in results if r['status'] == 'passed')
        failed = sum(1 for r in results if r['status'] == 'failed')
        errors = sum(1 for r in results if r['status'] == 'error')
        manual = sum(1 for r in results if r['status'] == 'manual_review')

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Passed", passed)
        col2.metric("Failed", failed)
        col3.metric("Errors", errors)
        col4.metric("Manual Review", manual)

        # Detailed list
        for result in results:
            status_icon = {
                'passed': '✅',
                'failed': '❌',
                'error': '⚠️',
                'manual_review': '📘'
            }.get(result['status'], '❓')
            
            with st.expander(f"{status_icon} [{result['check_id']}] {result['description']} ({result['severity'].upper()})"):
                st.write(f"**Status:** {result['status'].replace('_', ' ').title()}")
                st.write(f"**Reason:** {result['reason']}")
                # Optionally show command and output for failed/errors
                # if result['status'] in ['failed', 'error']:
                #     st.write(f"**Command:** `{result['command']}`")
                #     st.text_area("Output", value=result['actual_output'][:500] + "..." if len(result['actual_output']) > 500 else result['actual_output'], height=100, key=f"output_{result['check_id']}")

    else:
         st.info("No compliance check results available. Click '🔍 Run Compliance Check' to start.")

def render_honeypot_tab():
    """Renders the Honeypot Management tab."""
    st.header("🍯 Honeypot Management")
    st.markdown("""
    This section manages and monitors deceptive trap services.
    """)

    # Import and initialize HoneyPotX on demand
    if 'honeypot_manager' not in st.session_state:
         try:
             from modules.honeypotx import HoneyPotX
             # Default config for UI control
             default_config = {
                 'host': '127.0.0.1',
                 'port': 2222,
                 'service_type': 'generic_tcp',
                 'log_file': 'ui_honeypot_interactions.jsonl'
             }
             st.session_state.honeypot_manager = HoneyPotX(config=default_config)
             bd_logger.info("HoneyPotX initialized and stored in session state.")
         except Exception as e:
             st.error(f"Failed to initialize HoneyPotX: {e}")
             bd_logger.error(f"Failed to initialize HoneyPotX: {e}", exc_info=True)
             return

    hp = st.session_state.honeypot_manager

    st.subheader("Honeypot Configuration")
    # Allow basic configuration
    host = st.text_input("Host IP", value=hp.host)
    port = st.number_input("Port", min_value=1, max_value=65535, value=hp.port)
    service_type = st.selectbox("Service Type", options=["generic_tcp", "ssh", "http"], index=["generic_tcp", "ssh", "http"].index(hp.service_type) if hp.service_type in ["generic_tcp", "ssh", "http"] else 0)
    log_file = st.text_input("Log File", value=hp.log_file)

    if st.button("💾 Update Configuration"):
        try:
            # Note: Changing config of a running instance is complex.
            # A better approach is to stop, re-init, and optionally restart.
            # For simplicity here, we just update the session state instance's attributes.
            # A production app might manage multiple instances or use a factory.
            hp.host = host
            hp.port = port
            hp.service_type = service_type
            hp.log_file = log_file
            # Update internal config dict if it exists
            if hasattr(hp, 'config'):
                hp.config['host'] = host
                hp.config['port'] = port
                hp.config['service_type'] = service_type
                hp.config['log_file'] = log_file
            st.success("Honeypot configuration updated (requires restart to take full effect).")
        except Exception as e:
            st.error(f"Failed to update configuration: {e}")

    st.subheader("Honeypot Control")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🟢 Start Honeypot"):
            if not hp.is_active():
                with st.spinner("Starting honeypot..."):
                    try:
                        # Start in a background thread (HoneyPotX should handle this internally with threading)
                        # The example HoneyPotX uses threading when started directly.
                        import threading
                        hp_thread = threading.Thread(target=hp.start)
                        hp_thread.daemon = True
                        hp_thread.start()
                        # Give it a moment to start
                        import time
                        time.sleep(1)
                        if hp.is_active():
                             st.session_state.honeypot_thread = hp_thread # Keep reference
                             st.success("Honeypot started successfully.")
                        else:
                             st.warning("Honeypot start command sent, but status check failed.")
                    except Exception as e:
                        st.error(f"Failed to start honeypot: {e}")
                        bd_logger.error("Failed to start honeypot", exc_info=True)
            else:
                 st.info("Honeypot is already running.")

    with col2:
        if st.button("🟥 Stop Honeypot"):
            if hp.is_active():
                with st.spinner("Stopping honeypot..."):
                    try:
                        hp.stop()
                        # Wait a bit for thread to finish?
                        # hp_thread = st.session_state.get('honeypot_thread')
                        # if hp_thread and hp_thread.is_alive():
                        #     hp_thread.join(timeout=5)
                        st.success("Honeypot stopped.")
                        # Clean up thread reference
                        if 'honeypot_thread' in st.session_state:
                             del st.session_state.honeypot_thread
                    except Exception as e:
                        st.error(f"Failed to stop honeypot: {e}")
                        bd_logger.error("Failed to stop honeypot", exc_info=True)
            else:
                 st.info("Honeypot is not running.")

    st.write(f"**Status:** {'🟢 Running' if hp.is_active() else '🟥 Stopped'}")
    st.write(f"**Listening On:** {hp.host}:{hp.port} ({hp.service_type})")

    st.subheader("Recent Interactions")
    # Display recent interactions from in-memory list or log file
    # Using in-memory list for simplicity
    recent_interactions = hp.get_recent_interactions(count=10)
    if recent_interactions:
        df_interactions = pd.DataFrame(recent_interactions)
        st.dataframe(df_interactions, use_container_width=True)
    else:
        st.info("No recent interactions logged.")

def render_purpletest_tab():
    """Renders the Purple Team Testing tab."""
    st.header("🟣 Purple Team Testing")
    st.markdown("""
    This section simulates Red Team operations and validates Blue Team detections.
    """)

    # Import and initialize PurpleTest on demand
    if 'purple_tester' not in st.session_state:
         try:
             from modules.purpletest import PurpleTest
             st.session_state.purple_tester = PurpleTest()
             bd_logger.info("PurpleTest initialized and stored in session state.")
         except Exception as e:
             st.error(f"Failed to initialize PurpleTest: {e}")
             bd_logger.error(f"Failed to initialize PurpleTest: {e}", exc_info=True)
             return

    pt = st.session_state.purple_tester

    st.subheader("Available Test Scenarios")
    # List available scenarios
    scenario_names = list(pt.test_scenarios.keys())
    if not scenario_names:
         st.write("No test scenarios defined.")
         return

    selected_scenario = st.selectbox("Select a Test Scenario", options=scenario_names)

    st.subheader("Run Test")
    # Allow customization of parameters (basic example)
    # A full implementation would dynamically build UI for scenario params
    simulation_params = {}
    if selected_scenario == "ssh_brute_force_simulation":
         st.write("Customize SSH Brute Force Simulation:")
         simulation_params['attacker_ip'] = st.text_input("Simulated Attacker IP", value="10.100.100.100")
         simulation_params['num_attempts'] = st.number_input("Number of Failed Attempts", min_value=1, value=8)
         simulation_params['log_path'] = st.text_input("Log File Path", value="purple_test_ssh_simulation.log")
    # Add UI for other scenarios as needed...

    if st.button("🧪 Run Selected Test"):
        with st.spinner(f"Running test scenario: {selected_scenario}..."):
            try:
                # Run the selected test scenario with parameters
                result = pt.run_test_scenario(selected_scenario, simulation_params=simulation_params)
                # Store the single result
                st.session_state.purple_test_result_cache = result
                # Also store in the list of all results
                if 'purple_test_results_cache' not in st.session_state:
                     st.session_state.purple_test_results_cache = []
                st.session_state.purple_test_results_cache.append(result)

                if result.get('passed'):
                     st.success(f"Test '{selected_scenario}' PASSED. {result.get('validation_result', {}).get('reason', '')}")
                else:
                     st.warning(f"Test '{selected_scenario}' FAILED. {result.get('validation_result', {}).get('reason', '')}")
            except Exception as e:
                st.error(f"An error occurred during the test: {e}")
                bd_logger.error("Purple Team test failed", exc_info=True)

    st.subheader("Test Results")
    # Display results from the list
    if 'purple_test_results_cache' in st.session_state and st.session_state.purple_test_results_cache:
        results = st.session_state.purple_test_results_cache
        # Simple text report for the last few results
        # A full implementation might use pt.generate_report()
        for i, res in enumerate(reversed(results[-5:])): # Show last 5
             status = "✅ PASSED" if res.get('passed') else "❌ FAILED"
             st.markdown(f"**{status} - Test:** {res.get('name', 'N/A')} ({res.get('scenario', 'N/A')})")
             st.markdown(f"  - **Time:** {res.get('timestamp', 'N/A')}")
             st.markdown(f"  - **Reason:** {res.get('validation_result', {}).get('reason', 'N/A')}")
             # Optionally show more details
             # st.json(res) # This can be verbose
             st.markdown("---")
    else:
         st.info("No test results available. Run a test scenario to see results.")

def render_trust_tab():
    """Renders the Zero Trust Controller tab."""
    st.header("🛡️ Zero Trust Controller")
    st.markdown("""
    This section manages and displays trust scores for entities.
    """)

    tc = st.session_state.trust_controller # Guaranteed by app.py init

    st.subheader("Trust Score Lookup")
    entity_type = st.selectbox("Entity Type", options=["ip", "user", "host", "device"], index=0)
    entity_id = st.text_input("Entity Identifier (e.g., IP Address, Username)")

    if st.button("🔍 Get Trust Score"):
        if entity_id:
            with st.spinner(f"Fetching trust score for {entity_type}:{entity_id}..."):
                try:
                    score_info = tc.get_trust_score(entity_id, entity_type)
                    st.session_state.trust_lookup_result_cache = score_info
                    if score_info:
                        st.success(f"Trust score found for {entity_type}:{entity_id}.")
                    else:
                        st.info(f"No trust score found for {entity_type}:{entity_id}.")
                except Exception as e:
                    st.error(f"An error occurred while fetching trust score: {e}")
                    bd_logger.error("Trust score lookup failed", exc_info=True)
                    st.session_state.trust_lookup_result_cache = None
        else:
             st.warning("Please enter an Entity Identifier.")

    # Display lookup result
    if 'trust_lookup_result_cache' in st.session_state and st.session_state.trust_lookup_result_cache:
        score_info = st.session_state.trust_lookup_result_cache
        st.subheader(f"Trust Score Details for {entity_type}:{entity_id}")
        st.metric("Current Score", f"{score_info['score']:.2f}")
        st.write("**Contributing Factors:**")
        if score_info['factors']:
            factors_df = pd.DataFrame(list(score_info['factors'].items()), columns=["Factor", "Value"])
            st.dataframe(factors_df, use_container_width=True)
        else:
            st.write("No specific factors recorded.")
        
        st.write("**Score History (Recent):**")
        if score_info['history']:
            # Show last 5 history entries
            history_df = pd.DataFrame(score_info['history'][-5:])
            st.dataframe(history_df[['timestamp', 'previous_score', 'new_score', 'reason']], use_container_width=True)
        else:
             st.write("No history available.")

    elif 'trust_lookup_result_cache' in st.session_state:
         # This means the lookup returned None (entity not found)
         st.subheader(f"Trust Score Details for {entity_type}:{entity_id}")
         st.info(f"No trust score found for {entity_type}:{entity_id}.")

    st.subheader("All Trust Scores")
    # Display all scores
    all_scores = tc.get_all_scores()
    if all_scores:
        scores_df = pd.DataFrame.from_dict(all_scores, orient='index')
        # The index is now 'entity_type:entity_id'
        scores_df.reset_index(inplace=True)
        scores_df.rename(columns={'index': 'Entity'}, inplace=True)
        # Split 'Entity' column for better display
        scores_df[['Type', 'ID']] = pd.DataFrame(scores_df['Entity'].str.split(':', 1).tolist(), columns=['Type', 'ID'])
        # Reorder columns
        scores_df = scores_df[['Type', 'ID', 'score', 'last_updated']]
        scores_df.rename(columns={'score': 'Trust Score'}, inplace=True)
        st.dataframe(scores_df, use_container_width=True)
    else:
        st.info("No trust scores have been calculated yet.")

def render_dashboard_tab():
    """Renders the Real-time Metrics Dashboard tab."""
    st.header("📊 Real-time Security Dashboard")
    st.markdown("""
    This section provides an overview of security metrics and KPIs.
    """)

    # Import and initialize Dashboard on demand (it needs session state)
    if 'dashboard_viewer' not in st.session_state:
         try:
             from modules.dashboard import Dashboard
             st.session_state.dashboard_viewer = Dashboard(st.session_state) # Pass session state
             bd_logger.info("Dashboard viewer initialized and stored in session state.")
         except Exception as e:
             st.error(f"Failed to initialize Dashboard viewer: {e}")
             bd_logger.error(f"Failed to initialize Dashboard viewer: {e}", exc_info=True)
             return

    db = st.session_state.dashboard_viewer

    # The Dashboard module's render_overview method does all the work
    try:
        db.render_overview()
    except Exception as e:
        st.error(f"An error occurred while rendering the dashboard: {e}")
        bd_logger.error("Dashboard rendering failed", exc_info=True)

# --- Placeholder functions for other tabs ---

def render_mitre_tab():
    """Renders the MITRE ATT&CK Mapping tab."""
    st.header("🗺️ MITRE ATT&CK Mapping")
    st.markdown("This section correlates detections with ATT&CK techniques.")
    st.info("MITREMapper module integration pending.")

def render_settings_tab():
    """
    Renders the Configuration Settings tab.
    Allows viewing/editing core config files and reloading modules.
    """
    st.header("🛠️ Configuration Settings")
    st.markdown("""
    Manage BlueDefenderX configuration files and reload modules.
    """)

    # --- Section 1: Edit Configuration Files ---
    st.subheader("📝 Edit Configuration Files")

    # --- 1.1 SIEM Rules (rules.yaml) ---
    rules_file_path = "config/rules.yaml"
    st.markdown("**SIEM Detection Rules (`config/rules.yaml`)**")
    if os.path.exists(rules_file_path):
        with open(rules_file_path, 'r') as f:
            rules_content = f.read()

        edited_rules_content = st.text_area(
            "Edit rules.yaml content:",
            value=rules_content,
            height=300,
            key="rules_editor"
        )

        col1, col2 = st.columns(2)
        with col1:
            if st.button("💾 Save Rules"):
                try:
                    # Basic YAML validation before saving
                    yaml.safe_load(edited_rules_content)
                    with open(rules_file_path, 'w') as f:
                        f.write(edited_rules_content)
                    st.success("Rules file saved successfully!")
                    bd_logger.info(f"Saved changes to {rules_file_path}")
                except yaml.YAMLError as e:
                    st.error(f"Invalid YAML syntax in rules file: {e}")
                    bd_logger.error(f"Error saving rules file: Invalid YAML - {e}")
                except Exception as e:
                    st.error(f"Error saving rules file: {e}")
                    bd_logger.error(f"Error saving rules file: {e}", exc_info=True)

        with col2:
            if st.button("🔄 Reload SIEM Engine"):
                try:
                    # Re-import and re-initialize SIEM Engine
                    from modules.siemlite import SIEMLite
                    st.session_state.siem_engine = SIEMLite()
                    st.success("SIEM Engine reloaded with new rules!")
                    bd_logger.info("SIEM Engine reloaded via Settings tab.")
                    st.experimental_rerun() # Refresh UI to reflect changes
                except Exception as e:
                    st.error(f"Error reloading SIEM Engine: {e}")
                    bd_logger.error(f"Error reloading SIEM Engine: {e}", exc_info=True)
    else:
        st.warning(f"Rules file not found at {rules_file_path}")

    st.markdown("---")

    # --- 1.2 Threat Feeds (feedsources.json) ---
    feeds_file_path = "config/feedsources.json"
    st.markdown("**Threat Intelligence Feeds (`config/feedsources.json`)**")
    if os.path.exists(feeds_file_path):
        with open(feeds_file_path, 'r') as f:
            feeds_content = f.read()

        edited_feeds_content = st.text_area(
            "Edit feedsources.json content:",
            value=feeds_content,
            height=200,
            key="feeds_editor"
        )

        col1, col2 = st.columns(2)
        with col1:
            if st.button("💾 Save Feeds"):
                try:
                    # Basic JSON validation before saving
                    json.loads(edited_feeds_content)
                    with open(feeds_file_path, 'w') as f:
                        f.write(edited_feeds_content)
                    st.success("Feeds file saved successfully!")
                    bd_logger.info(f"Saved changes to {feeds_file_path}")
                except json.JSONDecodeError as e:
                    st.error(f"Invalid JSON syntax in feeds file: {e}")
                    bd_logger.error(f"Error saving feeds file: Invalid JSON - {e}")
                except Exception as e:
                    st.error(f"Error saving feeds file: {e}")
                    bd_logger.error(f"Error saving feeds file: {e}", exc_info=True)

        with col2:
            if st.button("🔄 Reload Threat Intel Engine"):
                try:
                    # Re-import and re-initialize Threat Intel Engine
                    from modules.threatfeedsync import ThreatFeedSync
                    st.session_state.threat_intel_engine = ThreatFeedSync()
                    st.success("Threat Intel Engine reloaded with new feeds!")
                    bd_logger.info("Threat Intel Engine reloaded via Settings tab.")
                    st.experimental_rerun() # Refresh UI to reflect changes
                except Exception as e:
                    st.error(f"Error reloading Threat Intel Engine: {e}")
                    bd_logger.error(f"Error reloading Threat Intel Engine: {e}", exc_info=True)
    else:
        st.warning(f"Feeds file not found at {feeds_file_path}")

    st.markdown("---")

    # --- 1.3 Compliance Baselines (compliance_baselines.yaml) ---
    compliance_file_path = "config/compliance_baselines.yaml"
    st.markdown("**Compliance Baselines (`config/compliance_baselines.yaml`)**")
    if os.path.exists(compliance_file_path):
        with open(compliance_file_path, 'r') as f:
            compliance_content = f.read()

        edited_compliance_content = st.text_area(
            "Edit compliance_baselines.yaml content:",
            value=compliance_content,
            height=200,
            key="compliance_editor"
        )

        col1, col2 = st.columns(2)
        with col1:
            if st.button("💾 Save Compliance"):
                try:
                    # Basic YAML validation before saving
                    yaml.safe_load(edited_compliance_content)
                    with open(compliance_file_path, 'w') as f:
                        f.write(edited_compliance_content)
                    st.success("Compliance file saved successfully!")
                    bd_logger.info(f"Saved changes to {compliance_file_path}")
                except yaml.YAMLError as e:
                    st.error(f"Invalid YAML syntax in compliance file: {e}")
                    bd_logger.error(f"Error saving compliance file: Invalid YAML - {e}")
                except Exception as e:
                    st.error(f"Error saving compliance file: {e}")
                    bd_logger.error(f"Error saving compliance file: {e}", exc_info=True)

        with col2:
            if st.button("🔄 Reload Policy Watcher"):
                 # Check if PolicyWatcher is initialized
                 if 'policy_watcher' in st.session_state:
                     try:
                         # Re-import and re-initialize Policy Watcher
                         from modules.policywatcher import PolicyWatcher
                         st.session_state.policy_watcher = PolicyWatcher()
                         st.success("Policy Watcher reloaded with new baselines!")
                         bd_logger.info("Policy Watcher reloaded via Settings tab.")
                         st.experimental_rerun() # Refresh UI to reflect changes
                     except Exception as e:
                         st.error(f"Error reloading Policy Watcher: {e}")
                         bd_logger.error(f"Error reloading Policy Watcher: {e}", exc_info=True)
                 else:
                      st.warning("Policy Watcher is not currently initialized. It will load with new settings on next use or app restart.")
    else:
        st.warning(f"Compliance file not found at {compliance_file_path}")

    # --- Section 2: System Controls (Optional/Advanced) ---
    st.subheader("🎛️ System Controls")
    st.markdown("Advanced system-level actions.")

    if st.button("🔄 Reload All Core Engines"):
        try:
            with st.spinner("Reloading all core engines..."):
                # Reload LogDefenderX
                from modules.logdefenderx import LogDefenderX
                st.session_state.log_defender = LogDefenderX()
                bd_logger.info("LogDefenderX reloaded.")

                # Reload SIEMLite
                from modules.siemlite import SIEMLite
                st.session_state.siem_engine = SIEMLite()
                bd_logger.info("SIEMLite reloaded.")

                # Reload ThreatFeedSync
                from modules.threatfeedsync import ThreatFeedSync
                st.session_state.threat_intel_engine = ThreatFeedSync()
                bd_logger.info("ThreatFeedSync reloaded.")

                # Reload AnomalyDetector
                from modules.anomalydetector import AnomalyDetector
                st.session_state.anomaly_detector = AnomalyDetector()
                bd_logger.info("AnomalyDetector reloaded.")

                # Reload MITREMapper
                from modules.mitremapper import MITREMapper
                st.session_state.mitre_mapper = MITREMapper()
                bd_logger.info("MITREMapper reloaded.")

                # Reload IncidentRespondr
                from modules.incidentrespondr import IncidentRespondr
                st.session_state.incident_responder = IncidentRespondr()
                bd_logger.info("IncidentRespondr reloaded.")

                # Reload TrustController
                from modules.trustcontroller import TrustController
                st.session_state.trust_controller = TrustController()
                bd_logger.info("TrustController reloaded.")

            st.success("All core engines reloaded successfully!")
            bd_logger.info("All core engines reloaded via Settings tab.")
            # Consider rerunning to refresh dependent UI elements
            # st.experimental_rerun()
        except Exception as e:
            st.error(f"Error reloading core engines: {e}")
            bd_logger.error(f"Error reloading core engines: {e}", exc_info=True)

    if st.button("🔁 Restart Application"):
        st.warning("Restarting the application...")
        bd_logger.info("Application restart requested via Settings tab.")
        # Streamlit doesn't have a direct restart command.
        # Killing the process or asking the user to restart manually is common.
        # For Streamlit, we can suggest a page refresh or rely on the dev server restart.
        # A common trick is to cause an error that forces a reload, but it's not clean.
        # Best practice is to inform the user.
        st.info("Please stop and restart the Streamlit server manually (e.g., Ctrl+C and `streamlit run app.py`).")
        # Alternatively, for development, you might trigger a file change
        # to force Streamlit to reload, but that's hacky.
        # Example (use cautiously):
        # with open("app.py", "a") as f:
        #     f.write("\n# Trigger restart\n")
        # os._exit(0) # Not recommended for production


# --- Main rendering logic ---

def render_tabs(view_name):
    """Render the content for the selected tab."""
    tab_functions = {
        'Home': render_home_tab,
        'Logs': render_logs_tab,
        'Alerts': render_alerts_tab,
        'Anomalies': render_anomalies_tab,
        'ThreatIntel': render_threatintel_tab,
        'Incidents': render_incidents_tab,
        'Playbooks': render_playbooks_tab,
        'UBA': render_uba_tab,
        'Policy': render_policy_tab,
        'Honeypot': render_honeypot_tab,
        'PurpleTest': render_purpletest_tab,
        'Trust': render_trust_tab,
        'Dashboard': render_dashboard_tab,
        'MITRE': render_mitre_tab,
        'Settings': render_settings_tab,
    }

    render_func = tab_functions.get(view_name)
    if render_func:
        render_func()
    else:
        st.error(f"View '{view_name}' is not implemented or the render function is missing.")
