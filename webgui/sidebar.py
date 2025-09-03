# BlueDefenderX/webgui/sidebar.py
import streamlit as st

def render_sidebar(mode='blue'):
    """Renders the sidebar for navigation, dynamically based on the mode."""
    st.sidebar.title("🧭 Navigation")

    if mode == 'blue':
        # --- BlueDefenderX Navigation ---
        # Use session state to track the current view
        # Home
        if st.sidebar.button("🏠 Home"):
            st.session_state.current_view = 'Home'

        st.sidebar.markdown("---")
        st.sidebar.subheader("🔍 Detection")
        if st.sidebar.button("📜 Logs"):
            st.session_state.current_view = 'Logs'
        if st.sidebar.button("🚨 Alerts"):
            st.session_state.current_view = 'Alerts'
        if st.sidebar.button("🧠 Anomalies"):
            st.session_state.current_view = 'Anomalies'
        if st.sidebar.button("🌐 Threat Intel"):
            st.session_state.current_view = 'ThreatIntel'

        st.sidebar.markdown("---")
        st.sidebar.subheader("🛡️ Response")
        if st.sidebar.button("⚡ Incidents"):
            st.session_state.current_view = 'Incidents'
        if st.sidebar.button("🔁 Playbooks"):
            st.session_state.current_view = 'Playbooks'

        st.sidebar.markdown("---")
        st.sidebar.subheader("📊 Intelligence")
        if st.sidebar.button("📊 Dashboard"):
            st.session_state.current_view = 'Dashboard'
        if st.sidebar.button("🗺️ MITRE ATT&CK"):
            st.session_state.current_view = 'MITRE'

        st.sidebar.markdown("---")
        st.sidebar.subheader("👥 Intelligence")
        if st.sidebar.button("👥 UBA"):
            st.session_state.current_view = 'UBA'
        if st.sidebar.button("📋 Policy"):
            st.session_state.current_view = 'Policy'

        st.sidebar.markdown("---")
        st.sidebar.subheader("🍯 Deception")
        if st.sidebar.button("🍯 Honeypot"):
            st.session_state.current_view = 'Honeypot'
        if st.sidebar.button("🟣 PurpleTest"):
            st.session_state.current_view = 'PurpleTest'

        st.sidebar.markdown("---")
        st.sidebar.subheader("🔐 Trust")
        if st.sidebar.button("🛡️ Trust"):
            st.session_state.current_view = 'Trust'

        st.sidebar.markdown("---")
        st.sidebar.subheader("⚙️ Configuration")
        if st.sidebar.button("🛠️ Settings"):
            st.session_state.current_view = 'Settings'
        # --- End BlueDefenderX Navigation ---

    elif mode == 'red':
        # --- RedOpsSuite Navigation ---
        # Use a different session state key to avoid conflict
        if st.sidebar.button("🏠 Home"):
            st.session_state.current_redops_view = 'Home'

        st.sidebar.markdown("---")
        st.sidebar.subheader("🔍 Reconnaissance")
        if st.sidebar.button("📡 Recon"):
            st.session_state.current_redops_view = 'Recon'
        if st.sidebar.button("🕷️ Crawler"):
            st.session_state.current_redops_view = 'Crawler'
        if st.sidebar.button("🍪 Cookie Snatcher"):
            st.session_state.current_redops_view = 'CookieSnatcher'

        st.sidebar.markdown("---")
        st.sidebar.subheader("🎯 Exploitation")
        if st.sidebar.button("💉 Injector"):
            st.session_state.current_redops_view = 'Injector'
        if st.sidebar.button("🛡️ Bypasser"):
            st.session_state.current_redops_view = 'Bypasser'
        if st.sidebar.button("🪤 SSRF Hunter"):
            st.session_state.current_redops_view = 'SSRFHunter'
        if st.sidebar.button("🧨 Exploit Launcher"):
            st.session_state.current_redops_view = 'ExploitLauncher'

        st.sidebar.markdown("---")
        st.sidebar.subheader("🛠️ Payloads")
        if st.sidebar.button("🧰 Payload Forge"):
            st.session_state.current_redops_view = 'PayloadForge'
        if st.sidebar.button("🥷 Obfuscator"):
            st.session_state.current_redops_view = 'Obfuscator'

        st.sidebar.markdown("---")
        st.sidebar.subheader("🖥️ Endpoint")
        if st.sidebar.button("💻 Endpoint Agent"):
            st.session_state.current_redops_view = 'EndpointAgent'

        # Future RedOps sections can go here (Reporting, Dashboard, etc.)
        # st.sidebar.subheader("📊 Intelligence")
        # if st.sidebar.button("📈 RedOps Dashboard"):
        #     st.session_state.current_redops_view = 'RedOpsDashboard'

        # st.sidebar.markdown("---")
        # st.sidebar.subheader("⚙️ Configuration")
        # if st.sidebar.button("🔧 RedOps Settings"):
        #     st.session_state.current_redops_view = 'RedOpsSettings'
        # --- End RedOpsSuite Navigation ---
