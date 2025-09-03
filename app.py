# BlueDefenderX/app.py
import streamlit as st
import os
import sys
import logging

# --- App Configuration ---
st.set_page_config(
    page_title="BlueDefenderX/RedOpsSuite - Unified SOC/Red Team Toolkit",
    page_icon="🛡️⚔️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Session State Initialization ---
# Ensure session state variables are initialized at app start
if 'current_view' not in st.session_state:
    st.session_state.current_view = 'Home'
if 'toolkit_mode' not in st.session_state:
    st.session_state.toolkit_mode = 'BlueDefenderX' # Default mode

# --- CORE MODULE INITIALIZATION ---
# Ensure core modules are initialized in session state at app start
# This prevents KeyError when tabs try to access them.

# Helper function to safely initialize a module in session state
# Using a lambda for module_class_factory delays the actual import
# until the initialization function is called. This helps avoid potential circular import issues.
def _init_module(session_key, module_class_factory, *args, **kwargs):
    """
    Safely initializes a module and stores it in st.session_state.

    Args:
        session_key (str): The key to use in st.session_state.
        module_class_factory (callable): A callable (e.g., lambda) that returns the module class.
        *args: Arguments to pass to the module class constructor.
        **kwargs: Keyword arguments to pass to the module class constructor.
    """
    if session_key not in st.session_state:
        try:
            # Call the factory function to get the class, then instantiate it
            module_class = module_class_factory()
            instance = module_class(*args, **kwargs)
            st.session_state[session_key] = instance
            from utils.logger import bd_logger
            bd_logger.info(f"Initialized and stored {module_class.__name__} in session state as '{session_key}'.")
        except ImportError as ie:
            st.error(f"Import error while initializing {session_key}: {ie}. Is the module installed/available?")
            from utils.logger import bd_logger
            bd_logger.error(f"Import error while initializing {session_key}: {ie}")
        except Exception as e:
            st.error(f"Failed to initialize {session_key}: {e}")
            from utils.logger import bd_logger
            bd_logger.error(f"Failed to initialize {session_key}: {e}", exc_info=True)

# --- ALWAYS INITIALIZE CORE BlueDefenderX MODULES ---
# These are fundamental to the app's operation and are used across multiple tabs.
# Initializing them upfront ensures they are always available.

# --- Check if RedOpsSuite modules are available (optional robustness) ---
REDOPS_AVAILABLE = True
try:
    # Attempt a lightweight import check for a core RedOpsSuite module
    import RedOpsSuite.modules.reconx
except ImportError:
    REDOPS_AVAILABLE = False
    st.warning("RedOpsSuite modules not found or not importable. RedOps features will be disabled.")
    from utils.logger import bd_logger
    bd_logger.warning("RedOpsSuite modules not found or not importable. RedOps features will be disabled.")

# --- Initialize BlueDefenderX modules ---
# Pass arguments where required by the module's constructor
# Do NOT pass session_state unless the module's __init__ explicitly accepts it as a kwarg
# and you are sure it's needed. Most modules don't need it passed directly.

_init_module('log_defender', lambda: __import__('modules.logdefenderx', fromlist=['LogDefenderX']).LogDefenderX)
_init_module('siem_engine', lambda: __import__('modules.siemlite', fromlist=['SIEMLite']).SIEMLite)
_init_module('threat_intel_engine', lambda: __import__('modules.threatfeedsync', fromlist=['ThreatFeedSync']).ThreatFeedSync)
_init_module('anomaly_detector', lambda: __import__('modules.anomalydetector', fromlist=['AnomalyDetector']).AnomalyDetector)
# Modules that might need session_state (check their __init__ methods)
# If a module's __init__ requires st.session_state, pass it like this:
# _init_module('dashboard_viewer', lambda: __import__('modules.dashboard', fromlist=['Dashboard']).Dashboard, session_state=st.session_state)
# But only do this if the module actually uses it in its constructor.
# For now, let's assume dashboard does need it.
dashboard_module_class = lambda: __import__('modules.dashboard', fromlist=['Dashboard']).Dashboard
_init_module('dashboard_viewer', dashboard_module_class, session_state=st.session_state) # Pass session_state only to Dashboard

# Initialize other modules that don't need special args
_init_module('mitre_mapper', lambda: __import__('modules.mitremapper', fromlist=['MITREMapper']).MITREMapper)
_init_module('incident_responder', lambda: __import__('modules.incidentrespondr', fromlist=['IncidentRespondr']).IncidentRespondr)
_init_module('trust_controller', lambda: __import__('modules.trustcontroller', fromlist=['TrustController']).TrustController)
_init_module('uba_monitor', lambda: __import__('modules.uba_monitor', fromlist=['UBAMonitor']).UBAMonitor)
_init_module('policy_watcher', lambda: __import__('modules.policywatcher', fromlist=['PolicyWatcher']).PolicyWatcher)
_init_module('honeypot_manager', lambda: __import__('modules.honeypotx', fromlist=['HoneyPotX']).HoneyPotX)
_init_module('purple_tester', lambda: __import__('modules.purpletest', fromlist=['PurpleTest']).PurpleTest)
# --- END CORE BlueDefenderX MODULES ---

# --- Initialize RedOpsSuite modules if available ---
if REDOPS_AVAILABLE:
    _init_module('recon_tool', lambda: __import__('RedOpsSuite.modules.reconx', fromlist=['ReconX']).ReconX)
    _init_module('injector_tool', lambda: __import__('RedOpsSuite.modules.injector', fromlist=['Injector']).Injector)
    _init_module('bypasser_tool', lambda: __import__('RedOpsSuite.modules.bypasser', fromlist=['Bypasser']).Bypasser)
    _init_module('crawler_tool', lambda: __import__('RedOpsSuite.modules.pathcrawler', fromlist=['PathCrawler']).PathCrawler)
    _init_module('cookie_snatcher_tool', lambda: __import__('RedOpsSuite.modules.cookiesnatcher', fromlist=['CookieSnatcher']).CookieSnatcher)
    _init_module('obfuscator_tool', lambda: __import__('RedOpsSuite.modules.obfuscator', fromlist=['Obfuscator']).Obfuscator)
    _init_module('ssrf_hunter_tool', lambda: __import__('RedOpsSuite.modules.ssrfhunter', fromlist=['SSRFHunter']).SSRFHunter)
    _init_module('exploit_launcher_tool', lambda: __import__('RedOpsSuite.modules.exploitx', fromlist=['ExploitX']).ExploitX)
    _init_module('payload_forge_tool', lambda: __import__('RedOpsSuite.modules.payloadforge', fromlist=['PayloadForge']).PayloadForge)
    _init_module('endpoint_agent', lambda: __import__('RedOpsSuite.modules.endpointagent', fromlist=['EndpointAgent']).EndpointAgent)
    # Add initialization for future RedOpsSuite modules here as they are created
# --- END RedOpsSuite MODULE INITIALIZATION ---

# --- END CORE MODULE INITIALIZATION ---

# Import UI components (do this after session state setup to avoid potential issues)
# Wrap UI imports in try-except to catch potential errors during development
try:
    from webgui.sidebar import render_sidebar
    from webgui.home import render_home
    # Import the BlueDefenderX tab controller
    from webgui.tabs_controller_bd import render_tabs
    # Import the RedOpsSuite tab controller if available
    if REDOPS_AVAILABLE:
        from webgui.tabs_controller_redops import render_tabs_redops
    else:
        render_tabs_redops = None # Define as None if not available
except ImportError as e:
    st.error(f"Error importing UI components: {e}")
    st.stop()


# --- Main App Layout ---
def main():
    st.title("🛡️⚔️ BlueDefenderX/RedOpsSuite - Unified Toolkit")

    # --- Mode Selector ---
    # Add a top-level selector to switch between Blue and Red team views
    # Use session state to remember the choice
    # Create a container for the mode selector at the top
    mode_container = st.container()
    with mode_container:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            # Use radio buttons or a selectbox. Radio is more visible.
            selected_mode = st.radio(
                "Select Toolkit Mode:",
                options=['BlueDefenderX', 'RedOpsSuite'],
                index=0 if st.session_state.toolkit_mode == 'BlueDefenderX' else 1,
                horizontal=True,
                key='mode_selector_radio' # Unique key for the widget
            )
            # Update session state if selection changes
            if selected_mode != st.session_state.toolkit_mode:
                st.session_state.toolkit_mode = selected_mode
                # Rerun might be needed to refresh UI immediately, but Streamlit usually handles this
                # st.experimental_rerun() # Uncomment if UI doesn't update as expected

    # --- Conditional Rendering based on Mode ---
    if st.session_state.toolkit_mode == 'BlueDefenderX':
        # Render the BlueDefenderX sidebar for navigation
        render_sidebar(mode='blue')
        # Based on sidebar selection, render the appropriate content
        if st.session_state.get('current_view', 'Home') == 'Home':
            render_home()
        else:
            # This will handle rendering other BlueDefenderX module-specific tabs/pages
            render_tabs(st.session_state.current_view) # Use BD-specific tab controller

    elif st.session_state.toolkit_mode == 'RedOpsSuite' and REDOPS_AVAILABLE:
        # Render the RedOpsSuite sidebar for navigation
        render_sidebar(mode='red')
        # Based on sidebar selection, render the appropriate RedOps content
        # Assuming a similar structure for RedOps tabs
        redops_view = st.session_state.get('current_redops_view', 'Home') # Use a different state key
        if redops_view == 'Home':
             render_home() # Reuse home for now, or create a specific RedOps home
        else:
            # Use RedOps-specific tab controller
            render_tabs_redops(redops_view) # Pass the specific RedOps view name

    elif st.session_state.toolkit_mode == 'RedOpsSuite' and not REDOPS_AVAILABLE:
        st.error("RedOpsSuite is selected, but the modules are not available or could not be imported.")
        st.info("Please ensure the `RedOpsSuite` directory is correctly placed and its modules are importable.")

if __name__ == "__main__":
    main()
