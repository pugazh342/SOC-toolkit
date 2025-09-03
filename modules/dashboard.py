# BlueDefenderX/modules/dashboard.py
import streamlit as st
import pandas as pd
import altair as alt # Streamlit works well with Altair for charts
from collections import Counter
from datetime import datetime, timedelta

# Import logger if needed for internal logging within this module
# from utils.logger import bd_logger

class Dashboard:
    """
    Visualizes real-time security metrics and KPIs from BlueDefenderX modules.
    Aggregates data from session state and presents it via Streamlit components.
    """
    def __init__(self, session_state):
        """
        Initializes the Dashboard with access to Streamlit's session state.

        Args:
            session_state (st.session_state): The Streamlit session state object.
        """
        self.session_state = session_state
        # bd_logger.info("Dashboard module initialized.") # Optional internal logging

    def _get_data_or_default(self, key, default=None):
        """
        Safely retrieves data from session state.

        Args:
            key (str): The key to look up in session_state.
            default: The default value to return if key is not found.

        Returns:
            The value from session_state or the default.
        """
        return self.session_state.get(key, default)

    def _calculate_alert_stats(self, alerts):
        """Calculates statistics from the alerts list."""
        if not alerts:
            return {"total": 0, "by_severity": {}, "by_rule": {}, "recent": []}

        total = len(alerts)
        severity_counts = Counter(alert.get('severity', 'unknown') for alert in alerts)
        rule_counts = Counter(alert.get('rule_id', 'unknown') for alert in alerts)
        
        # Get recent alerts (last 24 hours is arbitrary, could be configurable)
        # Assuming alerts have a 'timestamp' field in ISO format
        now = datetime.utcnow()
        recent_alerts = [
            alert for alert in alerts
            if 'timestamp' in alert and
               (now - datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))).total_seconds() < 86400
        ]
        recent_count = len(recent_alerts)

        return {
            "total": total,
            "by_severity": dict(severity_counts),
            "by_rule": dict(rule_counts),
            "recent_count": recent_count,
            "recent_alerts_sample": recent_alerts[:5] # Show a sample
        }

    def _calculate_log_stats(self, logs):
        """Calculates statistics from the parsed logs list."""
        if not logs:
            return {"total": 0, "by_type": {}, "by_service": {}, "unique_ips": 0}

        total = len(logs)
        type_counts = Counter(log.get('event_type', 'unknown') for log in logs)
        service_counts = Counter(log.get('service', 'unknown') for log in logs)
        unique_ips = len(set(log.get('src_ip') for log in logs if log.get('src_ip')))

        return {
            "total": total,
            "by_type": dict(type_counts),
            "by_service": dict(service_counts),
            "unique_ips": unique_ips
        }

    def _calculate_anomaly_stats(self, anomalies):
        """Calculates statistics from the anomalies list."""
        if not anomalies:
            return {"total": 0, "anomalous": 0, "normal": 0}

        total = len(anomalies)
        anomalous_count = sum(1 for a in anomalies if a.get('is_anomaly', False))
        normal_count = total - anomalous_count

        return {
            "total": total,
            "anomalous": anomalous_count,
            "normal": normal_count
        }

    def _calculate_threat_intel_stats(self, threat_feeds):
        """Calculates statistics from ThreatFeedSync (conceptual)."""
        # This would ideally get data directly from ThreatFeedSync instance or its results
        # For now, we'll assume it's stored in session state or passed in
        # As a placeholder, let's assume threat_feeds is a dict like {'ip': 100, 'domain': 50}
        if not threat_feeds or not isinstance(threat_feeds, dict):
             return {"total_iocs": 0, "by_type": {}}
        
        total = sum(threat_feeds.values())
        return {
            "total_iocs": total,
            "by_type": threat_feeds
        }

    def _calculate_trust_stats(self, trust_scores):
        """Calculates statistics from TrustController scores."""
        # Assume trust_scores is the dict returned by TrustController.get_all_scores()
        if not trust_scores:
            return {"total_entities": 0, "avg_score": 0.0, "low_trust_count": 0, "scores_list": []}

        scores_list = [profile['score'] for profile in trust_scores.values()]
        total_entities = len(scores_list)
        avg_score = sum(scores_list) / total_entities if total_entities > 0 else 0.0
        # Define "low trust" as score < 50 (arbitrary threshold)
        low_trust_count = sum(1 for score in scores_list if score < 50)

        return {
            "total_entities": total_entities,
            "avg_score": round(avg_score, 2),
            "low_trust_count": low_trust_count,
            "scores_list": scores_list
        }

    def render_kpi_summary(self):
        """Renders the main KPI summary cards."""
        st.subheader("📈 Key Performance Indicators")

        # Get data from session state
        alerts = self._get_data_or_default('alerts_cache', [])
        parsed_logs = self._get_data_or_default('parsed_logs_cache', [])
        anomalies = self._get_data_or_default('anomalies_cache', [])
        # Threat Intel data - assuming ThreatFeedSync stores loaded IOCs in session or we get them directly
        # For demo, let's assume a simple count is available or we access the engine
        threat_feed_engine = self._get_data_or_default('threat_intel_engine')
        threat_ioc_summary = {"total_iocs": 0, "by_type": {}}
        if threat_feed_engine and hasattr(threat_feed_engine, 'get_loaded_iocs'):
            threat_ioc_summary = self._calculate_threat_intel_stats(threat_feed_engine.get_loaded_iocs())
        
        # Trust scores - assuming TrustController stores data or we access the engine
        trust_controller = self._get_data_or_default('trust_controller') # If added to session state
        trust_scores_dict = {}
        if trust_controller and hasattr(trust_controller, 'get_all_scores'):
            trust_scores_dict = trust_controller.get_all_scores()
        trust_stats = self._calculate_trust_stats(trust_scores_dict)

        # Calculate stats
        alert_stats = self._calculate_alert_stats(alerts)
        log_stats = self._calculate_log_stats(parsed_logs)
        anomaly_stats = self._calculate_anomaly_stats(anomalies)

        # Display KPIs in columns
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Alerts", alert_stats['total'])
        col2.metric("Events Processed", log_stats['total'])
        col3.metric("Active IOCs", threat_ioc_summary['total_iocs'])
        col4.metric("Entities Scored", trust_stats['total_entities'])

        col5, col6, col7, col8 = st.columns(4)
        col5.metric("Anomalies Found", anomaly_stats['anomalous'])
        col6.metric("Unique Source IPs", log_stats['unique_ips'])
        col7.metric("Avg Trust Score", trust_stats['avg_score'])
        col8.metric("Low Trust Entities", trust_stats['low_trust_count'])

    def render_alert_charts(self):
        """Renders charts related to alerts."""
        st.subheader("🚨 Alert Analysis")

        alerts = self._get_data_or_default('alerts_cache', [])
        if not alerts:
            st.info("No alerts available to display.")
            return

        alert_stats = self._calculate_alert_stats(alerts)

        # Alerts by Severity
        if alert_stats['by_severity']:
            st.write("**Alerts by Severity:**")
            severity_df = pd.DataFrame(list(alert_stats['by_severity'].items()), columns=['Severity', 'Count'])
            severity_chart = alt.Chart(severity_df).mark_bar().encode(
                x='Severity:N',
                y='Count:Q',
                color='Severity:N'
            ).properties(title="Alerts by Severity")
            st.altair_chart(severity_chart, use_container_width=True)

        # Alerts by Rule (Top 10)
        if alert_stats['by_rule']:
            st.write("**Top Alert Rules:**")
            rule_items = list(alert_stats['by_rule'].items())
            rule_items.sort(key=lambda x: x[1], reverse=True)
            top_rules = rule_items[:10]
            rule_df = pd.DataFrame(top_rules, columns=['Rule ID', 'Count'])
            rule_chart = alt.Chart(rule_df).mark_bar().encode(
                x=alt.X('Count:Q', title='Number of Alerts'),
                y=alt.Y('Rule ID:N', sort='-x', title='Rule ID'),
                color=alt.Color('Count:Q', scale=alt.Scale(scheme='blues')) # Color by count
            ).properties(title="Top 10 Alert Rules Triggered")
            st.altair_chart(rule_chart, use_container_width=True)

    def render_log_charts(self):
        """Renders charts related to parsed logs."""
        st.subheader("📜 Log Analysis")

        logs = self._get_data_or_default('parsed_logs_cache', [])
        if not logs:
            st.info("No parsed logs available to display.")
            return

        log_stats = self._calculate_log_stats(logs)

        # Events by Type
        if log_stats['by_type']:
            st.write("**Events by Type:**")
            type_df = pd.DataFrame(list(log_stats['by_type'].items()), columns=['Event Type', 'Count'])
            # Use a pie chart for distribution
            type_chart = alt.Chart(type_df).mark_arc().encode(
                theta=alt.Theta(field="Count", type="quantitative"),
                color=alt.Color(field="Event Type", type="nominal"),
                tooltip=['Event Type:N', 'Count:Q']
            ).properties(title="Distribution of Event Types")
            st.altair_chart(type_chart, use_container_width=True)

        # Events by Service
        if log_stats['by_service']:
            st.write("**Events by Service:**")
            service_df = pd.DataFrame(list(log_stats['by_service'].items()), columns=['Service', 'Count'])
            service_df = service_df.sort_values(by='Count', ascending=False).head(10) # Top 10
            service_chart = alt.Chart(service_df).mark_bar().encode(
                x=alt.X('Count:Q', title='Number of Events'),
                y=alt.Y('Service:N', sort='-x', title='Service'),
                color=alt.Color('Count:Q', scale=alt.Scale(scheme='greens'))
            ).properties(title="Top 10 Services")
            st.altair_chart(service_chart, use_container_width=True)

    def render_trust_charts(self):
        """Renders charts related to trust scores."""
        st.subheader("🛡️ Trust Score Overview")

        trust_controller = self._get_data_or_default('trust_controller')
        trust_scores_dict = {}
        if trust_controller and hasattr(trust_controller, 'get_all_scores'):
            trust_scores_dict = trust_controller.get_all_scores()
        
        trust_stats = self._calculate_trust_stats(trust_scores_dict)

        if not trust_scores_dict:
            st.info("No trust scores available to display.")
            return

        # Distribution of Trust Scores
        st.write("**Distribution of Trust Scores:**")
        scores_df = pd.DataFrame(trust_stats['scores_list'], columns=['Score'])
        # Histogram
        hist_chart = alt.Chart(scores_df).mark_bar().encode(
            alt.X("Score:Q", bin=alt.Bin(maxbins=20), title="Trust Score"),
            alt.Y('count()', title="Number of Entities"),
            color=alt.Color('count()', scale=alt.Scale(scheme='reds'))
        ).properties(title="Trust Score Distribution")
        st.altair_chart(hist_chart, use_container_width=True)

        # List Low Trust Entities (if any)
        if trust_stats['low_trust_count'] > 0:
            st.write("**Entities with Low Trust Score (< 50):**")
            low_trust_entities = [
                (key, profile['score']) for key, profile in trust_scores_dict.items()
                if profile['score'] < 50
            ]
            if low_trust_entities:
                low_trust_df = pd.DataFrame(low_trust_entities, columns=['Entity', 'Score'])
                st.dataframe(low_trust_df.style.highlight_min(color='red', subset=['Score']), use_container_width=True)
            else:
                st.write("No entities currently have a trust score below the threshold.")

    def render_overview(self):
        """
        Renders the main dashboard overview page.
        This is the primary function called by the Streamlit UI.
        """
        st.title("📊 BlueDefenderX - Security Operations Dashboard")

        # 1. Render KPI Summary
        self.render_kpi_summary()

        # 2. Render Alert Charts
        self.render_alert_charts()

        # 3. Render Log Charts
        self.render_log_charts()

        # 4. Render Trust Charts
        self.render_trust_charts()

        # 5. (Optional) Add more sections for Anomalies, Honeypot interactions, etc.
        # For example:
        st.subheader("🧠 Anomaly Detection Summary")
        anomalies = self._get_data_or_default('anomalies_cache', [])
        if anomalies:
            anomaly_stats = self._calculate_anomaly_stats(anomalies)
            st.metric("Total Anomalies Detected", anomaly_stats['anomalous'])
            if anomaly_stats['anomalous'] > 0:
                st.write("Details of detected anomalies can be found in the 'Anomalies' tab.")
        else:
            st.info("No anomaly detection data available.")

        st.subheader("🍯 Honeypot Activity")
        # This would require accessing HoneyPotX data, which is not currently stored in session state
        # in a way that the dashboard can easily consume. A future enhancement.
        st.info("Honeypot activity visualization is planned for a future update.")

        # 6. Footer or Refresh Info
        st.markdown("---")
        st.caption(f"Dashboard last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if st.button("🔄 Refresh Dashboard"):
            st.experimental_rerun() # This will re-run the script, fetching latest data

# Note: This module is designed to be used within the Streamlit app context.
# It does not have a standalone 'if __name__ == "__main__"' block as it relies
# on Streamlit's session state and UI components.
 
