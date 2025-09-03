# BlueDefenderX/modules/anomalydetector.py
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from datetime import datetime
from utils.logger import bd_logger

class AnomalyDetector:
    """
    A class for detecting anomalies in parsed log data using various methods.
    Currently supports Isolation Forest and Z-Score.
    """
    def __init__(self, method='isolation_forest', contamination=0.1, random_state=42, zscore_threshold=3.0):
        """
        Initializes the AnomalyDetector.

        Args:
            method (str): The anomaly detection method to use ('isolation_forest' or 'zscore'). Default is 'isolation_forest'.
            contamination (float): The expected proportion of outliers in the data for Isolation Forest.
                                   Should be in (0, 0.5]. Default is 0.1.
            random_state (int): Random state for reproducibility for Isolation Forest. Default is 42.
            zscore_threshold (float): The Z-Score threshold for anomaly detection. Data points with
                                      absolute Z-Score greater than this value are considered anomalies.
                                      Default is 3.0.
        """
        self.method = method
        self.contamination = contamination
        self.random_state = random_state
        self.zscore_threshold = zscore_threshold
        
        if self.method == 'isolation_forest':
            self.model = IsolationForest(contamination=self.contamination, random_state=self.random_state)
        elif self.method == 'zscore':
            self.scaler = StandardScaler()
        else:
            raise ValueError(f"Unsupported method: {self.method}. Supported methods are 'isolation_forest' and 'zscore'.")
            
        self.label_encoders = {}
        self.is_fitted = False
        bd_logger.info(f"AnomalyDetector initialized with method={self.method}, contamination={self.contamination}, zscore_threshold={self.zscore_threshold}")

    def prepare_features(self, parsed_logs):
        """
        Prepares a DataFrame of features from parsed logs suitable for ML.
        This is a basic example. Feature engineering can be much more complex.

        Args:
            parsed_logs (list): A list of dictionaries representing parsed log events.

        Returns:
            pd.DataFrame: A DataFrame with numerical/categorical features.
        """
        if not parsed_logs:
            bd_logger.warning("No parsed logs provided for feature preparation.")
            return pd.DataFrame()

        df_logs = pd.DataFrame(parsed_logs)
        
        # Select basic features. In practice, you'd engineer more complex ones.
        # For example, time-based features (hour of day), count aggregations, etc.
        # Focus on numerical features for Z-Score, include categorical for Isolation Forest
        features_to_use = ['src_ip', 'service', 'event_type', 'hostname']
        # Only use features that exist in the data
        available_features = [f for f in features_to_use if f in df_logs.columns]
        
        if not available_features:
            bd_logger.error("No suitable features found in parsed logs for anomaly detection.")
            return pd.DataFrame()

        df_features = df_logs[available_features].copy()

        # Handle categorical features using Label Encoding (mainly for Isolation Forest)
        # For Z-Score, we'll focus on numerical features derived from these or others.
        for col in df_features.select_dtypes(include=['object']).columns:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
                df_features[col] = self.label_encoders[col].fit_transform(df_features[col].astype(str))
            else:
                # Handle unseen labels by assigning a default value (e.g., -1)
                try:
                    df_features[col] = self.label_encoders[col].transform(df_features[col].astype(str))
                except ValueError as e:
                    bd_logger.warning(f"Label encoding error for column {col}: {e}. Assigning -1 to unseen labels.")
                    # A simple way to handle unseen labels is to map them to a default class
                    # This is a basic approach. More robust methods exist.
                    le = self.label_encoders[col]
                    # Get the mapping
                    classes = le.classes_
                    # Create a map from value to index
                    value_to_index = {v: i for i, v in enumerate(classes)}
                    # Define a default index (e.g., one more than the last class index)
                    default_index = len(classes) 
                    
                    def map_value(val):
                        return value_to_index.get(val, default_index)
                    
                    df_features[col] = df_features[col].astype(str).map(map_value).fillna(default_index)

        # Handle any remaining missing numerical values
        df_features.fillna(-1, inplace=True) # Or use df_features.mean() etc.

        bd_logger.info(f"Prepared features for anomaly detection: {list(df_features.columns)}")
        return df_features

    def _detect_with_isolation_forest(self, df_features):
        """
        Detects anomalies using the Isolation Forest algorithm.

        Args:
            df_features (pd.DataFrame): The DataFrame of features.

        Returns:
            tuple: (predictions, scores) where predictions are 1 for inliers, -1 for outliers,
                   and scores are the anomaly scores.
        """
        if not self.is_fitted:
            bd_logger.info("Fitting Isolation Forest model...")
            self.model.fit(df_features)
            self.is_fitted = True

        bd_logger.info("Predicting anomalies with Isolation Forest...")
        # predict returns 1 for inliers, -1 for outliers
        predictions = self.model.predict(df_features)
        # decision_function gives an anomaly score (lower is more anomalous)
        scores = self.model.decision_function(df_features)
        return predictions, scores

    def _detect_with_zscore(self, df_features):
        """
        Detects anomalies using the Z-Score method.
        An anomaly is identified if the absolute Z-Score of any feature for a data point
        exceeds the `zscore_threshold`.

        Args:
            df_features (pd.DataFrame): The DataFrame of features.

        Returns:
            tuple: (predictions, scores) where predictions are 1 for inliers, -1 for outliers,
                   and scores are the maximum absolute Z-Score across features for each point.
        """
        # Select only numerical columns for Z-Score calculation
        # In this basic example, we assume all features prepared are numerical after encoding.
        # A more robust version would explicitly select numerical columns.
        numerical_features = df_features.select_dtypes(include=[np.number]).columns.tolist()
        
        if not numerical_features:
            bd_logger.warning("No numerical features found for Z-Score calculation. All points will be considered normal.")
            return np.ones(len(df_features)), np.zeros(len(df_features))

        df_numerical = df_features[numerical_features]
        
        # Fit the scaler on the numerical features
        if not self.is_fitted:
            bd_logger.info("Fitting StandardScaler for Z-Score calculation...")
            self.scaler.fit(df_numerical)
            self.is_fitted = True

        # Transform the data
        bd_logger.info("Calculating Z-Scores...")
        scaled_data = self.scaler.transform(df_numerical)
        
        # Calculate Z-Scores (scaled_data is already standardized, so Z-Score is the value itself)
        z_scores = pd.DataFrame(scaled_data, columns=numerical_features)
        
        # Determine anomalies: if the absolute Z-Score of ANY feature exceeds the threshold
        # Calculate the maximum absolute Z-Score for each row
        max_abs_z_scores = z_scores.abs().max(axis=1)
        
        # Predictions: -1 for anomaly, 1 for normal
        predictions = np.where(max_abs_z_scores > self.zscore_threshold, -1, 1)
        
        # Scores: Use the max absolute Z-Score as the anomaly score (higher = more anomalous)
        scores = max_abs_z_scores.values
        
        return predictions, scores

    def detect(self, parsed_logs):
        """
        Detects anomalies in a list of parsed log events.

        Args:
            parsed_logs (list): A list of dictionaries representing parsed log events.

        Returns:
            list: A list of dictionaries, each containing the original log event and an 'is_anomaly' flag.
        """
        if not parsed_logs:
            bd_logger.warning("No parsed logs provided for anomaly detection.")
            return []

        # --- ALWAYS RESET STATE FOR NEW DATA ---
        # Reset encoders and model state for each detection run
        # This prevents issues with unseen labels from previous runs.
        self.label_encoders = {}
        self.is_fitted = False
        # For Z-Score, also reset the scaler if used
        if self.method == 'zscore':
             self.scaler = StandardScaler()
        # --- END RESET ---

        df_features = self.prepare_features(parsed_logs)
        if df_features.empty:
             return [{"raw_event": event, "is_anomaly": False, "anomaly_score": None} for event in parsed_logs]

        try:
            if self.method == 'isolation_forest':
                predictions, scores = self._detect_with_isolation_forest(df_features)
            elif self.method == 'zscore':
                predictions, scores = self._detect_with_zscore(df_features)
            else:
                # This case should ideally not be reached due to __init__ check, but added for robustness
                raise ValueError(f"Detection method '{self.method}' is not implemented in the detect function.")

            # Add results back to the original logs
            results = []
            for i, log_event in enumerate(parsed_logs):
                results.append({
                    "raw_event": log_event,
                    "is_anomaly": bool(predictions[i] == -1),
                    "anomaly_score": float(scores[i])
                })
            
            anomaly_count = sum(1 for r in results if r['is_anomaly'])
            bd_logger.info(f"Anomaly detection ({self.method}) complete. Found {anomaly_count} anomalies out of {len(results)} events.")
            return results

        except Exception as e:
            bd_logger.error(f"Error during anomaly detection ({self.method}): {e}", exc_info=True)
            # Return logs with no anomaly flag if detection fails
            return [{"raw_event": event, "is_anomaly": False, "anomaly_score": None} for event in parsed_logs]

    def retrain(self, parsed_logs):
        """
        Retrains the model on new data. Resets the fitted state.

        Args:
            parsed_logs (list): A list of dictionaries representing parsed log events.
        """
        self.is_fitted = False
        self.label_encoders = {} # Reset encoders
        # For Z-Score, also reset the scaler
        if self.method == 'zscore':
             self.scaler = StandardScaler()
        bd_logger.info("AnomalyDetector model reset for retraining.")
        return self.detect(parsed_logs) # This will trigger a new fit

# Example usage (can be run as a script for testing)
if __name__ == '__main__':
    # Simulate some parsed log data
    sample_logs = [
        {"src_ip": "192.168.1.100", "service": "sshd", "event_type": "ssh_failed_login", "hostname": "server1"},
        {"src_ip": "192.168.1.100", "service": "sshd", "event_type": "ssh_failed_login", "hostname": "server1"},
        {"src_ip": "192.168.1.100", "service": "sshd", "event_type": "ssh_failed_login", "hostname": "server1"},
        {"src_ip": "192.168.1.100", "service": "sshd", "event_type": "ssh_failed_login", "hostname": "server1"},
        {"src_ip": "192.168.1.100", "service": "sshd", "event_type": "ssh_failed_login", "hostname": "server1"},
        {"src_ip": "10.0.0.1", "service": "sshd", "event_type": "ssh_successful_login", "hostname": "server1"},
        {"src_ip": "172.16.0.5", "service": "apache2", "event_type": "web_access", "hostname": "webserver1"},
        # --- Anomalous events ---
        {"src_ip": "8.8.8.8", "service": "sshd", "event_type": "ssh_failed_login", "hostname": "server1"}, # Unusual IP
        {"src_ip": "172.16.5.100", "service": "sshd", "event_type": "ssh_failed_login", "hostname": "server2"}, # Unusual IP
    ]

    print("--- Testing Isolation Forest ---")
    detector_if = AnomalyDetector(method='isolation_forest', contamination=0.1)
    print("Running initial detection...")
    results_if = detector_if.detect(sample_logs)
    
    for result in results_if:
        log = result['raw_event']
        is_anom = result['is_anomaly']
        score = result['anomaly_score']
        print(f"Event: {log} -> Anomaly: {is_anom}, Score: {score:.4f}")

    print("\n--- Testing Z-Score ---")
    detector_z = AnomalyDetector(method='zscore', zscore_threshold=2.0) # Lower threshold for demo
    print("Running initial detection...")
    results_z = detector_z.detect(sample_logs)
    
    for result in results_z:
        log = result['raw_event']
        is_anom = result['is_anomaly']
        score = result['anomaly_score']
        print(f"Event: {log} -> Anomaly: {is_anom}, Score: {score:.4f}")
