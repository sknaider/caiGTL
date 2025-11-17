"""
GTL Threat Detector - ML-Based Anomaly Detection
Real-time threat detection using machine learning and behavioral analysis
"""

import asyncio
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import logging
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class ThreatEvent:
    """Threat detection event"""
    event_id: str
    timestamp: datetime
    threat_type: str  # malware, intrusion, anomaly, bruteforce, data_exfiltration
    severity: str  # critical, high, medium, low
    confidence_score: float  # 0.0 - 1.0
    source_ip: Optional[str]
    destination_ip: Optional[str]
    description: str
    indicators: Dict[str, Any]  # IOCs
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    raw_data: Dict[str, Any]


@dataclass
class NetworkBehavior:
    """Network behavior metrics for anomaly detection"""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    connection_duration: float
    protocol: str
    destination_port: int
    failed_connections: int
    unique_destinations: int
    dns_queries: int


class AnomalyDetector:
    """
    ML-based anomaly detector using Isolation Forest
    Detects unusual network behavior patterns
    """

    def __init__(self, contamination: float = 0.1):
        """
        Initialize anomaly detector

        Args:
            contamination: Expected proportion of anomalies (0.1 = 10%)
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
            'connection_duration', 'destination_port', 'failed_connections',
            'unique_destinations', 'dns_queries', 'hour_of_day', 'day_of_week'
        ]

    def extract_features(self, behavior: NetworkBehavior) -> np.ndarray:
        """Extract features from network behavior"""
        features = [
            behavior.bytes_sent,
            behavior.bytes_received,
            behavior.packets_sent,
            behavior.packets_received,
            behavior.connection_duration,
            behavior.destination_port,
            behavior.failed_connections,
            behavior.unique_destinations,
            behavior.dns_queries,
            behavior.timestamp.hour,
            behavior.timestamp.weekday(),
        ]
        return np.array(features).reshape(1, -1)

    def train(self, historical_behaviors: List[NetworkBehavior]) -> None:
        """
        Train anomaly detector on historical data

        Args:
            historical_behaviors: List of normal network behaviors
        """
        logger.info(f"Training anomaly detector on {len(historical_behaviors)} samples")

        # Extract features
        X = np.array([
            self.extract_features(b).flatten()
            for b in historical_behaviors
        ])

        # Fit scaler and model
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True

        logger.info("Anomaly detector training completed")

    def detect(self, behavior: NetworkBehavior) -> Tuple[bool, float]:
        """
        Detect if behavior is anomalous

        Args:
            behavior: Network behavior to analyze

        Returns:
            (is_anomaly, anomaly_score) tuple
            - is_anomaly: True if anomalous, False if normal
            - anomaly_score: Anomaly score (lower = more anomalous)
        """
        if not self.is_trained:
            raise ValueError("Detector must be trained before detecting anomalies")

        # Extract and scale features
        X = self.extract_features(behavior)
        X_scaled = self.scaler.transform(X)

        # Predict
        prediction = self.model.predict(X_scaled)[0]  # -1 for anomaly, 1 for normal
        anomaly_score = self.model.score_samples(X_scaled)[0]

        is_anomaly = (prediction == -1)

        # Convert score to 0-1 range (higher = more anomalous)
        normalized_score = 1 / (1 + np.exp(anomaly_score))  # Sigmoid

        return is_anomaly, normalized_score


class ThreatDetectionEngine:
    """Main threat detection engine combining multiple detection methods"""

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.threat_intelligence = ThreatIntelligence()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.signature_matcher = SignatureMatcher()

    async def analyze(self, event_data: Dict[str, Any]) -> Optional[ThreatEvent]:
        """
        Analyze event for threats using multiple detection methods

        Args:
            event_data: Raw event data (network logs, system logs, etc.)

        Returns:
            ThreatEvent if threat detected, None otherwise
        """
        threats = []

        # 1. Anomaly-based detection
        anomaly_threat = await self._detect_anomaly(event_data)
        if anomaly_threat:
            threats.append(anomaly_threat)

        # 2. Signature-based detection
        signature_threat = await self._detect_signature(event_data)
        if signature_threat:
            threats.append(signature_threat)

        # 3. Behavioral analysis
        behavioral_threat = await self._detect_behavioral(event_data)
        if behavioral_threat:
            threats.append(behavioral_threat)

        # 4. Threat intelligence correlation
        intel_threat = await self._correlate_threat_intel(event_data)
        if intel_threat:
            threats.append(intel_threat)

        # Return highest severity threat
        if threats:
            return max(threats, key=lambda t: self._severity_score(t.severity))

        return None

    async def _detect_anomaly(self, event_data: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect anomalies using ML"""
        try:
            # Convert event to NetworkBehavior
            behavior = self._event_to_behavior(event_data)

            if not behavior:
                return None

            # Detect anomaly
            is_anomaly, score = self.anomaly_detector.detect(behavior)

            if is_anomaly and score > 0.7:  # High confidence threshold
                return ThreatEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.utcnow(),
                    threat_type="anomaly",
                    severity=self._score_to_severity(score),
                    confidence_score=score,
                    source_ip=behavior.source_ip,
                    destination_ip=behavior.destination_ip,
                    description=f"Anomalous network behavior detected from {behavior.source_ip}",
                    indicators={
                        "anomaly_score": score,
                        "bytes_sent": behavior.bytes_sent,
                        "unique_destinations": behavior.unique_destinations,
                    },
                    mitre_tactics=["TA0001"],  # Initial Access
                    mitre_techniques=["T1078"],  # Valid Accounts
                    raw_data=event_data
                )

        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")

        return None

    async def _detect_signature(self, event_data: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect known attack signatures"""
        try:
            # Check for known attack patterns
            matches = self.signature_matcher.match(event_data)

            if matches:
                highest_severity = matches[0]  # Assuming sorted by severity

                return ThreatEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.utcnow(),
                    threat_type=highest_severity['type'],
                    severity=highest_severity['severity'],
                    confidence_score=0.95,  # High confidence for signature matches
                    source_ip=event_data.get('source_ip'),
                    destination_ip=event_data.get('destination_ip'),
                    description=highest_severity['description'],
                    indicators=highest_severity['indicators'],
                    mitre_tactics=highest_severity.get('mitre_tactics', []),
                    mitre_techniques=highest_severity.get('mitre_techniques', []),
                    raw_data=event_data
                )

        except Exception as e:
            logger.error(f"Error in signature detection: {e}")

        return None

    async def _detect_behavioral(self, event_data: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect behavioral anomalies"""
        try:
            # Analyze user/system behavior
            result = await self.behavioral_analyzer.analyze(event_data)

            if result and result['is_suspicious']:
                return ThreatEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.utcnow(),
                    threat_type=result['threat_type'],
                    severity=result['severity'],
                    confidence_score=result['confidence'],
                    source_ip=event_data.get('source_ip'),
                    destination_ip=event_data.get('destination_ip'),
                    description=result['description'],
                    indicators=result['indicators'],
                    mitre_tactics=result.get('mitre_tactics', []),
                    mitre_techniques=result.get('mitre_techniques', []),
                    raw_data=event_data
                )

        except Exception as e:
            logger.error(f"Error in behavioral detection: {e}")

        return None

    async def _correlate_threat_intel(self, event_data: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Correlate with threat intelligence feeds"""
        try:
            source_ip = event_data.get('source_ip')
            destination_ip = event_data.get('destination_ip')

            # Check IPs against threat feeds
            threats = []

            if source_ip:
                threat = await self.threat_intelligence.lookup_ip(source_ip)
                if threat:
                    threats.append(('source', threat))

            if destination_ip:
                threat = await self.threat_intelligence.lookup_ip(destination_ip)
                if threat:
                    threats.append(('destination', threat))

            if threats:
                direction, threat_info = threats[0]

                return ThreatEvent(
                    event_id=self._generate_event_id(),
                    timestamp=datetime.utcnow(),
                    threat_type=threat_info.get('type', 'malicious_ip'),
                    severity=threat_info.get('severity', 'high'),
                    confidence_score=threat_info.get('confidence', 0.9),
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    description=f"Communication with known malicious IP ({direction}): {threat_info.get('description', 'No description')}",
                    indicators={
                        'malicious_ip': source_ip if direction == 'source' else destination_ip,
                        'threat_actor': threat_info.get('threat_actor'),
                        'first_seen': threat_info.get('first_seen'),
                    },
                    mitre_tactics=threat_info.get('mitre_tactics', []),
                    mitre_techniques=threat_info.get('mitre_techniques', []),
                    raw_data=event_data
                )

        except Exception as e:
            logger.error(f"Error in threat intelligence correlation: {e}")

        return None

    def _event_to_behavior(self, event_data: Dict[str, Any]) -> Optional[NetworkBehavior]:
        """Convert raw event to NetworkBehavior object"""
        try:
            return NetworkBehavior(
                timestamp=datetime.fromisoformat(event_data.get('timestamp', datetime.utcnow().isoformat())),
                source_ip=event_data.get('source_ip', ''),
                destination_ip=event_data.get('destination_ip', ''),
                bytes_sent=event_data.get('bytes_sent', 0),
                bytes_received=event_data.get('bytes_received', 0),
                packets_sent=event_data.get('packets_sent', 0),
                packets_received=event_data.get('packets_received', 0),
                connection_duration=event_data.get('duration', 0.0),
                protocol=event_data.get('protocol', 'TCP'),
                destination_port=event_data.get('destination_port', 0),
                failed_connections=event_data.get('failed_connections', 0),
                unique_destinations=event_data.get('unique_destinations', 1),
                dns_queries=event_data.get('dns_queries', 0),
            )
        except Exception as e:
            logger.error(f"Error converting event to behavior: {e}")
            return None

    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        import secrets
        return f"THR-{secrets.token_hex(8).upper()}"

    def _severity_score(self, severity: str) -> int:
        """Convert severity to numeric score"""
        severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
        }
        return severity_map.get(severity.lower(), 0)

    def _score_to_severity(self, score: float) -> str:
        """Convert anomaly score to severity level"""
        if score >= 0.9:
            return 'critical'
        elif score >= 0.75:
            return 'high'
        elif score >= 0.5:
            return 'medium'
        else:
            return 'low'


class BehavioralAnalyzer:
    """Analyzes user and system behavior for suspicious patterns"""

    def __init__(self):
        self.baselines = {}  # User/system baselines

    async def analyze(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze event for behavioral anomalies"""

        # Check for brute force attacks
        if self._is_brute_force(event_data):
            return {
                'is_suspicious': True,
                'threat_type': 'bruteforce',
                'severity': 'high',
                'confidence': 0.9,
                'description': 'Brute force attack detected',
                'indicators': {
                    'failed_attempts': event_data.get('failed_login_attempts', 0),
                    'time_window': '5 minutes'
                },
                'mitre_tactics': ['TA0006'],  # Credential Access
                'mitre_techniques': ['T1110'],  # Brute Force
            }

        # Check for data exfiltration
        if self._is_data_exfiltration(event_data):
            return {
                'is_suspicious': True,
                'threat_type': 'data_exfiltration',
                'severity': 'critical',
                'confidence': 0.85,
                'description': 'Possible data exfiltration detected',
                'indicators': {
                    'bytes_transferred': event_data.get('bytes_sent', 0),
                    'destination': event_data.get('destination_ip')
                },
                'mitre_tactics': ['TA0010'],  # Exfiltration
                'mitre_techniques': ['T1041'],  # Exfiltration Over C2 Channel
            }

        # Check for privilege escalation
        if self._is_privilege_escalation(event_data):
            return {
                'is_suspicious': True,
                'threat_type': 'privilege_escalation',
                'severity': 'high',
                'confidence': 0.8,
                'description': 'Privilege escalation attempt detected',
                'indicators': {
                    'user': event_data.get('user'),
                    'command': event_data.get('command')
                },
                'mitre_tactics': ['TA0004'],  # Privilege Escalation
                'mitre_techniques': ['T1068'],  # Exploitation for Privilege Escalation
            }

        return None

    def _is_brute_force(self, event_data: Dict[str, Any]) -> bool:
        """Detect brute force attacks"""
        failed_attempts = event_data.get('failed_login_attempts', 0)
        return failed_attempts >= 5

    def _is_data_exfiltration(self, event_data: Dict[str, Any]) -> bool:
        """Detect data exfiltration"""
        bytes_sent = event_data.get('bytes_sent', 0)
        # Threshold: 100 MB in single transfer
        return bytes_sent > 100 * 1024 * 1024

    def _is_privilege_escalation(self, event_data: Dict[str, Any]) -> bool:
        """Detect privilege escalation"""
        suspicious_commands = ['sudo', 'su', 'chmod 777', 'setuid']
        command = event_data.get('command', '').lower()
        return any(cmd in command for cmd in suspicious_commands)


class SignatureMatcher:
    """Matches events against known attack signatures"""

    def __init__(self):
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> List[Dict[str, Any]]:
        """Load attack signatures database"""
        return [
            # SQL Injection
            {
                'name': 'SQL Injection',
                'type': 'injection',
                'severity': 'critical',
                'pattern': r"(\bOR\b|\bAND\b).*[=<>]|';.*--|UNION.*SELECT",
                'description': 'SQL injection attempt detected',
                'indicators': {'attack_type': 'sql_injection'},
                'mitre_tactics': ['TA0001'],
                'mitre_techniques': ['T1190'],
            },
            # XSS
            {
                'name': 'Cross-Site Scripting (XSS)',
                'type': 'injection',
                'severity': 'high',
                'pattern': r'<script|javascript:|onerror=|onload=',
                'description': 'XSS attack attempt detected',
                'indicators': {'attack_type': 'xss'},
                'mitre_tactics': ['TA0001'],
                'mitre_techniques': ['T1189'],
            },
            # Port Scan
            {
                'name': 'Port Scan',
                'type': 'reconnaissance',
                'severity': 'medium',
                'pattern': 'port_scan',
                'description': 'Port scanning activity detected',
                'indicators': {'attack_type': 'port_scan'},
                'mitre_tactics': ['TA0043'],  # Reconnaissance
                'mitre_techniques': ['T1046'],  # Network Service Scanning
            },
        ]

    def match(self, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match event against signatures"""
        import re

        matches = []

        # Check request parameters for injection patterns
        request_params = event_data.get('request_params', {})
        request_body = event_data.get('request_body', '')
        user_agent = event_data.get('user_agent', '')

        all_input = ' '.join([
            str(request_params),
            str(request_body),
            str(user_agent)
        ])

        for signature in self.signatures:
            if re.search(signature['pattern'], all_input, re.IGNORECASE):
                matches.append(signature)

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        matches.sort(key=lambda x: severity_order.get(x['severity'], 999))

        return matches


class ThreatIntelligence:
    """Threat intelligence integration"""

    def __init__(self):
        self.cache = {}  # IP reputation cache
        self.cache_ttl = timedelta(hours=24)

    async def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Lookup IP in threat intelligence feeds

        Args:
            ip: IP address to check

        Returns:
            Threat information if IP is malicious, None otherwise
        """
        # Check cache
        if ip in self.cache:
            cached_data, cached_time = self.cache[ip]
            if datetime.utcnow() - cached_time < self.cache_ttl:
                return cached_data

        # TODO: Integrate with real threat intelligence APIs
        # - AlienVault OTX
        # - AbuseIPDB
        # - VirusTotal
        # - Shodan
        # - Greynoise

        # Simulated response for now
        malicious_ips = [
            '192.0.2.1',  # Example malicious IP
            '198.51.100.1',
        ]

        if ip in malicious_ips:
            threat_info = {
                'type': 'malicious_ip',
                'severity': 'high',
                'confidence': 0.95,
                'description': 'IP associated with known malware C2',
                'threat_actor': 'APT28',
                'first_seen': '2024-01-01',
                'mitre_tactics': ['TA0011'],  # Command and Control
                'mitre_techniques': ['T1071'],  # Application Layer Protocol
            }

            # Cache result
            self.cache[ip] = (threat_info, datetime.utcnow())

            return threat_info

        # Cache negative result
        self.cache[ip] = (None, datetime.utcnow())
        return None


# Main detection loop
class ThreatDetectionService:
    """Background service for continuous threat detection"""

    def __init__(self):
        self.engine = ThreatDetectionEngine()
        self.running = False

    async def start(self):
        """Start threat detection service"""
        self.running = True
        logger.info("Threat detection service started")

        while self.running:
            try:
                # TODO: Pull events from queue/stream
                # - Network logs from firewall
                # - Application logs
                # - System logs
                # - API requests

                # For now, simulate
                await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"Error in threat detection loop: {e}")
                await asyncio.sleep(5)

    async def stop(self):
        """Stop threat detection service"""
        self.running = False
        logger.info("Threat detection service stopped")


# Export main classes
__all__ = [
    'ThreatDetectionEngine',
    'ThreatEvent',
    'AnomalyDetector',
    'BehavioralAnalyzer',
    'SignatureMatcher',
    'ThreatIntelligence',
    'ThreatDetectionService',
]
