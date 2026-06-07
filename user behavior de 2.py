# aegisx/digital_twin/anomaly_detector.py

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from aegisx.core.types import AnomalyType, ThreatScore, DetectionResult
from aegisx.core.config import AegisXConfig
from aegisx.digital_twin.profile import (
    DigitalTwinProfile, LoginEvent, Transaction, GeoLocation
)


@dataclass
class AnomalyResult:
    anomaly_type: AnomalyType
    severity: float  # 0-1
    details: str


class BehaviorAnomalyDetector:
    """
    Detect behavioral anomalies by comparing current activity
    against the user's Digital Twin profile.
    """
    
    def __init__(self, config: AegisXConfig):
        self.config = config
    
    def analyze_login(
        self, profile: DigitalTwinProfile, event: LoginEvent
    ) -> DetectionResult:
        """Check login event against user's baseline."""
        anomalies = []
        
        # 1. Impossible travel detection
        travel_anomaly = self._check_impossible_travel(profile, event)
        if travel_anomaly:
            anomalies.append(travel_anomaly)
        
        # 2. New device detection
        device_anomaly = self._check_new_device(profile, event)
        if device_anomaly:
            anomalies.append(device_anomaly)
        
        # 3. Unusual location
        location_anomaly = self._check_unusual_location(profile, event)
        if location_anomaly:
            anomalies.append(location_anomaly)
        
        # 4. Unusual time
        time_anomaly = self._check_unusual_time(profile, event)
        if time_anomaly:
            anomalies.append(time_anomaly)
        
        return self._build_result(anomalies)
    
    def analyze_transaction(
        self, profile: DigitalTwinProfile, transaction: Transaction
    ) -> DetectionResult:
        """Check transaction against spending baseline."""
        anomalies = []
        
        # Unusual amount
        if profile.avg_transaction_amount > 0:
            z_score = abs(
                transaction.amount - profile.avg_transaction_amount
            ) / max(profile._transaction_std, 1)
            
            if z_score > self.config.thresholds.anomaly_sensitivity:
                anomalies.append(AnomalyResult(
                    anomaly_type=AnomalyType.UNUSUAL_TRANSACTION,
                    severity=min(z_score / 5, 1.0),
                    details=f"Transaction ${transaction.amount:.2f} is {z_score:.1f}σ from average ${profile.avg_transaction_amount:.2f}"
                ))
        
        # New merchant category
        if transaction.merchant_category not in profile.typical_merchants:
            anomalies.append(AnomalyResult(
                anomaly_type=AnomalyType.UNUSUAL_TRANSACTION,
                severity=0.3,
                details=f"First transaction in category: {transaction.merchant_category}"
            ))
        
        return self._build_result(anomalies)
    
    def _check_impossible_travel(
        self, profile: DigitalTwinProfile, event: LoginEvent
    ) -> Optional[AnomalyResult]:
        """Detect if user couldn't physically travel between logins."""
        # Need last login location and time
        last_login = self._get_last_login(profile)
        if not last_login:
            return None
        
        distance_km = event.location.distance_km(last_login.location)
        time_delta = event.timestamp - last_login.timestamp
        hours = time_delta.total_seconds() / 3600
        
        if hours <= 0:
            return None
        
        required_speed = distance_km / hours
        
        if required_speed > self.config.thresholds.impossible_travel_speed_kmh:
            return AnomalyResult(
                anomaly_type=AnomalyType.IMPOSSIBLE_TRAVEL,
                severity=min(required_speed / 2000, 1.0),
                details=f"Login from {event.location.city or 'unknown'} requires {required_speed:.0f} km/h travel from previous location"
            )
        
        return None
    
    def _check_new_device(
        self, profile: DigitalTwinProfile, event: LoginEvent
    ) -> Optional[AnomalyResult]:
        """Detect first-time device."""
        if event.device.device_id not in profile.known_devices:
            return AnomalyResult(
                anomaly_type=AnomalyType.NEW_DEVICE,
                severity=0.5,
                details=f"First login from {event.device.device_type} ({event.device.os})"
            )
        return None
    
    def _check_unusual_location(
        self, profile: DigitalTwinProfile, event: LoginEvent
    ) -> Optional[AnomalyResult]:
        """Detect login from unknown location."""
        for known in profile.known_locations:
            if event.location.distance_km(known) < profile._location_radius_km:
                return None  # Within known location
        
        return AnomalyResult(
            anomaly_type=AnomalyType.UNUSUAL_LOCATION,
            severity=0.6,
            details=f"Login from new location: {event.location.city or 'unknown'}, {event.location.country or 'unknown'}"
        )
    
    def _check_unusual_time(
        self, profile: DigitalTwinProfile, event: LoginEvent
    ) -> Optional[AnomalyResult]:
        """Detect login outside typical hours."""
        hour = event.timestamp.hour
        start, end = profile.typical_login_hours
        
        if hour < start or hour > end:
            return AnomalyResult(
                anomaly_type=AnomalyType.UNUSUAL_TIME,
                severity=0.4,
                details=f"Login at {hour:02d}:00 outside typical hours ({start:02d}:00-{end:02d}:00)"
            )
        
        if event.timestamp.weekday() not in profile.typical_days:
            return AnomalyResult(
                anomaly_type=AnomalyType.UNUSUAL_TIME,
                severity=0.3,
                details="Login on atypical day of week"
            )
        
        return None
    
    def _get_last_login(self, profile: DigitalTwinProfile) -> Optional[LoginEvent]:
        """Get most recent login event (would query storage in production)."""
        # Placeholder - in production, query event store
        return None
    
    def _build_result(self, anomalies: list[AnomalyResult]) -> DetectionResult:
        """Combine anomalies into detection result."""
        if not anomalies:
            return DetectionResult(
                classification=ThreatClassification.SAFE,
                threat_score=ThreatScore(0, 0.9),
                explanation="Activity matches established behavioral patterns."
            )
        
        max_severity = max(a.severity for a in anomalies)
        combined_score = min(sum(a.severity for a in anomalies) * 30, 100)
        
        from aegisx.core.types import ThreatClassification
        
        if combined_score >= 70:
            classification = ThreatClassification.MALICIOUS
        elif combined_score >= 40:
            classification = ThreatClassification.SUSPICIOUS
        else:
            classification = ThreatClassification.SAFE
        
        return DetectionResult(
            classification=classification,
            threat_score=ThreatScore(
                value=combined_score,
                confidence=0.75,
                factors={a.anomaly_type.value: a.severity for a in anomalies}
            ),
            anomalies=[a.anomaly_type for a in anomalies],
            explanation=" • ".join(a.details for a in anomalies)
        )
