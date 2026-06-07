# aegisx/core/types.py

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid


class ThreatClassification(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MALICIOUS = "malicious"


class ScamType(Enum):
    LOTTERY = "lottery_scam"
    BANK_VERIFICATION = "bank_verification"
    URGENT_PAYMENT = "urgent_payment"
    OTP_THEFT = "otp_theft"
    JOB_SCAM = "job_scam"
    ROMANCE_SCAM = "romance_scam"
    TECH_SUPPORT = "tech_support_scam"
    INVESTMENT = "investment_scam"
    NONE = "none"


class AnomalyType(Enum):
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    NEW_DEVICE = "new_device"
    UNUSUAL_LOCATION = "unusual_location"
    UNUSUAL_TIME = "unusual_time"
    UNUSUAL_TRANSACTION = "unusual_transaction"
    SUSPICIOUS_BROWSING = "suspicious_browsing"
    CREDENTIAL_STUFFING = "credential_stuffing"


@dataclass
class ThreatScore:
    value: float  # 0-100
    confidence: float  # 0-1
    factors: dict[str, float] = field(default_factory=dict)
    
    def __post_init__(self):
        self.value = max(0.0, min(100.0, self.value))
        self.confidence = max(0.0, min(1.0, self.confidence))


@dataclass
class DetectionResult:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    classification: ThreatClassification = ThreatClassification.SAFE
    threat_score: ThreatScore = field(default_factory=lambda: ThreatScore(0, 0))
    scam_types: list[ScamType] = field(default_factory=list)
    anomalies: list[AnomalyType] = field(default_factory=list)
    explanation: str = ""
    raw_signals: dict = field(default_factory=dict)
