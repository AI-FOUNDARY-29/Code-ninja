# aegisx/detectors/scam_detector.py

import re
from dataclasses import dataclass
from typing import Optional

from aegisx.core.types import (
    ThreatClassification, ThreatScore, DetectionResult, ScamType
)
from aegisx.core.config import AegisXConfig


@dataclass
class MessageData:
    content: str
    sender: Optional[str] = None
    channel: str = "sms"  # sms, email, chat, social


class ScamDetector:
    """
    Pattern-based + ML scam detection for various scam categories.
    """
    
    SCAM_PATTERNS = {
        ScamType.LOTTERY: [
            r'you\s+(have\s+)?won',
            r'lottery\s+winner',
            r'prize\s+of\s+\$?\d+',
            r'claim\s+(your\s+)?prize',
            r'congratulations.*winner',
            r'selected\s+as\s+(a\s+)?winner',
        ],
        ScamType.BANK_VERIFICATION: [
            r'verify\s+(your\s+)?bank',
            r'account\s+(has\s+been\s+)?suspended',
            r'unusual\s+(bank\s+)?activity',
            r'confirm\s+(your\s+)?(bank\s+)?details',
            r'update\s+(your\s+)?payment\s+information',
            r'card\s+(has\s+been\s+)?blocked',
        ],
        ScamType.URGENT_PAYMENT: [
            r'urgent\s+payment',
            r'pay\s+(immediately|now|within)',
            r'overdue\s+(payment|invoice)',
            r'legal\s+action.*pay',
            r'arrest\s+warrant.*pay',
            r'irs.*owe',
        ],
        ScamType.OTP_THEFT: [
            r'share\s+(your\s+)?otp',
            r'send\s+(me\s+)?(the\s+)?code',
            r'verification\s+code.*share',
            r'one.time\s+(password|pin)',
            r'confirm.*code\s+sent',
        ],
        ScamType.JOB_SCAM: [
            r'work\s+from\s+home.*\$\d+',
            r'earn\s+\$\d+.*per\s+(hour|day|week)',
            r'no\s+experience\s+(needed|required)',
            r'hiring\s+immediately',
            r'make\s+money\s+(fast|easy)',
            r'guaranteed\s+income',
        ],
        ScamType.ROMANCE_SCAM: [
            r'send\s+(me\s+)?money',
            r'wire\s+transfer.*love',
            r'stuck\s+(abroad|overseas)',
            r'need\s+money.*emergency',
            r'gift\s+cards?.*relationship',
        ],
        ScamType.TECH_SUPPORT: [
            r'computer\s+(has\s+)?virus',
            r'microsoft\s+(support|tech)',
            r'call\s+(this\s+)?number.*fix',
            r'remote\s+access.*support',
            r'detected\s+malware',
        ],
        ScamType.INVESTMENT: [
            r'guaranteed\s+returns?',
            r'double\s+your\s+(money|investment)',
            r'risk.free\s+investment',
            r'invest.*crypto.*profit',
            r'once\s+in\s+a\s+lifetime',
        ],
    }
    
    URGENCY_PHRASES = [
        'act now', 'limited time', 'expires today', 'last chance',
        'immediately', 'urgent', 'asap', 'right away', 'don\'t delay',
        'within 24 hours', 'before it\'s too late'
    ]
    
    PRESSURE_PHRASES = [
        'don\'t tell anyone', 'keep this confidential', 'secret',
        'only you', 'chosen you', 'trust me', 'believe me'
    ]

    def __init__(self, config: AegisXConfig):
        self.config = config
    
    def analyze(self, message: MessageData) -> DetectionResult:
        """Detect scam patterns in message."""
        text = message.content.lower()
        
        # Pattern matching
        detected_scams = self._match_patterns(text)
        
        # Urgency analysis
        urgency_score = self._analyze_urgency(text)
        
        # Pressure tactics
        pressure_score = self._analyze_pressure(text)
        
        # Financial indicators
        financial_score = self._analyze_financial_requests(text)
        
        # Combine scores
        base_score = max(
            [0.0] + [score for _, score in detected_scams]
        )
        
        modifier = 1.0 + (urgency_score * 0.3) + (pressure_score * 0.2)
        final_score = min(base_score * modifier + financial_score * 0.2, 1.0)
        
        threat_score = ThreatScore(
            value=final_score * 100,
            confidence=0.85 if detected_scams else 0.6,
            factors={
                'pattern_match': base_score,
                'urgency': urgency_score,
                'pressure': pressure_score,
                'financial': financial_score
            }
        )
        
        scam_types = [scam for scam, _ in detected_scams]
        classification = self._classify(threat_score, scam_types)
        
        return DetectionResult(
            classification=classification,
            threat_score=threat_score,
            scam_types=scam_types,
            explanation=self._generate_explanation(
                detected_scams, urgency_score, pressure_score
            ),
            raw_signals={
                'detected_scams': detected_scams,
                'urgency_score': urgency_score,
                'pressure_score': pressure_score,
                'financial_score': financial_score
            }
        )
    
    def _match_patterns(self, text: str) -> list[tuple[ScamType, float]]:
        """Match text against scam patterns."""
        matches = []
        
        for scam_type, patterns in self.SCAM_PATTERNS.items():
            match_count = sum(
                1 for p in patterns if re.search(p, text, re.IGNORECASE)
            )
            if match_count > 0:
                # Score increases with more pattern matches
                confidence = min(0.5 + (match_count * 0.15), 0.95)
                matches.append((scam_type, confidence))
        
        return sorted(matches, key=lambda x: x[1], reverse=True)
    
    def _analyze_urgency(self, text: str) -> float:
        """Score urgency language."""
        matches = sum(1 for phrase in self.URGENCY_PHRASES if phrase in text)
        return min(matches * 0.2, 1.0)
    
    def _analyze_pressure(self, text: str) -> float:
        """Score pressure tactics."""
        matches = sum(1 for phrase in self.PRESSURE_PHRASES if phrase in text)
        return min(matches * 0.25, 1.0)
    
    def _analyze_financial_requests(self, text: str) -> float:
        """Detect financial requests."""
        patterns = [
            r'send\s+\$?\d+',
            r'transfer\s+money',
            r'wire\s+\$?\d+',
            r'gift\s+card',
            r'bitcoin|btc|crypto',
            r'bank\s+account\s+number',
            r'credit\s+card',
            r'ssn|social\s+security',
        ]
        matches = sum(1 for p in patterns if re.search(p, text))
        return min(matches * 0.25, 1.0)
    
    def _classify(
        self, score: ThreatScore, scams: list[ScamType]
    ) -> ThreatClassification:
        if score.value >= 60 or len(scams) >= 2:
            return ThreatClassification.MALICIOUS
        elif score.value >= 35 or scams:
            return ThreatClassification.SUSPICIOUS
        return ThreatClassification.SAFE
    
    def _generate_explanation(
        self, 
        scams: list[tuple[ScamType, float]], 
        urgency: float, 
        pressure: float
    ) -> str:
        if not scams and urgency < 0.3 and pressure < 0.3:
            return "No scam indicators detected."
        
        parts = []
        
        if scams:
            scam_names = [s[0].value.replace('_', ' ').title() for s in scams[:2]]
            parts.append(f"Detected scam type(s): {', '.join(scam_names)}")
        
        if urgency >= 0.4:
            parts.append("Uses urgency tactics to pressure quick action")
        
        if pressure >= 0.3:
            parts.append("Contains social pressure or secrecy requests")
        
        return " • ".join(parts)
