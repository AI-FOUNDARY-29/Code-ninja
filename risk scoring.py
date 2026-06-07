# aegisx/engine/risk_scorer.py

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from aegisx.core.types import ThreatScore, ThreatClassification, DetectionResult
from aegisx.core.config import AegisXConfig


@dataclass
class RiskContext:
    """Aggregated context for risk calculation."""
    phishing_result: Optional[DetectionResult] = None
    url_results: list[DetectionResult] = None
    scam_result: Optional[DetectionResult] = None
    behavior_result: Optional[DetectionResult] = None
    
    # Additional context
    user_risk_history: float = 0.0  # Historical risk score
    account_age_days: int = 365
    mfa_enabled: bool = True
    
    def __post_init__(self):
        self.url_results = self.url_results or []


class RiskScoringEngine:
    """
    Final risk aggregation combining all detection signals.
    
    Produces a unified threat score that accounts for:
    - Individual detector outputs
    - Signal correlation
    - User context
    - Temporal patterns
    """
    
    # Base weights for each signal type
    WEIGHTS = {
        'phishing': 0.30,
        'url': 0.20,
        'scam': 0.25,
        'behavior': 0.15,
        'history': 0.10
    }
    
    # Amplification factors for correlated signals
    CORRELATION_BOOST = {
        ('phishing', 'url'): 1.3,
        ('scam', 'behavior'): 1.25,
        ('phishing', 'scam'): 1.2,
    }

    def __init__(self, config: AegisXConfig):
        self.config = config
    
    def calculate(self, context: RiskContext) -> DetectionResult:
        """Calculate final risk score from all signals."""
        signals = self._extract_signals(context)
        
        # Base weighted score
        base_score = self._weighted_score(signals)
        
        # Apply correlation boost
        boosted_score = self._apply_correlations(base_score, signals)
        
        # Context adjustments
        adjusted_score = self._apply_context_modifiers(boosted_score, context)
        
        # Calculate confidence
        confidence = self._calculate_confidence(signals)
        
        # Build final result
        threat_score = ThreatScore(
            value=adjusted_score,
            confidence=confidence,
            factors=signals
        )
        
        return DetectionResult(
            classification=self._classify(threat_score),
            threat_score=threat_score,
            explanation=self._generate_summary(context, signals),
            raw_signals={'context': self._serialize_context(context)}
        )
    
    def _extract_signals(self, context: RiskContext) -> dict[str, float]:
        """Extract normalized scores from each detector."""
        signals = {}
        
        if context.phishing_result:
            signals['phishing'] = context.phishing_result.threat_score.value / 100
        
        if context.url_results:
            max_url = max(r.threat_score.value for r in context.url_results)
            signals['url'] = max_url / 100
        
        if context.scam_result:
            signals['scam'] = context.scam_result.threat_score.value / 100
        
        if context.behavior_result:
            signals['behavior'] = context.behavior_result.threat_score.value / 100
        
        signals['history'] = context.user_risk_history
        
        return signals
    
    def _weighted_score(self, signals: dict[str, float]) -> float:
        """Calculate base weighted score."""
        total = 0.0
        weight_sum = 0.0
        
        for key, weight in self.WEIGHTS.items():
            if key in signals:
                total += signals[key] * weight
                weight_sum += weight
        
        return (total / weight_sum * 100) if weight_sum > 0 else 0.0
    
    def _apply_correlations(
        self, base_score: float, signals: dict[str, float]
    ) -> float:
        """Boost score when multiple related signals fire."""
        score = base_score
        
        for (sig1, sig2), boost in self.CORRELATION_BOOST.items():
            if signals.get(sig1, 0) > 0.4 and signals.get(sig2, 0) > 0.4:
                score *= boost
        
        return min(score, 100.0)
    
    def _apply_context_modifiers(
        self, score: float, context: RiskContext
    ) -> float:
        """Adjust score based on account context."""
        modified = score
        
        # New accounts are higher risk
        if context.account_age_days < 30:
            modified *= 1.2
        
        # MFA reduces risk
        if context.mfa_enabled:
            modified *= 0.85
        
        return min(modified, 100.0)
    
    def _calculate_confidence(self, signals: dict[str, float]) -> float:
        """
        Confidence based on:
        - Number of signals available
        - Agreement between signals
        """
        if not signals:
            return 0.0
        
        # More signals = higher confidence
        coverage = len(signals) / len(self.WEIGHTS)
        
        # Agreement: lower variance = higher confidence
        values = list(signals.values())
        if len(values) > 1:
            import statistics
            variance = statistics.variance(values)
            agreement = max(0, 1 - variance)
        else:
            agreement = 0.5
        
        return (coverage * 0.4 + agreement * 0.6)
    
    def _classify(self, score: ThreatScore) -> ThreatClassification:
        if score.value >= 75:
            return ThreatClassification.MALICIOUS
        elif score.value >= 45:
            return ThreatClassification.SUSPICIOUS
        elif score.value >= 25:
            return ThreatClassification.SUSPICIOUS
        return ThreatClassification.SAFE
    
    def _generate_summary(
        self, context: RiskContext, signals: dict[str, float]
    ) -> str:
        """Generate human-readable risk summary."""
        parts = []
        
        # Identify top contributors
        sorted_signals = sorted(
            signals.items(), key=lambda x: x[1], reverse=True
        )
        
        for signal, value in sorted_signals[:3]:
            if value >= 0.4:
                if signal == 'phishing' and context.phishing_result:
                    parts.append(context.phishing_result.explanation)
                elif signal == 'scam' and context.scam_result:
                    parts.append(context.scam_result.explanation)
                elif signal == 'behavior' and context.behavior_result:
                    parts.append(context.behavior_result.explanation)
                elif signal == 'url' and context.url_results:
                    parts.append("High-risk URLs detected")
        
        return " | ".join(parts) if parts else "No significant threats detected."
    
    def _serialize_context(self, context: RiskContext) -> dict:
        """Serialize context for logging/audit."""
        return {
            'has_phishing': context.phishing_result is not None,
            'url_count': len(context.url_results),
            'has_scam': context.scam_result is not None,
            'has_behavior': context.behavior_result is not None,
            'mfa_enabled': context.mfa_enabled,
            'account_age_days': context.account_age_days
        }
