# aegisx/detectors/phishing.py

import re
from dataclasses import dataclass
from typing import Optional
import numpy as np
from email.utils import parseaddr

from aegisx.core.types import (
    ThreatClassification, ThreatScore, DetectionResult
)
from aegisx.core.config import AegisXConfig


@dataclass
class EmailData:
    sender: str
    recipient: str
    subject: str
    body: str
    headers: dict[str, str]
    attachments: list[str] = None
    urls: list[str] = None
    
    def __post_init__(self):
        self.attachments = self.attachments or []
        self.urls = self.urls or self._extract_urls()
    
    def _extract_urls(self) -> list[str]:
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, self.body)


class PhishingDetector:
    """
    Multi-signal phishing detection combining:
    - Header analysis (SPF, DKIM, DMARC)
    - Sender reputation
    - Content analysis via transformer model
    - URL risk assessment
    - Attachment risk scoring
    """
    
    # Known legitimate domains that are frequently spoofed
    IMPERSONATION_TARGETS = {
        'paypal.com', 'apple.com', 'microsoft.com', 'google.com',
        'amazon.com', 'netflix.com', 'facebook.com', 'instagram.com',
        'linkedin.com', 'dropbox.com', 'docusign.com', 'chase.com',
        'bankofamerica.com', 'wellsfargo.com'
    }
    
    SUSPICIOUS_PATTERNS = [
        r'verify.{0,20}account',
        r'suspend.{0,20}account',
        r'unusual.{0,20}activity',
        r'click.{0,20}immediately',
        r'expire.{0,20}hours?',
        r'confirm.{0,20}identity',
        r'security.{0,20}alert',
        r'unauthorized.{0,20}access',
        r'update.{0,20}payment',
        r'won.{0,20}\$?\d+',
    ]
    
    RISKY_ATTACHMENTS = {
        '.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
        '.jar', '.msi', '.hta', '.iso', '.img'
    }

    def __init__(self, config: AegisXConfig, url_analyzer: 'URLAnalyzer'):
        self.config = config
        self.url_analyzer = url_analyzer
        self._load_models()
    
    def _load_models(self):
        """Load ML models for content classification."""
        # In production, load actual trained models
        # self.classifier = load_model(self.config.models.phishing_model_path)
        # self.embedder = SentenceTransformer(self.config.models.embedding_model)
        pass
    
    def analyze(self, email: EmailData) -> DetectionResult:
        """Run full phishing analysis pipeline."""
        signals = {}
        
        # 1. Header analysis
        signals['header'] = self._analyze_headers(email)
        
        # 2. Sender analysis
        signals['sender'] = self._analyze_sender(email)
        
        # 3. Content analysis
        signals['content'] = self._analyze_content(email)
        
        # 4. URL analysis
        signals['urls'] = self._analyze_urls(email)
        
        # 5. Attachment analysis
        signals['attachments'] = self._analyze_attachments(email)
        
        # Calculate composite score
        threat_score = self._calculate_threat_score(signals)
        classification = self._classify(threat_score)
        explanation = self._generate_explanation(signals, classification)
        
        return DetectionResult(
            classification=classification,
            threat_score=threat_score,
            explanation=explanation,
            raw_signals=signals
        )
    
    def _analyze_headers(self, email: EmailData) -> dict:
        """Check authentication headers (SPF, DKIM, DMARC)."""
        headers = email.headers
        
        spf_pass = 'pass' in headers.get('Received-SPF', '').lower()
        dkim_pass = 'pass' in headers.get('Authentication-Results', '').lower()
        
        # Check for header anomalies
        received_chain = headers.get('Received', '')
        has_suspicious_relay = self._check_suspicious_relays(received_chain)
        
        return {
            'spf_pass': spf_pass,
            'dkim_pass': dkim_pass,
            'suspicious_relay': has_suspicious_relay,
            'score': self._header_score(spf_pass, dkim_pass, has_suspicious_relay)
        }
    
    def _analyze_sender(self, email: EmailData) -> dict:
        """Analyze sender for impersonation and reputation."""
        name, address = parseaddr(email.sender)
        domain = address.split('@')[-1].lower() if '@' in address else ''
        
        # Check display name vs actual address mismatch
        impersonation_score = 0.0
        for target in self.IMPERSONATION_TARGETS:
            if target in name.lower() and target not in domain:
                impersonation_score = 0.9
                break
            # Check for typosquatting in domain
            if self._levenshtein_distance(domain, target) <= 2 and domain != target:
                impersonation_score = max(impersonation_score, 0.85)
        
        # Check for newly registered domain (would query external service)
        # is_new_domain = self._check_domain_age(domain)
        
        return {
            'address': address,
            'domain': domain,
            'display_name': name,
            'impersonation_score': impersonation_score,
            'score': impersonation_score
        }
    
    def _analyze_content(self, email: EmailData) -> dict:
        """NLP analysis of email content."""
        text = f"{email.subject} {email.body}".lower()
        
        # Pattern matching for urgency/threat indicators
        pattern_matches = []
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                pattern_matches.append(pattern)
        
        pattern_score = min(len(pattern_matches) * 0.15, 0.6)
        
        # In production: run through trained classifier
        # ml_score = self.classifier.predict_proba(
        #     self.embedder.encode(text)
        # )[0][1]
        ml_score = 0.0  # Placeholder
        
        combined_score = max(pattern_score, ml_score)
        
        return {
            'pattern_matches': pattern_matches,
            'pattern_score': pattern_score,
            'ml_score': ml_score,
            'score': combined_score
        }
    
    def _analyze_urls(self, email: EmailData) -> dict:
        """Analyze all URLs in the email."""
        if not email.urls:
            return {'urls': [], 'max_risk': 0, 'score': 0}
        
        url_results = []
        max_risk = 0
        
        for url in email.urls[:10]:  # Limit to prevent DoS
            result = self.url_analyzer.analyze(url)
            url_results.append({
                'url': url,
                'risk_score': result.threat_score.value
            })
            max_risk = max(max_risk, result.threat_score.value)
        
        return {
            'urls': url_results,
            'max_risk': max_risk,
            'score': max_risk / 100
        }
    
    def _analyze_attachments(self, email: EmailData) -> dict:
        """Score attachment risk based on file types."""
        if not email.attachments:
            return {'attachments': [], 'risky_count': 0, 'score': 0}
        
        risky = [
            a for a in email.attachments
            if any(a.lower().endswith(ext) for ext in self.RISKY_ATTACHMENTS)
        ]
        
        score = min(len(risky) * 0.4, 0.8)
        
        return {
            'attachments': email.attachments,
            'risky_count': len(risky),
            'risky_files': risky,
            'score': score
        }
    
    def _calculate_threat_score(self, signals: dict) -> ThreatScore:
        """Weighted combination of all signals."""
        weights = {
            'header': 0.15,
            'sender': 0.25,
            'content': 0.30,
            'urls': 0.20,
            'attachments': 0.10
        }
        
        weighted_sum = sum(
            signals[k]['score'] * w 
            for k, w in weights.items()
        )
        
        # Confidence based on signal agreement
        scores = [signals[k]['score'] for k in weights]
        confidence = 1.0 - (np.std(scores) / 0.5)  # Lower std = higher confidence
        confidence = max(0.3, min(1.0, confidence))
        
        return ThreatScore(
            value=weighted_sum * 100,
            confidence=confidence,
            factors={k: signals[k]['score'] for k in weights}
        )
    
    def _classify(self, score: ThreatScore) -> ThreatClassification:
        """Map threat score to classification."""
        if score.value >= self.config.thresholds.phishing_confirmed * 100:
            return ThreatClassification.PHISHING
        elif score.value >= self.config.thresholds.phishing_suspicious * 100:
            return ThreatClassification.SUSPICIOUS
        return ThreatClassification.SAFE
    
    def _generate_explanation(
        self, signals: dict, classification: ThreatClassification
    ) -> str:
        """Generate human-readable explanation."""
        if classification == ThreatClassification.SAFE:
            return "No significant phishing indicators detected."
        
        reasons = []
        
        if signals['sender']['impersonation_score'] > 0.5:
            reasons.append(
                f"Sender appears to impersonate a legitimate organization"
            )
        
        if not signals['header']['spf_pass']:
            reasons.append("Email failed SPF authentication")
        
        if signals['content']['pattern_matches']:
            reasons.append(
                f"Contains urgency patterns: {', '.join(signals['content']['pattern_matches'][:3])}"
            )
        
        if signals['urls']['max_risk'] > 50:
            reasons.append("Contains high-risk URLs")
        
        if signals['attachments']['risky_count'] > 0:
            reasons.append(
                f"Contains potentially dangerous attachments: {signals['attachments']['risky_files']}"
            )
        
        return " • ".join(reasons) if reasons else "Multiple weak signals combined."
    
    def _check_suspicious_relays(self, received: str) -> bool:
        """Check for suspicious mail relays."""
        suspicious_indicators = ['unknown', 'localhost', '127.0.0.1']
        return any(ind in received.lower() for ind in suspicious_indicators)
    
    def _header_score(self, spf: bool, dkim: bool, suspicious: bool) -> float:
        score = 0.0
        if not spf:
            score += 0.3
        if not dkim:
            score += 0.3
        if suspicious:
            score += 0.4
        return min(score, 1.0)
    
    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate edit distance between strings."""
        if len(s1) < len(s2):
            return PhishingDetector._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        
        return prev_row[-1]
