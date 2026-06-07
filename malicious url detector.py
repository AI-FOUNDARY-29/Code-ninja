# aegisx/detectors/url_analyzer.py

import re
import socket
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
from typing import Optional
import tldextract

from aegisx.core.types import ThreatClassification, ThreatScore, DetectionResult
from aegisx.core.config import AegisXConfig


@dataclass 
class URLFeatures:
    full_url: str
    domain: str
    subdomain: str
    tld: str
    path: str
    query_params: dict
    is_ip_address: bool
    uses_https: bool
    port: Optional[int]
    url_length: int
    subdomain_count: int
    has_at_symbol: bool
    has_double_slash_redirect: bool
    uses_shortener: bool
    entropy: float


class URLAnalyzer:
    """
    Detect malicious URLs through:
    - Structural analysis
    - Typosquatting detection
    - URL shortener resolution
    - Domain reputation
    - Fake login page detection
    """
    
    SHORTENER_DOMAINS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tr.im',
        'cli.gs', 'short.to', 'budurl.com', 'clck.ru'
    }
    
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
        '.work', '.click', '.link', '.men', '.loan', '.win'
    }
    
    BRAND_KEYWORDS = {
        'paypal', 'apple', 'microsoft', 'google', 'amazon',
        'netflix', 'facebook', 'instagram', 'linkedin', 'bank',
        'secure', 'account', 'verify', 'login', 'signin',
        'update', 'confirm', 'support', 'service', 'help'
    }
    
    LOGIN_INDICATORS = {
        'login', 'signin', 'sign-in', 'log-in', 'auth',
        'authenticate', 'verify', 'confirm', 'secure', 'account'
    }

    def __init__(self, config: AegisXConfig):
        self.config = config
        self._load_reputation_data()
    
    def _load_reputation_data(self):
        """Load known malicious domains/IPs."""
        # In production: load from threat intelligence feeds
        self.known_malicious = set()
        self.known_safe = set()
    
    def analyze(self, url: str) -> DetectionResult:
        """Full URL threat analysis."""
        features = self._extract_features(url)
        signals = {}
        
        # 1. Structural analysis
        signals['structure'] = self._analyze_structure(features)
        
        # 2. Typosquatting detection
        signals['typosquat'] = self._detect_typosquatting(features)
        
        # 3. Shortener analysis
        signals['shortener'] = self._analyze_shortener(features)
        
        # 4. Domain reputation
        signals['reputation'] = self._check_reputation(features)
        
        # 5. Fake login detection
        signals['fake_login'] = self._detect_fake_login(features)
        
        threat_score = self._calculate_risk_score(signals)
        classification = self._classify(threat_score)
        
        return DetectionResult(
            classification=classification,
            threat_score=threat_score,
            explanation=self._generate_explanation(signals, features),
            raw_signals=signals
        )
    
    def _extract_features(self, url: str) -> URLFeatures:
        """Parse URL into analyzable features."""
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Check if domain is an IP address
        is_ip = False
        try:
            socket.inet_aton(extracted.domain)
            is_ip = True
        except socket.error:
            pass
        
        return URLFeatures(
            full_url=url,
            domain=extracted.domain,
            subdomain=extracted.subdomain,
            tld=f".{extracted.suffix}" if extracted.suffix else "",
            path=parsed.path,
            query_params=parse_qs(parsed.query),
            is_ip_address=is_ip,
            uses_https=parsed.scheme == 'https',
            port=parsed.port,
            url_length=len(url),
            subdomain_count=len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
            has_at_symbol='@' in url,
            has_double_slash_redirect='//' in parsed.path,
            uses_shortener=f"{extracted.domain}.{extracted.suffix}".lower() in self.SHORTENER_DOMAINS,
            entropy=self._calculate_entropy(url)
        )
    
    def _analyze_structure(self, f: URLFeatures) -> dict:
        """Score URL structural anomalies."""
        score = 0.0
        flags = []
        
        # IP-based URL
        if f.is_ip_address:
            score += 0.4
            flags.append("Uses IP address instead of domain")
        
        # No HTTPS
        if not f.uses_https:
            score += 0.15
            flags.append("Does not use HTTPS")
        
        # Excessive length
        if f.url_length > 100:
            score += min((f.url_length - 100) / 200, 0.3)
            flags.append("Unusually long URL")
        
        # Deep subdomain nesting
        if f.subdomain_count > 3:
            score += 0.25
            flags.append("Excessive subdomain depth")
        
        # @ symbol (URL obfuscation)
        if f.has_at_symbol:
            score += 0.5
            flags.append("Contains @ symbol (potential redirect)")
        
        # Double slash redirect
        if f.has_double_slash_redirect:
            score += 0.3
            flags.append("Contains redirect pattern")
        
        # Suspicious TLD
        if f.tld in self.SUSPICIOUS_TLDS:
            score += 0.3
            flags.append(f"Suspicious TLD: {f.tld}")
        
        # High entropy (randomized strings)
        if f.entropy > 4.5:
            score += 0.2
            flags.append("High URL entropy (may be auto-generated)")
        
        return {
            'score': min(score, 1.0),
            'flags': flags
        }
    
    def _detect_typosquatting(self, f: URLFeatures) -> dict:
        """Detect domain typosquatting."""
        from aegisx.detectors.phishing import PhishingDetector
        
        domain_lower = f.domain.lower()
        best_match = None
        min_distance = float('inf')
        
        for brand in self.BRAND_KEYWORDS:
            # Check if brand name appears in domain but isn't exact
            if brand in domain_lower and domain_lower != brand:
                # Suspicious: brand name embedded
                return {
                    'score': 0.7,
                    'matched_brand': brand,
                    'type': 'brand_embedding'
                }
            
            # Check edit distance for typosquatting
            dist = PhishingDetector._levenshtein_distance(domain_lower, brand)
            if dist < min_distance and 0 < dist <= 2:
                min_distance = dist
                best_match = brand
        
        if best_match:
            return {
                'score': 0.8 - (min_distance * 0.15),
                'matched_brand': best_match,
                'type': 'typosquat',
                'edit_distance': min_distance
            }
        
        return {'score': 0.0, 'matched_brand': None}
    
    def _analyze_shortener(self, f: URLFeatures) -> dict:
        """Handle URL shorteners."""
        if not f.uses_shortener:
            return {'score': 0.0, 'is_shortener': False}
        
        # In production: resolve and re-analyze destination
        # resolved_url = self._resolve_shortener(f.full_url)
        # return self.analyze(resolved_url)
        
        return {
            'score': 0.25,  # Base penalty for obfuscation
            'is_shortener': True,
            'note': 'URL shortener detected - destination masked'
        }
    
    def _check_reputation(self, f: URLFeatures) -> dict:
        """Check domain against reputation databases."""
        full_domain = f"{f.subdomain}.{f.domain}{f.tld}".strip('.')
        
        if full_domain in self.known_malicious:
            return {'score': 1.0, 'status': 'known_malicious'}
        
        if f.domain in self.known_safe:
            return {'score': 0.0, 'status': 'known_safe'}
        
        # In production: query VirusTotal, Google Safe Browsing, etc.
        return {'score': 0.0, 'status': 'unknown'}
    
    def _detect_fake_login(self, f: URLFeatures) -> dict:
        """Detect fake login page indicators."""
        combined = f"{f.subdomain} {f.domain} {f.path}".lower()
        
        login_keywords = sum(
            1 for kw in self.LOGIN_INDICATORS if kw in combined
        )
        brand_keywords = sum(
            1 for kw in self.BRAND_KEYWORDS if kw in combined
        )
        
        # Login keywords + brand keywords + not official domain = suspicious
        if login_keywords > 0 and brand_keywords > 0:
            return {
                'score': min(0.3 + (login_keywords * 0.15) + (brand_keywords * 0.1), 0.85),
                'login_keywords': login_keywords,
                'brand_keywords': brand_keywords,
                'likely_impersonating': True
            }
        
        return {'score': 0.0, 'likely_impersonating': False}
    
    def _calculate_risk_score(self, signals: dict) -> ThreatScore:
        """Combine signals into final risk score."""
        weights = {
            'structure': 0.20,
            'typosquat': 0.30,
            'shortener': 0.10,
            'reputation': 0.25,
            'fake_login': 0.15
        }
        
        # Reputation override: known malicious = max score
        if signals['reputation'].get('status') == 'known_malicious':
            return ThreatScore(value=100.0, confidence=1.0, factors=signals)
        
        weighted_sum = sum(
            signals[k]['score'] * w for k, w in weights.items()
        )
        
        return ThreatScore(
            value=weighted_sum * 100,
            confidence=0.8,
            factors={k: signals[k]['score'] for k in weights}
        )
    
    def _classify(self, score: ThreatScore) -> ThreatClassification:
        if score.value >= self.config.thresholds.url_risk_high:
            return ThreatClassification.MALICIOUS
        elif score.value >= self.config.thresholds.url_risk_medium:
            return ThreatClassification.SUSPICIOUS
        return ThreatClassification.SAFE
    
    def _generate_explanation(self, signals: dict, features: URLFeatures) -> str:
        reasons = []
        
        if signals['structure']['flags']:
            reasons.extend(signals['structure']['flags'][:2])
        
        if signals['typosquat']['score'] > 0:
            reasons.append(
                f"Domain resembles '{signals['typosquat']['matched_brand']}'"
            )
        
        if signals['fake_login']['likely_impersonating']:
            reasons.append("Appears to be a fake login page")
        
        if signals['reputation']['status'] == 'known_malicious':
            reasons.insert(0, "Domain is on known malicious list")
        
        return " • ".join(reasons) if reasons else "No significant risk indicators."
    
    @staticmethod
    def _calculate_entropy(s: str) -> float:
        """Shannon entropy of string."""
        import math
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum(
            (count/length) * math.log2(count/length) 
            for count in freq.values()
        )
