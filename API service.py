# aegisx/api/service.py

from dataclasses import dataclass
from typing import Optional
from datetime import datetime

from aegisx.core.config import AegisXConfig
from aegisx.core.types import DetectionResult
from aegisx.detectors.phishing import PhishingDetector, EmailData
from aegisx.detectors.url_analyzer import URLAnalyzer
from aegisx.detectors.scam_detector import ScamDetector, MessageData
from aegisx.digital_twin.profile import DigitalTwinProfile, DigitalTwinBuilder
from aegisx.digital_twin.anomaly_detector import BehaviorAnomalyDetector, LoginEvent
from aegisx.engine.risk_scorer import RiskScoringEngine, RiskContext


class AegisXService:
    """
    Main service interface for the AegisX threat detection platform.
    
    Provides unified API for:
    - Email/phishing analysis
    - URL scanning
    - Message/scam detection
    - Behavioral anomaly detection
    - Unified risk scoring
    """
    
    def __init__(self, config: AegisXConfig = None):
        self.config = config or AegisXConfig()
        
        # Initialize components
        self.url_analyzer = URLAnalyzer(self.config)
        self.phishing_detector = PhishingDetector(self.config, self.url_analyzer)
        self.scam_detector = ScamDetector(self.config)
        self.behavior_detector = BehaviorAnomalyDetector(self.config)
        self.risk_engine = RiskScoringEngine(self.config)
        
        # Profile management (would use actual storage in production)
        self._profiles: dict[str, DigitalTwinProfile] = {}
    
    async def analyze_email(self, email: EmailData) -> DetectionResult:
        """Full email threat analysis."""
        return self.phishing_detector.analyze(email)
    
    async def analyze_url(self, url: str) -> DetectionResult:
        """Single URL risk analysis."""
        return self.url_analyzer.analyze(url)
    
    async def analyze_urls(self, urls: list[str]) -> list[DetectionResult]:
        """Batch URL analysis."""
        return [self.url_analyzer.analyze(url) for url in urls]
    
    async def analyze_message(self, message: MessageData) -> DetectionResult:
        """Scam/fraud message detection."""
        return self.scam_detector.analyze(message)
    
    async def analyze_login(
        self, user_id: str, event: LoginEvent
    ) -> DetectionResult:
        """Behavioral analysis of login event."""
        profile = self._get_or_create_profile(user_id)
        result = self.behavior_detector.analyze_login(profile, event)
        
        # Update profile with new event
        DigitalTwinBuilder(None).update_from_login(profile, event)
        
        return result
    
    async def calculate_risk(
        self,
        email: Optional[EmailData] = None,
        urls: Optional[list[str]] = None,
        message: Optional[MessageData] = None,
        user_id: Optional[str] = None,
        login_event: Optional[LoginEvent] = None
    ) -> DetectionResult:
        """
        Unified risk calculation combining all available signals.
        
        Pass any combination of inputs for holistic threat assessment.
        """
        context = RiskContext()
        
        if email:
            context.phishing_result = await self.analyze_email(email)
        
        if urls:
            context.url_results = await self.analyze_urls(urls)
        
        if message:
            context.scam_result = await self.analyze_message(message)
        
        if user_id and login_event:
            context.behavior_result = await self.analyze_login(user_id, login_event)
        
        return self.risk_engine.calculate(context)
    
    def _get_or_create_profile(self, user_id: str) -> DigitalTwinProfile:
        """Retrieve or create user profile."""
        if user_id not in self._profiles:
            self._profiles[user_id] = DigitalTwinProfile(user_id=user_id)
        return self._profiles[user_id]


# FastAPI routes (example)
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="AegisX Threat Detection API")
service = AegisXService()

class EmailRequest(BaseModel):
    sender: str
    recipient: str
    subject: str
    body: str
    headers: dict = {}

@app.post("/api/v1/analyze/email")
async def analyze_email_endpoint(request: EmailRequest):
    email = EmailData(
        sender=request.sender,
        recipient=request.recipient,
        subject=request.subject,
        body=request.body,
        headers=request.headers
    )
    result = await service.analyze_email(email)
    return {
        "classification": result.classification.value,
        "threat_score": result.threat_score.value,
        "confidence": result.threat_score.confidence,
        "explanation": result.explanation
    }

@app.post("/api/v1/analyze/url")
async def analyze_url_endpoint(url: str):
    result = await service.analyze_url(url)
    return {
        "url": url,
        "risk_score": result.threat_score.value,
        "classification": result.classification.value,
        "explanation": result.explanation
    }
"""
