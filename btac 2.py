# aegisx/core/config.py

from dataclasses import dataclass
from typing import Optional


@dataclass
class ModelConfig:
    phishing_model_path: str = "models/phishing_classifier_v2"
    url_model_path: str = "models/url_risk_scorer"
    scam_model_path: str = "models/scam_detector"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    device: str = "cuda"  # or "cpu"


@dataclass
class ThresholdConfig:
    phishing_suspicious: float = 0.4
    phishing_confirmed: float = 0.75
    url_risk_medium: float = 40.0
    url_risk_high: float = 70.0
    anomaly_sensitivity: float = 2.5  # standard deviations
    impossible_travel_speed_kmh: float = 800.0


@dataclass
class AegisXConfig:
    models: ModelConfig = None
    thresholds: ThresholdConfig = None
    redis_url: str = "redis://localhost:6379"
    db_url: str = "postgresql://localhost/aegisx"
    
    def __post_init__(self):
        self.models = self.models or ModelConfig()
        self.thresholds = self.thresholds or ThresholdConfig()
