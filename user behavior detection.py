# aegisx/digital_twin/profile.py

from dataclasses import dataclass, field
from datetime import datetime, time
from typing import Optional
import statistics


@dataclass
class GeoLocation:
    latitude: float
    longitude: float
    city: Optional[str] = None
    country: Optional[str] = None
    
    def distance_km(self, other: 'GeoLocation') -> float:
        """Haversine distance between two points."""
        import math
        R = 6371  # Earth radius in km
        
        lat1, lat2 = math.radians(self.latitude), math.radians(other.latitude)
        dlat = math.radians(other.latitude - self.latitude)
        dlon = math.radians(other.longitude - self.longitude)
        
        a = (math.sin(dlat/2)**2 + 
             math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2)
        return 2 * R * math.atan2(math.sqrt(a), math.sqrt(1-a))


@dataclass
class DeviceInfo:
    device_id: str
    device_type: str  # mobile, desktop, tablet
    os: str
    browser: Optional[str] = None
    first_seen: datetime = None
    last_seen: datetime = None
    trust_score: float = 0.5


@dataclass
class LoginEvent:
    timestamp: datetime
    location: GeoLocation
    device: DeviceInfo
    ip_address: str
    success: bool
    mfa_used: bool = False


@dataclass
class Transaction:
    timestamp: datetime
    amount: float
    currency: str
    merchant_category: str
    location: Optional[GeoLocation] = None


@dataclass
class BrowsingEvent:
    timestamp: datetime
    domain: str
    category: str  # banking, social, shopping, etc.
    duration_seconds: int


@dataclass
class DigitalTwinProfile:
    """
    Behavioral profile representing a user's normal patterns.
    Built incrementally from observed activity.
    """
    user_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    # Location patterns
    known_locations: list[GeoLocation] = field(default_factory=list)
    home_location: Optional[GeoLocation] = None
    work_location: Optional[GeoLocation] = None
    
    # Time patterns
    typical_login_hours: tuple[int, int] = (6, 23)  # start, end hour
    typical_days: set[int] = field(default_factory=lambda: {0,1,2,3,4,5,6})
    
    # Device patterns
    known_devices: dict[str, DeviceInfo] = field(default_factory=dict)
    primary_device_id: Optional[str] = None
    
    # Browsing patterns
    frequent_domains: dict[str, int] = field(default_factory=dict)
    typical_categories: set[str] = field(default_factory=set)
    
    # Transaction patterns
    avg_transaction_amount: float = 0.0
    max_normal_transaction: float = 0.0
    typical_merchants: set[str] = field(default_factory=set)
    
    # Statistical baselines
    login_frequency_per_day: float = 0.0
    session_duration_avg: float = 0.0
    
    # Calculated thresholds
    _location_radius_km: float = 50.0
    _transaction_std: float = 0.0


class DigitalTwinBuilder:
    """Build and update user profiles from behavioral data."""
    
    LEARNING_PERIOD_DAYS = 30
    MIN_EVENTS_FOR_BASELINE = 20
    
    def __init__(self, storage: 'ProfileStorage'):
        self.storage = storage
    
    def update_from_login(
        self, profile: DigitalTwinProfile, event: LoginEvent
    ) -> DigitalTwinProfile:
        """Update profile from login event."""
        # Add to known devices
        if event.device.device_id not in profile.known_devices:
            profile.known_devices[event.device.device_id] = event.device
        else:
            profile.known_devices[event.device.device_id].last_seen = event.timestamp
        
        # Update location patterns
        self._update_locations(profile, event.location)
        
        # Update time patterns
        self._update_time_patterns(profile, event.timestamp)
        
        profile.last_updated = datetime.utcnow()
        return profile
    
    def update_from_transactions(
        self, profile: DigitalTwinProfile, transactions: list[Transaction]
    ) -> DigitalTwinProfile:
        """Update profile from transaction history."""
        if not transactions:
            return profile
        
        amounts = [t.amount for t in transactions]
        
        profile.avg_transaction_amount = statistics.mean(amounts)
        profile._transaction_std = statistics.stdev(amounts) if len(amounts) > 1 else 0
        profile.max_normal_transaction = (
            profile.avg_transaction_amount + 3 * profile._transaction_std
        )
        
        for t in transactions:
            profile.typical_merchants.add(t.merchant_category)
        
        profile.last_updated = datetime.utcnow()
        return profile
    
    def update_from_browsing(
        self, profile: DigitalTwinProfile, events: list[BrowsingEvent]
    ) -> DigitalTwinProfile:
        """Update profile from browsing history."""
        for event in events:
            profile.frequent_domains[event.domain] = (
                profile.frequent_domains.get(event.domain, 0) + 1
            )
            profile.typical_categories.add(event.category)
        
        profile.last_updated = datetime.utcnow()
        return profile
    
    def _update_locations(
        self, profile: DigitalTwinProfile, location: GeoLocation
    ):
        """Add location to known locations if sufficiently distinct."""
        for known in profile.known_locations:
            if location.distance_km(known) < profile._location_radius_km:
                return  # Already within known location cluster
        
        profile.known_locations.append(location)
        
        # Infer home/work from frequency (simplified)
        if len(profile.known_locations) >= 5 and not profile.home_location:
            # Most frequent location = home (simplistic heuristic)
            profile.home_location = profile.known_locations[0]
    
    def _update_time_patterns(
        self, profile: DigitalTwinProfile, timestamp: datetime
    ):
        """Update typical login time window."""
        hour = timestamp.hour
        current_start, current_end = profile.typical_login_hours
        
        if hour < current_start:
            profile.typical_login_hours = (hour, current_end)
        elif hour > current_end:
            profile.typical_login_hours = (current_start, hour)
