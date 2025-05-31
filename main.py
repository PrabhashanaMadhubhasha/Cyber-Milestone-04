from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import uuid
from collections import defaultdict
import math

app = FastAPI()

# Data storage
event_history = []
attack_logs = []
user_profiles = defaultdict(dict)

# Detection configuration
DETECTION_CONFIG = {
    "failed_login": {
        "threshold": 5,
        "time_window": timedelta(minutes=1),
        "message": "Multiple failed login attempts detected"
    },
    "toggle_spam": {
        "threshold": 10,
        "time_window": timedelta(seconds=30),
        "message": "High frequency of toggle commands detected"
    },
    "power_anomaly": {
        "upper_threshold_percent": 150,
        "lower_threshold_percent": 10,
        "message": "Abnormal power consumption detected"
    },
    "unusual_time": {
        "start_business_hours": 8,
        "end_business_hours": 18,
        "message": "Activity detected outside business hours"
    },
    "geo_anomaly": {
        "distance_threshold_m": 500,  # Changed from km to meters
        "time_window": timedelta(minutes=1),  # Added time window
        "message": "Login from unusual location detected"
    },
    "device_impersonation": {
        "message": "Unauthorized device access detected"
    },
    "role_escalation": {
        "message": "Unauthorized role change attempted"
    }
}

class Event(BaseModel):
    event_name: str
    user_role: str
    user_id: str
    source_id: str
    timestamp: Optional[datetime] = None
    context: Dict[str, object] = {}

class AttackLog(BaseModel):
    id: str
    timestamp: datetime
    event_name: str
    user_id: str
    source_id: str
    user_role: str
    detection_type: str
    message: str
    context: Dict[str, object]

class EventLog(BaseModel):
    id: str
    timestamp: datetime
    event_name: str
    user_id: str
    source_id: str
    user_role: str
    context: Dict[str, object]

def is_business_hours(timestamp: datetime) -> bool:
    hour = timestamp.hour
    return (DETECTION_CONFIG["unusual_time"]["start_business_hours"] <= hour < 
            DETECTION_CONFIG["unusual_time"]["end_business_hours"])

def calculate_distance_meters(loc1: str, loc2: str) -> float:
    """Calculate distance between two coordinates in meters"""
    lat1, lon1 = map(float, loc1.split(','))
    lat2, lon2 = map(float, loc2.split(','))
    
    # Approximate calculation (Haversine formula)
    R = 6371000  # Earth radius in meters
    φ1 = math.radians(lat1)
    φ2 = math.radians(lat2)
    Δφ = math.radians(lat2 - lat1)
    Δλ = math.radians(lon2 - lon1)

    a = math.sin(Δφ/2) * math.sin(Δφ/2) + math.cos(φ1) * math.cos(φ2) * math.sin(Δλ/2) * math.sin(Δλ/2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    
    return R * c

def instrument(event: Event):
    if event.timestamp is None:
        event.timestamp = datetime.now()
    
    # Store the event
    event_id = str(uuid.uuid4())
    event_log = EventLog(
        id=event_id,
        timestamp=event.timestamp,
        event_name=event.event_name,
        user_id=event.user_id,
        source_id=event.source_id,
        user_role=event.user_role,
        context=event.context
    )
    event_history.append(event_log)
    
    # Run detection checks
    check_failed_logins(event)
    check_toggle_spam(event)
    check_power_anomalies(event)
    check_unusual_time_activity(event)
    check_geo_anomalies(event)
    check_device_impersonation(event)
    check_role_escalation(event)
    
    return event_log

def check_failed_logins(event: Event):
    if event.event_name != "login_attempt" or event.context.get("success", True):
        return
    
    threshold = DETECTION_CONFIG["failed_login"]["threshold"]
    time_window = DETECTION_CONFIG["failed_login"]["time_window"]
    cutoff = event.timestamp - time_window
    
    failed_attempts = sum(
        1 for e in event_history
        if e.event_name == "login_attempt"
        and e.user_id == event.user_id
        and e.timestamp >= cutoff
        and not e.context.get("success", True)
    )
    
    if failed_attempts >= threshold:
        log_attack(event, "failed_login", 
                  f"{failed_attempts} failed login attempts in {time_window}")

def check_toggle_spam(event: Event):
    if event.event_name not in ["toggle_device", "adjust_device"]:
        return
    
    if event.user_role in ["ADMIN", "MANAGER"] and is_business_hours(event.timestamp):
        return
    
    threshold = DETECTION_CONFIG["toggle_spam"]["threshold"]
    time_window = DETECTION_CONFIG["toggle_spam"]["time_window"]
    cutoff = event.timestamp - time_window
    
    toggle_count = sum(
        1 for e in event_history
        if e.event_name in ["toggle_device", "adjust_device"]
        and e.user_id == event.user_id
        and e.timestamp >= cutoff
    )
    
    if toggle_count >= threshold:
        log_attack(event, "toggle_spam", 
                  f"{toggle_count} toggle commands in {time_window}")

def check_power_anomalies(event: Event):
    if event.event_name != "power_reading":
        return
    
    value = event.context.get("value")
    if value is None:
        return
    
    avg = event.context.get("historical_avg")
    if avg is None:
        return
    
    upper_threshold = avg * (DETECTION_CONFIG["power_anomaly"]["upper_threshold_percent"] / 100)
    lower_threshold = avg * (DETECTION_CONFIG["power_anomaly"]["lower_threshold_percent"] / 100)
    
    if value <= 0:
        log_attack(event, "power_anomaly", "Zero or negative power reading")
    elif value > upper_threshold:
        log_attack(event, "power_anomaly", 
                  f"Power spike detected ({value} > {upper_threshold})")
    elif value < lower_threshold:
        log_attack(event, "power_anomaly", 
                  f"Power drop detected ({value} < {lower_threshold})")

def check_unusual_time_activity(event: Event):
    if event.user_role in ["ADMIN", "MANAGER"]:
        return
    
    if event.event_name not in ["toggle_device", "adjust_device", "set_power_level"]:
        return
    
    if not is_business_hours(event.timestamp):
        log_attack(event, "unusual_time", 
                  f"Activity outside business hours at {event.timestamp.time()}")

def check_geo_anomalies(event: Event):
    if event.event_name != "login_attempt" or not event.context.get("success"):
        return
    
    location = event.context.get("location")
    if not location:
        return
    
    user_profile = user_profiles.get(event.user_id, {})
    usual_locations = user_profile.get("usual_locations", [])
    
    if not usual_locations:
        user_profiles[event.user_id]["usual_locations"] = [location]
        return
    
    # Check for logins from unusual locations within the time window
    time_window = DETECTION_CONFIG["geo_anomaly"]["time_window"]
    cutoff = event.timestamp - time_window
    
    # Get all logins from this user in the time window
    recent_logins = [
        e for e in event_history
        if e.event_name == "login_attempt"
        and e.user_id == event.user_id
        and e.timestamp >= cutoff
        and e.context.get("success")
        and "location" in e.context
    ]
    
    # Check distance for each recent login
    for login in recent_logins:
        login_loc = login.context["location"]
        distance = calculate_distance_meters(login_loc, location)
        
        if distance > DETECTION_CONFIG["geo_anomaly"]["distance_threshold_m"]:
            log_attack(event, "geo_anomaly", 
                      f"Login from unusual location {location} (distance: {distance:.1f}m from {login_loc})")
            break

def check_device_impersonation(event: Event):
    if event.event_name not in ["toggle_device", "adjust_device"]:
        return
    
    user_profile = user_profiles.get(event.user_id, {})
    authorized_devices = user_profile.get("authorized_devices", [])
    
    if event.source_id not in authorized_devices:
        log_attack(event, "device_impersonation", 
                  f"Unauthorized device access: {event.source_id}")

def check_role_escalation(event: Event):
    if event.event_name != "change_role":
        return
    
    if event.user_role not in ["ADMIN", "MANAGER"]:
        new_role = event.context.get("new_role")
        if new_role in ["ADMIN", "MANAGER"]:
            log_attack(event, "role_escalation", 
                      f"Unauthorized role change to {new_role}")

def log_attack(event: Event, detection_type: str, message: str):
    attack_id = str(uuid.uuid4())
    attack_log = AttackLog(
        id=attack_id,
        timestamp=event.timestamp,
        event_name=event.event_name,
        user_id=event.user_id,
        source_id=event.source_id,
        user_role=event.user_role,
        detection_type=detection_type,
        message=message,
        context=event.context
    )
    attack_logs.append(attack_log)

# API Endpoints
@app.post("/instrument")
async def api_instrument(event: Event):
    """Main endpoint for logging events"""
    try:
        result = instrument(event)
        return {"status": "success", "event_id": result.id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/simulate/normal-activity")
async def simulate_normal_activity():
    """Simulate normal user activity"""
    normal_user = "user_normal_123"
    user_profiles[normal_user] = {
        # Coordinates within 500m of each other (New York City area)
        "usual_locations": ["40.7128,-74.0060", "40.7125,-74.0062", "40.7130,-74.0058"],
        "authorized_devices": ["192.168.1.100", "smart_meter_1"]
    }
    
    now = datetime.now()
    
    # Successful login
    instrument(Event(
        event_name="login_attempt",
        user_role="USER",
        user_id=normal_user,
        source_id="192.168.1.100",
        timestamp=now - timedelta(minutes=10),
        context={"success": True, "location": "40.7128,-74.0060"}
    ))
    
    # Normal device toggles
    for i in range(2):
        instrument(Event(
            event_name="toggle_device",
            user_role="USER",
            user_id=normal_user,
            source_id="192.168.1.100",
            timestamp=now - timedelta(minutes=9, seconds=30-i),
            context={"device": "light_1", "state": "on" if i%2==0 else "off"}
        ))
    
    # Normal power reading
    instrument(Event(
        event_name="power_reading",
        user_role="SYSTEM",
        user_id="sensor_1",
        source_id="smart_meter_1",
        timestamp=now - timedelta(minutes=8),
        context={"value": 120.5, "historical_avg": 115.0}
    ))

    # Successful logins from usual locations during a minute threshold
    for i, loc in enumerate(user_profiles[normal_user]["usual_locations"]):
        instrument(Event(
            event_name="login_attempt",
            user_role="USER",
            user_id=normal_user,
            source_id=f"192.168.1.{100+i}",
            timestamp=now,
            context={"success": True, "location": loc}
        ))

    # Successful logins from two locations(diffrence > 500m) time gap > minute threshold - Step 1
    instrument(Event(
        event_name="login_attempt",
        user_role="USER",
        user_id="user_normal_567",
        source_id="192.168.5.100",
        timestamp=now,
        context={"success": True, "location": "41.7178,-73.0060"}
    ))

    # Successful logins from two locations(diffrence > 500m) time gap > minute threshold - Step 2
    instrument(Event(
        event_name="login_attempt",
        user_role="USER",
        user_id="user_normal_567",
        source_id="192.168.5.100",
        timestamp=now + timedelta(minutes=2),
        context={"success": True, "location": "51.7178,-83.0060"}
    ))
    
    return {"status": "simulated normal activity"}

@app.post("/simulate/attack-activity")
async def simulate_attack_activity():
    """Simulate various attack scenarios"""
    attacker_user = "user_attacker_456"
    user_profiles[attacker_user] = {
        "usual_locations": ["40.7128,-74.0060"],  # New York
        "authorized_devices": ["192.168.1.200"]
    }
    
    now = datetime.now()
    
    # Failed login attempts
    for i in range(6):
        instrument(Event(
            event_name="login_attempt",
            user_role="USER",
            user_id=attacker_user,
            source_id="192.168.1.666",
            timestamp=now - timedelta(seconds=50-i*10),
            context={"success": False}
        ))
    
    # Toggle spam
    for i in range(15):
        instrument(Event(
            event_name="toggle_device",
            user_role="USER",
            user_id=attacker_user,
            source_id="192.168.1.666",
            timestamp=now - timedelta(seconds=25-i),
            context={"device": "light_1", "state": "on" if i%2==0 else "off"}
        ))
    
    # Power anomalies
    instrument(Event(
        event_name="power_reading",
        user_role="SYSTEM",
        user_id="sensor_2",
        source_id="hacked_meter_1",
        timestamp=now,
        context={"value": 300.0, "historical_avg": 120.0}
    ))
    
    instrument(Event(
        event_name="power_reading",
        user_role="SYSTEM",
        user_id="sensor_2",
        source_id="hacked_meter_1",
        timestamp=now,
        context={"value": 0, "historical_avg": 120.0}
    ))
    
    # Unusual time activity
    unusual_time = now.replace(hour=2)  # 2 AM
    instrument(Event(
        event_name="toggle_device",
        user_role="USER",
        user_id=attacker_user,
        source_id="192.168.1.200",
        timestamp=unusual_time,
        context={"device": "thermostat", "state": "high"}
    ))
    
    # Role escalation
    instrument(Event(
        event_name="change_role",
        user_role="USER",
        user_id=attacker_user,
        source_id="192.168.1.666",
        timestamp=now,
        context={"new_role": "ADMIN"}
    ))
    
    # Geographic anomaly - Step 1
    instrument(Event(
        event_name="login_attempt",
        user_role="USER",
        user_id=attacker_user,
        source_id="192.168.5.100",
        timestamp=now,
        context={"success": True, "location": "41.7178,-73.0060"}
    ))

    # Geographic anomaly - Step 2
    instrument(Event(
        event_name="login_attempt",
        user_role="USER",
        user_id=attacker_user,
        source_id="192.168.5.100",
        timestamp=now + timedelta(seconds=10),
        context={"success": True, "location": "51.7178,-83.0060"}
    ))
    
    # Device impersonation
    instrument(Event(
        event_name="toggle_device",
        user_role="USER",
        user_id="user_normal_123",
        source_id="192.168.1.666",
        timestamp=now,
        context={"device": "light_1", "state": "off"}
    ))
    
    return {"status": "simulated attack activity"}

@app.get("/event-logs")
async def get_event_logs(limit: int = 100):
    """Get recent event logs"""
    return event_history[-limit:]

@app.get("/attack-logs")
async def get_attack_logs(limit: int = 100):
    """Get recent attack logs"""
    return attack_logs[-limit:]

@app.post("/reset-logs")
async def reset_logs():
    """Clear all logs (for testing)"""
    global event_history, attack_logs, user_profiles
    event_history = []
    attack_logs = []
    user_profiles = defaultdict(dict)
    return {"status": "logs reset"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
