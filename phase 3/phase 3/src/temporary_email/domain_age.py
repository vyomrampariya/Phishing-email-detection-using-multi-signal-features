"""Domain-age signal. No network lookup is performed by default."""
from datetime import date, datetime, timezone

def age_risk_from_days(age_days, config):
    if age_days is None: return {"score":None,"status":"UNAVAILABLE","evidence":[],"source":None,"explanation":"Registration date unavailable; no zero-risk assumption made."}
    if isinstance(age_days,bool) or not isinstance(age_days,int) or age_days < 0:
        return {"score":None,"status":"UNKNOWN","evidence":[],"source":None,"explanation":"Invalid domain age evidence."}
    for rule in config.get("age_risk_days",[]):
        limit=rule.get("max_age_days")
        if limit is None or age_days <= int(limit):
            return {"score":float(rule["score"]),"status":"ESTIMATED","evidence":[f"Domain registration age: {age_days} days"],"source":"configured age-risk mapping","explanation":"Age is a weak risk signal and does not imply disposability or maliciousness."}
    return {"score":0.0,"status":"ESTIMATED","evidence":[f"Domain registration age: {age_days} days"],"source":"configured age-risk mapping","explanation":"Domain is older than configured risk bands."}

def age_days_from_registration_date(registration_date, today=None):
    if not registration_date: return None
    try:
        if isinstance(registration_date,str):
            parsed=datetime.fromisoformat(registration_date.replace("Z","+00:00")).date()
        elif isinstance(registration_date,datetime): parsed=registration_date.date()
        elif isinstance(registration_date,date): parsed=registration_date
        else: return None
        current=today or datetime.now(timezone.utc).date()
        days=(current-parsed).days
        return days if days>=0 else None
    except (ValueError,TypeError): return None
