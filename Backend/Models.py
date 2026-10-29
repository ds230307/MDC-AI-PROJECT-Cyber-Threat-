from sqlalchemy import Column, Integer, String, Float, Text, DateTime, JSON
from datetime import datetime
from database import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    input_type = Column(String)
    model_used = Column(String)
    input_text = Column(Text)
    risk_level = Column(String, index=True)      # HIGH / MEDIUM / LOW
    confidence = Column(Float)
    category_scores = Column(JSON)                # {"Ransomware": 82.3, ...}
    mitre_techniques = Column(JSON)                # [{"id":"T1486","name":"..."}]
    iocs = Column(JSON)                            # [{"type":"IP","value":"..."}]


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ioc_type = Column(String)
    indicator = Column(String)
    verdict = Column(String)          # MALICIOUS / CLEAN
    threat_score = Column(Integer)
    sources_checked = Column(JSON)
    mitre_matches = Column(JSON)
    last_seen = Column(String)


class ThreatFeedItem(Base):
    __tablename__ = "threat_feed"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    title = Column(String)
    risk_level = Column(String)
    source = Column(String)
