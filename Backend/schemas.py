from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime


class AnalyzeRequest(BaseModel):
    input_type: str
    model: str
    text: str


class IOCItem(BaseModel):
    type: str
    value: str


class MitreItem(BaseModel):
    id: str
    name: str


class AnalyzeResponse(BaseModel):
    id: int
    timestamp: datetime
    risk_level: str
    confidence: float
    category_scores: Dict[str, float]
    mitre_techniques: List[MitreItem]
    iocs: List[IOCItem]

    class Config:
        orm_mode = True


class ScanRequest(BaseModel):
    ioc_type: str
    indicator: str
    sources: List[str] = []


class ScanResponse(BaseModel):
    id: int
    verdict: str
    threat_score: int
    ioc_type: str
    indicator: str
    mitre_matches: List[str]
    last_seen: str
    sources_checked: List[str]


class DashboardMetrics(BaseModel):
    threats_today: int
    high_risk_alerts: int
    iocs_extracted: int
    ai_confidence: float


class ChartPoint(BaseModel):
    day: str
    high: int
    medium: int
    low: int


class DistributionResponse(BaseModel):
    high: float
    medium: float
    low: float


class FeedItem(BaseModel):
    id: int
    timestamp: datetime
    title: str
    risk_level: str
    source: str

    class Config:
        orm_mode = True
