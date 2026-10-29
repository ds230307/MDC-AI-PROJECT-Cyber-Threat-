import re
import random
from datetime import datetime, timedelta

IOC_PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz)\b"),
    "hash": re.compile(r"\b[a-fA-F0-9]{32,64}\b"),
    "cve": re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}

CATEGORY_KEYWORDS = {
    "Ransomware": ["ransomware", "encrypt", "decrypt", "bitcoin", "ransom", "locker", "extortion"],
    "APT / Nation-State": ["apt", "nation-state", "espionage", "advanced persistent", "state-sponsored", "cyberespionage"],
    "Phishing": ["phishing", "credential", "spoofed", "fake login", "email lure", "social engineering"],
    "DDoS": ["ddos", "denial of service", "botnet", "flood", "amplification"],
    "Insider Threat": ["insider", "disgruntled", "privileged access", "data exfiltration", "employee"],
    "Malware": ["malware", "trojan", "backdoor", "rootkit", "worm", "payload", "dropper"],
}

MITRE_MAP = {
    "Ransomware": [("T1486", "Data Encrypted for Impact"), ("T1490", "Inhibit System Recovery")],
    "APT / Nation-State": [("T1071", "Application Layer Protocol"), ("T1059", "Command and Scripting Interpreter")],
    "Phishing": [("T1566", "Phishing"), ("T1204", "User Execution")],
    "DDoS": [("T1498", "Network Denial of Service")],
    "Insider Threat": [("T1078", "Valid Accounts"), ("T1530", "Data from Cloud Storage")],
    "Malware": [("T1105", "Ingress Tool Transfer"), ("T1027", "Obfuscated Files or Information")],
}

HIGH_RISK_CATEGORIES = {"Ransomware", "APT / Nation-State", "Malware"}


def extract_iocs(text: str):
    iocs = []
    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in set(pattern.findall(text)):
            iocs.append({"type": ioc_type.upper(), "value": match})
    return iocs


def classify_threat(text: str, model: str = "hybrid"):
    text_lower = text.lower()
    hit_counts = {cat: sum(1 for kw in kws if kw in text_lower)
                  for cat, kws in CATEGORY_KEYWORDS.items()}
    total_hits = sum(hit_counts.values())

    if total_hits == 0:
        top_category = "Uncategorized"
        confidence = round(40 + random.uniform(0, 10), 1)
        risk_level = "LOW"
        category_scores = {"Uncategorized": 100.0}
    else:
        top_category = max(hit_counts, key=hit_counts.get)
        category_scores = {
            cat: round(min(96, 35 + hits * 14 + random.uniform(0, 8)), 1)
            for cat, hits in hit_counts.items() if hits > 0
        }
        confidence = round(min(99.4, 58 + hit_counts[top_category] * 10 + random.uniform(0, 7)), 1)

        if top_category in HIGH_RISK_CATEGORIES or hit_counts[top_category] >= 3:
            risk_level = "HIGH"
        else:
            risk_level = "MEDIUM"

    mitre_pairs = MITRE_MAP.get(top_category, [])
    mitre_techniques = [{"id": tid, "name": name} for tid, name in mitre_pairs]
    iocs = extract_iocs(text)

    return {
        "risk_level": risk_level,
        "confidence": confidence,
        "category_scores": category_scores,
        "mitre_techniques": mitre_techniques,
        "iocs": iocs,
        "top_category": top_category,
    }


def scan_indicator(ioc_type: str, indicator: str, sources: list):
    """Deterministic pseudo-intel lookup: same indicator -> same verdict, every time."""
    seed = sum(ord(c) for c in indicator) + len(ioc_type)
    rnd = random.Random(seed)

    is_malicious = rnd.random() > 0.45
    threat_score = rnd.randint(70, 98) if is_malicious else rnd.randint(2, 28)
    verdict = "MALICIOUS" if is_malicious else "CLEAN"

    mitre_pool = ["T1071", "T1566", "T1486", "T1059", "T1078", "T1105", "T1498"]
    mitre_matches = rnd.sample(mitre_pool, k=rnd.randint(1, 3)) if is_malicious else []

    days_ago = rnd.randint(0, 45)
    last_seen = (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%d")

    return {
        "verdict": verdict,
        "threat_score": threat_score,
        "mitre_matches": mitre_matches,
        "last_seen": last_seen,
    }
