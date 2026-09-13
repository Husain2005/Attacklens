"""
AttackLens - Automated Attack Timeline Reconstruction & Incident Investigation Engine
Full Self-Contained Web Platform Application with Email/File Threat Scanner
"""

import re
import json
import tempfile
import uuid
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import email
from email import policy

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from pydantic import BaseModel, Field

# ==============================================================================
# 1. DOMAIN MODELS & SCHEMAS
# ==============================================================================

class NormalizedEvent(BaseModel):
    """Canonical event format across all log sources."""
    event_id: str
    timestamp: datetime
    source_format: str
    host: str = "UNKNOWN"
    username: str = "UNKNOWN"
    process_name: Optional[str] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    event_type: str = "GENERIC"
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class IOCItem(BaseModel):
    """Extracted Indicator of Compromise."""
    type: str
    value: str
    context: str
    severity: str = "MEDIUM"


class DetectionRuleMatch(BaseModel):
    """Detection rule match metadata."""
    rule_id: str
    rule_name: str
    description: str
    mitre_id: str
    mitre_tactic: str
    severity_weight: int
    confidence_weight: int
    recommendation: str


class Incident(BaseModel):
    """Correlated Security Incident story context."""
    incident_id: str
    title: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    severity_score: int = 0
    severity_label: str = "LOW"
    confidence_score: float = 0.0
    events: List[NormalizedEvent] = Field(default_factory=list)
    detections: List[DetectionRuleMatch] = Field(default_factory=list)
    iocs: List[IOCItem] = Field(default_factory=list)
    affected_hosts: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    executive_summary: str = ""

# ==============================================================================
# 2. LOG PARSERS WITH FLEXIBLE TEXT HANDLING
# ==============================================================================

class MultiFormatParser:
    """Ingests and normalizes structured and unstructured logs safely."""

    @staticmethod
    def parse_text_stream(content: str, default_source: str = "Text Input") -> List[NormalizedEvent]:
        """Parses generic plain text / raw log lines (auth.log, syslog, firewall, text)."""
        events = []
        if not content or not content.strip():
            return events

        lines = content.splitlines()
        current_year = datetime.utcnow().year

        ssh_failed = r"Failed password for (invalid user )?(\S+) from (\S+) port (\d+) ssh2"
        ssh_success = r"Accepted (password|publickey) for (\S+) from (\S+) port (\d+) ssh2"
        sudo_regex = r"sudo:\s+(\S+) : TTY=\S+ ; USER=(\S+) ; COMMAND=(.*)"
        kv_regex = r'(\w+)=["\']?([^"\'\s]+)["\']?'

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            ts = datetime.utcnow()
            parts = line.split()
            host = parts[3] if len(parts) >= 4 else "UNKNOWN_HOST"

            if len(parts) >= 3:
                try:
                    raw_ts = f"{current_year} {' '.join(parts[:3])}"
                    ts = datetime.strptime(raw_ts, "%Y %b %d %H:%M:%S")
                except ValueError:
                    pass

            # 1. SSH Failed Login
            failed_match = re.search(ssh_failed, line)
            if failed_match:
                events.append(NormalizedEvent(
                    event_id="4625",
                    timestamp=ts,
                    source_format=default_source,
                    host=host,
                    username=failed_match.group(2),
                    src_ip=failed_match.group(3),
                    event_type="FAILED_LOGIN",
                    command_line=line[:500],
                    raw_data={"raw_line": line}
                ))
                continue

            # 2. SSH Successful Login
            success_match = re.search(ssh_success, line)
            if success_match:
                events.append(NormalizedEvent(
                    event_id="4624",
                    timestamp=ts,
                    source_format=default_source,
                    host=host,
                    username=success_match.group(2),
                    src_ip=success_match.group(3),
                    event_type="SUCCESSFUL_LOGIN",
                    command_line=line[:500],
                    raw_data={"raw_line": line}
                ))
                continue

            # 3. Sudo Privilege Escalation
            sudo_match = re.search(sudo_regex, line)
            if sudo_match:
                events.append(NormalizedEvent(
                    event_id="sudo_exec",
                    timestamp=ts,
                    source_format=default_source,
                    host=host,
                    username=sudo_match.group(1),
                    process_name="sudo",
                    command_line=sudo_match.group(3)[:500],
                    event_type="PRIVILEGE_ESCALATION",
                    raw_data={"raw_line": line}
                ))
                continue

            # 4. Key-Value / Firewall Log Pattern
            kv = dict(re.findall(kv_regex, line))
            if kv and ("src" in kv or "SRC" in kv or "action" in kv or "act" in kv or "hostname" in kv):
                src_ip = kv.get("src") or kv.get("SRC")
                dest_ip = kv.get("dst") or kv.get("DST")
                dest_port = kv.get("dpt") or kv.get("DPT")
                action = kv.get("action") or kv.get("act") or ("BLOCK" if "DENY" in line or "DROP" in line else "ALLOW")

                events.append(NormalizedEvent(
                    event_id=f"FW_{action.upper()}",
                    timestamp=ts,
                    source_format="Firewall Text",
                    host=kv.get("hostname", "FIREWALL_GATEWAY"),
                    username="NETWORK",
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    dest_port=int(dest_port) if dest_port and dest_port.isdigit() else None,
                    command_line=f"Action: {action} | Src: {src_ip} -> Dst: {dest_ip}:{dest_port}",
                    raw_data={"raw_line": line, "kv": kv}
                ))
                continue

            # Universal Fallback for Long / Custom Logs
            events.append(NormalizedEvent(
                event_id=f"LOG_LINE_{line_num}",
                timestamp=ts,
                source_format=default_source,
                host=host if host != "UNKNOWN_HOST" else "HOST",
                command_line=line[:1000],
                raw_data={"raw_line": line}
            ))

        return events

    @staticmethod
    def parse_json(content: str) -> List[NormalizedEvent]:
        events = []
        try:
            data = json.loads(content)
        except Exception:
            return []

        records = data if isinstance(data, list) else [data]

        for rec in records:
            if not isinstance(rec, dict):
                continue

            ts_str = str(rec.get("timestamp") or rec.get("TimeCreated") or datetime.utcnow().isoformat())
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.utcnow()

            events.append(
                NormalizedEvent(
                    event_id=str(rec.get("event_id") or rec.get("EventID") or "0"),
                    timestamp=ts,
                    source_format="JSON/WinEvent",
                    host=str(rec.get("host") or rec.get("Computer") or "UNKNOWN"),
                    username=str(rec.get("username") or rec.get("User") or "UNKNOWN"),
                    process_name=rec.get("process") or rec.get("Image"),
                    parent_process_name=rec.get("parent_process") or rec.get("ParentImage"),
                    command_line=rec.get("command_line") or rec.get("CommandLine"),
                    src_ip=rec.get("src_ip") or rec.get("IpAddress"),
                    dest_ip=rec.get("dest_ip") or rec.get("DestinationIp"),
                    raw_data=rec
                )
            )
        return events

    @staticmethod
    def parse_csv(file_path: Path) -> List[NormalizedEvent]:
        events = []
        try:
            df = pd.read_csv(file_path).fillna("")
        except Exception:
            return []

        for idx, row in df.iterrows():
            ts_val = str(row.get("timestamp", row.get("Time", datetime.utcnow().isoformat())))
            try:
                ts = pd.to_datetime(ts_val).to_pydatetime()
            except Exception:
                ts = datetime.utcnow()

            events.append(
                NormalizedEvent(
                    event_id=str(row.get("event_id", idx)),
                    timestamp=ts,
                    source_format="CSV Log",
                    host=str(row.get("host", "UNKNOWN")),
                    username=str(row.get("username", "UNKNOWN")),
                    process_name=str(row.get("process", "")) or None,
                    parent_process_name=str(row.get("parent_process", "")) or None,
                    command_line=str(row.get("command_line", "")) or None,
                    src_ip=str(row.get("src_ip", "")) or None,
                    dest_ip=str(row.get("dest_ip", "")) or None,
                    raw_data=row.to_dict()
                )
            )
        return events

# ==============================================================================
# 3. DETECTION & CORRELATION ENGINES
# ==============================================================================

DEFAULT_RULES = [
    {
        "id": "R-1001",
        "name": "Repeated Failed Logins / Brute-Force",
        "description": "Detects multiple authentication failures indicating credential access attempts.",
        "mitre_id": "T1110.001",
        "mitre_tactic": "Credential Access",
        "severity_weight": 20,
        "confidence_weight": 15,
        "recommendation": "Lock target user account and block origin IP address at firewall perimeter.",
        "conditions": {"event_id": ["4625"]}
    },
    {
        "id": "R-1002",
        "name": "Encoded PowerShell Execution",
        "description": "Detects execution of PowerShell commands using Base64 encoded payload switches.",
        "mitre_id": "T1059.001",
        "mitre_tactic": "Execution",
        "severity_weight": 30,
        "confidence_weight": 25,
        "recommendation": "Decode command payload from host logs; isolate host immediately.",
        "conditions": {
            "process_name": ["powershell.exe", "pwsh.exe"],
            "command_line_regex": "(?i)(-enc|-encodedcommand|-e\\s)"
        }
    },
    {
        "id": "R-1003",
        "name": "Office Spawning Command Interpreter",
        "description": "Detects Microsoft Office launching cmd or powershell processes.",
        "mitre_id": "T1204.002",
        "mitre_tactic": "Execution",
        "severity_weight": 35,
        "confidence_weight": 30,
        "recommendation": "Quarantine email attachment and kill spawned process tree.",
        "conditions": {
            "parent_process_regex": "(?i)(winword\\.exe|excel\\.exe|powerpnt\\.exe)",
            "process_name": ["cmd.exe", "powershell.exe", "pwsh.exe"]
        }
    },
    {
        "id": "R-1004",
        "name": "Linux Privilege Escalation via Sudo",
        "description": "Detects sudo execution for elevated administrative privilege abuse.",
        "mitre_id": "T1548.003",
        "mitre_tactic": "Privilege Escalation",
        "severity_weight": 25,
        "confidence_weight": 20,
        "recommendation": "Audit sudoers configuration and investigate executed binary.",
        "conditions": {"process_name": ["sudo"]}
    },
    {
        "id": "R-1005",
        "name": "Perimeter Firewall Blocked Outbound Traffic",
        "description": "Detects egress network connection drops pointing to potential malware C2.",
        "mitre_id": "T1071.001",
        "mitre_tactic": "Command and Control",
        "severity_weight": 15,
        "confidence_weight": 10,
        "recommendation": "Inspect internal endpoint for malicious network socket listeners.",
        "conditions": {"event_id": ["FW_BLOCK", "FW_DENY", "FW_DROP"]}
    }
]


class DetectionEngine:
    def __init__(self, rules: List[Dict[str, Any]]):
        self.rules = rules

    def evaluate(self, events: List[NormalizedEvent]) -> List[Tuple[NormalizedEvent, DetectionRuleMatch]]:
        matches = []
        for event in events:
            for rule in self.rules:
                if self._check_rule(event, rule):
                    match = DetectionRuleMatch(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        description=rule["description"],
                        mitre_id=rule["mitre_id"],
                        mitre_tactic=rule["mitre_tactic"],
                        severity_weight=rule["severity_weight"],
                        confidence_weight=rule["confidence_weight"],
                        recommendation=rule["recommendation"]
                    )
                    matches.append((event, match))
        return matches

    def _check_rule(self, event: NormalizedEvent, rule: Dict[str, Any]) -> bool:
        conds = rule.get("conditions", {})

        if "event_id" in conds:
            eid = str(event.event_id)
            if not any(str(expected) == eid for expected in conds["event_id"]):
                return False

        if "process_name" in conds:
            if not event.process_name or not any(p.lower() in event.process_name.lower() for p in conds["process_name"]):
                return False

        if "command_line_regex" in conds:
            if not event.command_line or not re.search(conds["command_line_regex"], event.command_line):
                return False

        if "parent_process_regex" in conds:
            if not event.parent_process_name or not re.search(conds["parent_process_regex"], event.parent_process_name):
                return False

        return True


class CorrelationEngine:
    def __init__(self, time_window_minutes: int = 120):
        self.window = timedelta(minutes=time_window_minutes)

    def correlate(self, matches: List[Tuple[NormalizedEvent, DetectionRuleMatch]]) -> List[Incident]:
        if not matches:
            return []

        sorted_matches = sorted(matches, key=lambda x: x[0].timestamp)
        incidents: List[Incident] = []

        for event, rule_match in sorted_matches:
            assigned = False
            for inc in incidents:
                same_host = event.host != "UNKNOWN" and event.host in inc.affected_hosts
                same_user = event.username != "UNKNOWN" and event.username in inc.affected_users
                time_close = abs(event.timestamp - inc.events[-1].timestamp) <= self.window

                if (same_host or same_user) and time_close:
                    inc.events.append(event)
                    inc.detections.append(rule_match)
                    if event.host not in inc.affected_hosts and event.host != "UNKNOWN":
                        inc.affected_hosts.append(event.host)
                    if event.username not in inc.affected_users and event.username != "UNKNOWN":
                        inc.affected_users.append(event.username)
                    if rule_match.mitre_tactic not in inc.mitre_tactics:
                        inc.mitre_tactics.append(rule_match.mitre_tactic)
                    if rule_match.recommendation not in inc.recommendations:
                        inc.recommendations.append(rule_match.recommendation)
                    assigned = True
                    break

            if not assigned:
                new_inc = Incident(
                    incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                    title=f"Incident involving {event.host} / {event.username}",
                    events=[event],
                    detections=[rule_match],
                    affected_hosts=[event.host] if event.host != "UNKNOWN" else [],
                    affected_users=[event.username] if event.username != "UNKNOWN" else [],
                    mitre_tactics=[rule_match.mitre_tactic],
                    recommendations=[rule_match.recommendation]
                )
                incidents.append(new_inc)

        return incidents


class IOCExtractor:
    IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    HASH_REGEX = r"\b[a-fA-F0-9]{64}\b"
    URL_REGEX = r"https?://[^\s<>\"']+"

    def extract(self, events: List[NormalizedEvent]) -> List[IOCItem]:
        iocs: List[IOCItem] = []
        seen = set()

        for ev in events:
            text_block = f"{ev.command_line or ''} {ev.src_ip or ''} {ev.dest_ip or ''} {str(ev.raw_data)}"

            for ip in re.findall(self.IP_REGEX, text_block):
                if ip not in ["127.0.0.1", "0.0.0.0"] and ip not in seen:
                    seen.add(ip)
                    iocs.append(IOCItem(type="IP Address", value=ip, context=f"Observed on Host {ev.host}"))

            for sha in re.findall(self.HASH_REGEX, text_block):
                if sha not in seen:
                    seen.add(sha)
                    iocs.append(IOCItem(type="SHA256 Hash", value=sha, context=f"Binary executed on {ev.host}"))

            for url in re.findall(self.URL_REGEX, text_block):
                if url not in seen:
                    seen.add(url)
                    iocs.append(IOCItem(type="URL Payload", value=url, context=f"Command payload on {ev.host}"))

        return iocs


class ScoringEngine:
    @staticmethod
    def process(incident: Incident):
        total_score = sum(d.severity_weight for d in incident.detections)
        if len(incident.affected_hosts) > 1:
            total_score = int(total_score * 1.3)

        incident.severity_score = total_score
        if total_score < 20:
            incident.severity_label = "LOW"
        elif total_score < 45:
            incident.severity_label = "MEDIUM"
        elif total_score < 75:
            incident.severity_label = "HIGH"
        elif total_score < 100:
            incident.severity_label = "SEVERE"
        else:
            incident.severity_label = "CRITICAL"

        base_conf = sum(d.confidence_weight for d in incident.detections) / max(len(incident.detections), 1)
        bonus = min(len(incident.events) * 3, 20) + min(len(incident.iocs) * 5, 15)
        incident.confidence_score = round(min(base_conf + bonus, 99.0), 1)

        hosts_str = ", ".join(incident.affected_hosts) if incident.affected_hosts else "Unknown Host"
        users_str = ", ".join(incident.affected_users) if incident.affected_users else "Unknown User"
        tactics_str = ", ".join(incident.mitre_tactics) if incident.mitre_tactics else "Execution"
        rules_str = ", ".join(set(d.rule_name for d in incident.detections))

        incident.executive_summary = (
            f"AttackLens engine reconstructed a {incident.severity_label} severity attack story "
            f"({incident.incident_id}) with a calculated confidence score of {incident.confidence_score}%. "
            f"The attack chain affected targets [{hosts_str}] and involved accounts [{users_str}]. "
            f"Detected adversarial activity aligns with MITRE ATT&CK tactics: {tactics_str}. "
            f"Triggered rule matches: {rules_str}. "
            f"A total of {len(incident.iocs)} Indicators of Compromise (IOCs) were automatically extracted."
        )

# ==============================================================================
# 4. MALICIOUS FILE & EMAIL ANALYZER ENGINE
# ==============================================================================

class ThreatScanner:
    SUSPICIOUS_EXTENSIONS = ['.exe', '.vbs', '.js', '.scr', '.bat', '.ps1', '.docm', '.xlsm', '.zip', '.iso']
    SUSPICIOUS_KEYWORDS = ['password', 'urgent', 'login', 'verify', 'update', 'invoice', 'bank', 'wire', 'account']

    @classmethod
    def analyze_file(cls, filename: str, content: bytes) -> Dict[str, Any]:
        sha256_hash = hashlib.sha256(content).hexdigest()
        md5_hash = hashlib.md5(content).hexdigest()
        ext = Path(filename).suffix.lower()

        is_suspicious_ext = ext in cls.SUSPICIOUS_EXTENSIONS
        findings = []
        score = 0

        if is_suspicious_ext:
            score += 40
            findings.append(f"Dangerous or executable extension detected: '{ext}'")

        # Check binary signatures (e.g., Executable header MZ)
        if content.startswith(b'MZ'):
            score += 30
            findings.append("Executable magic header (MZ) detected in binary content.")

        # Email Inspection (.eml or .msg)
        email_metadata = None
        if ext in ['.eml', '.msg', '.txt'] or b"Received:" in content[:500]:
            try:
                msg = email.message_from_bytes(content, policy=policy.default)
                email_metadata = {
                    "Subject": msg.get("subject", "N/A"),
                    "From": msg.get("from", "N/A"),
                    "To": msg.get("to", "N/A"),
                    "Date": msg.get("date", "N/A")
                }
                body = msg.get_body(preferencelist=('plain', 'html'))
                body_text = body.get_content() if body else ""

                # Extract URLs in body
                urls = re.findall(r"https?://[^\s<>\"']+", body_text)
                if urls:
                    findings.append(f"Extracted {len(urls)} link(s) from email body.")
                    score += 15

                # Check subject keywords
                subj = str(msg.get("subject", "")).lower()
                for kw in cls.SUSPICIOUS_KEYWORDS:
                    if kw in subj:
                        score += 10
                        findings.append(f"Suspicious keyword '{kw}' found in Subject line.")
            except Exception:
                pass

        status = "MALICIOUS / HIGH RISK" if score >= 40 else ("SUSPICIOUS" if score >= 20 else "CLEAN / LOW RISK")

        return {
            "filename": filename,
            "size_bytes": len(content),
            "sha256": sha256_hash,
            "md5": md5_hash,
            "score": score,
            "status": status,
            "findings": findings,
            "email_metadata": email_metadata
        }

# ==============================================================================
# 5. STREAMLIT WEB INTERFACE
# ==============================================================================

st.set_page_config(
    page_title="AttackLens | Incident & Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    .main { background-color: #0d1117; color: #c9d1d9; }
    .stMetric { background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; }
    .stAlert { background-color: #161b22; border-left: 4px solid #58a6ff; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ AttackLens SOC Investigation Engine")
st.caption("Automated Incident Timeline Reconstruction & Malicious Threat Inspection")

# Navigation Tabs
nav_tab1, nav_tab2 = st.tabs(["📊 Incident Log Reconstruction", "🔍 Email & File Threat Inspector"])

with nav_tab1:
    st.sidebar.header("📁 Multi-Source Log Ingestion")

    # Option 1: File Upload
    uploaded_files = st.sidebar.file_uploader(
        "1. Upload Security Log Files",
        type=["json", "csv", "xml", "log", "txt", "syslog", "auth"],
        accept_multiple_files=True
    )

    st.sidebar.markdown("---")

    # Option 2: Direct Text Input
    st.sidebar.subheader("2. Paste Raw Logs Direct")
    raw_text_input = st.sidebar.text_area(
        "Paste Auth Logs, Syslog, or Raw Text Strings",
        height=180,
        placeholder="Sep 12 08:30:12 srv-db01 sshd[14220]: Failed password for invalid user admin from 198.51.100.42 port 52102 ssh2..."
    )

    # Explicit Action Button to run log analysis
    run_log_analysis = st.sidebar.button("⚡ Run Log Analysis Engine", type="primary")

    raw_events = []
    MAX_FILE_SIZE_MB = 100

    if run_log_analysis or uploaded_files or (raw_text_input and raw_text_input.strip()):
        with st.spinner("Parsing and normalizing inputs..."):
            
            # 1. Process Files
            if uploaded_files:
                for file in uploaded_files:
                    if file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
                        st.error(f"❌ File '{file.name}' exceeds maximum size of {MAX_FILE_SIZE_MB}MB.")
                        continue

                    content_bytes = file.getvalue()
                    if not content_bytes or not content_bytes.strip():
                        st.warning(f"⚠️ File '{file.name}' is empty. Skipping.")
                        continue

                    file_ext = file.name.split('.')[-1].lower()
                    try:
                        content_str = content_bytes.decode("utf-8", errors="ignore")
                    except Exception as e:
                        st.error(f"❌ Failed to decode file '{file.name}': {e}")
                        continue

                    if file_ext == "json":
                        parsed = MultiFormatParser.parse_json(content_str)
                        if not parsed:
                            parsed = MultiFormatParser.parse_text_stream(content_str, default_source=file.name)
                        raw_events.extend(parsed)

                    elif file_ext == "csv":
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
                            tmp.write(content_bytes)
                            tmp_path = Path(tmp.name)
                        raw_events.extend(MultiFormatParser.parse_csv(tmp_path))

                    else:
                        raw_events.extend(MultiFormatParser.parse_text_stream(content_str, default_source=file.name))

            # 2. Process Direct Text Input
            if raw_text_input and raw_text_input.strip():
                text_parsed = MultiFormatParser.parse_text_stream(raw_text_input.strip(), default_source="Pasted Log Text")
                raw_events.extend(text_parsed)

        if not raw_events:
            st.error("❌ No parseable log data found. Please enter valid log text.")
        else:
            st.success(f"Successfully normalized **{len(raw_events)}** canonical event lines.")

            # Processing Pipeline
            detection_engine = DetectionEngine(DEFAULT_RULES)
            matches = detection_engine.evaluate(raw_events)

            correlation_engine = CorrelationEngine()
            incidents = correlation_engine.correlate(matches)

            ioc_extractor = IOCExtractor()

            for inc in incidents:
                inc.iocs = ioc_extractor.extract(inc.events)
                ScoringEngine.process(inc)

            if not incidents:
                st.warning("No correlation matches triggered. Raw events displayed below.")
                st.dataframe(pd.DataFrame([e.dict() for e in raw_events]))
            else:
                inc_map = {inc.incident_id: inc for inc in incidents}
                selected_id = st.sidebar.selectbox("Select Correlated Incident", list(inc_map.keys()))
                selected_inc = inc_map[selected_id]

                # Metric Cards
                mcol1, mcol2, mcol3, mcol4 = st.columns(4)
                mcol1.metric("Severity Level", selected_inc.severity_label)
                mcol2.metric("Risk Score", selected_inc.severity_score)
                mcol3.metric("Confidence", f"{selected_inc.confidence_score}%")
                mcol4.metric("Extracted IOCs", len(selected_inc.iocs))

                st.markdown("---")

                # Executive Summary
                st.subheader("📋 Executive Briefing")
                st.info(selected_inc.executive_summary)

                # Charts
                gcol1, gcol2 = st.columns([1, 2])

                with gcol1:
                    fig_gauge = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=selected_inc.severity_score,
                        domain={'x': [0, 1], 'y': [0, 1]},
                        title={'text': "Incident Risk Score"},
                        gauge={
                            'axis': {'range': [0, 120]},
                            'bar': {'color': "#f85149"},
                            'steps': [
                                {'range': [0, 30], 'color': "#3fb950"},
                                {'range': [30, 70], 'color': "#d29922"},
                                {'range': [70, 120], 'color': "#f85149"}
                            ]
                        }
                    ))
                    fig_gauge.update_layout(template="plotly_dark", height=280)
                    st.plotly_chart(fig_gauge, use_container_width=True)

                with gcol2:
                    timeline_rows = [
                        {
                            "Timestamp": ev.timestamp,
                            "Host": ev.host,
                            "User": ev.username,
                            "Source": ev.source_format,
                            "Details": ev.command_line or ev.process_name or "N/A"
                        }
                        for ev in selected_inc.events
                    ]
                    df_timeline = pd.DataFrame(timeline_rows)

                    fig_timeline = px.scatter(
                        df_timeline,
                        x="Timestamp",
                        y="Host",
                        color="Source",
                        hover_data=["User", "Details"],
                        title="Chronological Attack Chain",
                        template="plotly_dark"
                    )
                    fig_timeline.update_traces(marker=dict(size=14, symbol="diamond"))
                    fig_timeline.update_layout(height=280)
                    st.plotly_chart(fig_timeline, use_container_width=True)

                # Details Tabs
                tab1, tab2, tab3, tab4 = st.tabs([
                    "⏱️ Timeline Data",
                    "🎯 MITRE Detections",
                    "🚨 Extracted IOCs",
                    "💡 Recommendations"
                ])

                with tab1:
                    st.dataframe(df_timeline, use_container_width=True)

                with tab2:
                    det_df = pd.DataFrame([
                        {
                            "Rule ID": d.rule_id,
                            "Rule Name": d.rule_name,
                            "MITRE ID": d.mitre_id,
                            "Tactic": d.mitre_tactic,
                            "Description": d.description
                        }
                        for d in selected_inc.detections
                    ])
                    st.table(det_df)

                with tab3:
                    if selected_inc.iocs:
                        ioc_df = pd.DataFrame([
                            {"IOC Type": i.type, "Indicator Value": i.value, "Context": i.context}
                            for i in selected_inc.iocs
                        ])
                        st.table(ioc_df)
                    else:
                        st.write("No IOCs extracted from this incident.")

                with tab4:
                    st.subheader("Automated Containment Guidance")
                    for rec in set(selected_inc.recommendations):
                        st.warning(f"• {rec}")
    else:
        st.info("👈 Paste text logs or upload log files in the sidebar and click 'Run Log Analysis Engine'.")

# ==============================================================================
# SECTION 2: EMAIL & FILE THREAT INSPECTOR
# ==============================================================================
with nav_tab2:
    st.header("🔎 Malicious Email & Artifact Inspector")
    st.write("Upload suspicious email files (`.eml`, `.msg`), scripts, executables, or attachments for automated malicious analysis.")

    threat_file = st.file_uploader(
        "Upload Email file or Artifact to Inspect",
        type=None,
        key="threat_file_uploader"
    )

    if threat_file:
        file_bytes = threat_file.getvalue()
        res = ThreatScanner.analyze_file(threat_file.name, file_bytes)

        st.markdown("---")
        tcol1, tcol2, tcol3 = st.columns(3)
        tcol1.metric("Analysis Status", res["status"])
        tcol2.metric("Threat Score", f"{res['score']} / 100")
        tcol3.metric("File Size", f"{res['size_bytes']} Bytes")

        if res["email_metadata"]:
            st.subheader("📧 Email Header Metadata")
            st.json(res["email_metadata"])

        st.subheader("🔑 File Hashes")
        st.code(f"SHA256: {res['sha256']}\nMD5:    {res['md5']}", language="text")

        st.subheader("⚠️ Threat Detection Findings")
        if res["findings"]:
            for finding in res["findings"]:
                st.error(f"• {finding}")
        else:
            st.success("No immediate threat indicators found in this file.")