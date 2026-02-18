#!/usr/bin/env python3
import json
import time
import requests
import os
import argparse
import subprocess
import logging
import urllib3
import glob
import shutil
import hashlib
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- PATH CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(SCRIPT_DIR, "tests")):
    BASE_DIR = SCRIPT_DIR
else:
    BASE_DIR = os.path.dirname(SCRIPT_DIR)

# Directory Setup
SANDBOX_IN_DIR = os.path.join(BASE_DIR, "sandbox_in")
REPORTS_DIR = os.path.join(BASE_DIR, "sandbox_reports")
ARCHIVE_DIR = os.path.join(BASE_DIR, "sandbox_archive")
EVIDENCE_DIR = os.path.join(BASE_DIR, "case_evidence")
RULES_FILE = os.path.join(BASE_DIR, "rules", "local.rules")
OUTPUT_LOG = "orchestrator_events.json"

CONFIG = {
    "API_URL": "https://192.168.100.10/api",
    "API_KEY": "YOUR_REAL_API_KEY",
    "VICTIM_IP": "192.168.100.20",
    "VICTIM_USER": "so_agent",
    "SSH_KEY_PATH": "./keys/id_rsa",
    "LOG_FILE": "/nsm/suricata/eve.json",
    "COWRIE_LOG_FILE": "/opt/cowrie/var/log/cowrie/cowrie.json",
    "TEST_LOG_FILE": os.path.join(BASE_DIR, "tests", "dummy_eve.json"),
    "TEST_COWRIE_LOG": os.path.join(BASE_DIR, "tests", "dummy_cowrie.json"),
    "SCORE_THRESHOLD": 10,
    "DECAY_TIME": 3600
}

logger = logging.getLogger("Orchestrator")
logger.setLevel(logging.INFO)

c_handler = logging.StreamHandler()
c_format = logging.Formatter('%(asctime)s - %(message)s')
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)

f_handler = logging.FileHandler(OUTPUT_LOG)
f_format = logging.Formatter('%(message)s')
f_handler.setFormatter(f_format)
logger.addHandler(f_handler)


class RuleManager:
    def __init__(self, rules_path):
        self.rules_path = rules_path
        self.start_sid = 1000000
        self.generated_items = set()
        rules_dir = os.path.dirname(self.rules_path)
        if not os.path.exists(rules_dir): os.makedirs(rules_dir)
            
    def _get_next_sid(self):
        try:
            if not os.path.exists(self.rules_path): return self.start_sid
            with open(self.rules_path, "r") as f: return self.start_sid + len(f.readlines()) + 1
        except: return self.start_sid

    def generate_block_rule(self, ip_address, reason):
        if ip_address in self.generated_items: return None
        sid = self._get_next_sid()
        rule = f'drop ip {ip_address} any -> $HOME_NET any (msg:"[Orchestrator] Auto-Block IP {ip_address} - {reason}"; classtype:trojan-activity; sid:{sid}; rev:1;)'
        self._write_rule(rule)
        self.generated_items.add(ip_address)
        return sid

    def generate_hash_rule(self, file_hash, filename):
        if file_hash in self.generated_items: return None
        sid = self._get_next_sid()
        rule = f'drop http any any -> $HOME_NET any (msg:"[Orchestrator] Block Hash {filename}"; filesha256:{file_hash}; classtype:trojan-activity; sid:{sid}; rev:1;)'
        self._write_rule(rule)
        self.generated_items.add(file_hash)
        return sid

    def _write_rule(self, rule):
        try:
            with open(self.rules_path, "a") as f:
                f.write(f"# Generated {datetime.now()}\n{rule}\n")
        except: pass


class Orchestrator:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.suspicion_scores = {}
        self.active_incidents = {}
        self.headers = {"header-auth-key": CONFIG["API_KEY"], "Content-Type": "application/json"}
        self.rule_manager = RuleManager(RULES_FILE)
        
        if self.dry_run:
            for d in [SANDBOX_IN_DIR, REPORTS_DIR, ARCHIVE_DIR, EVIDENCE_DIR]:
                if not os.path.exists(d): os.makedirs(d)

    def log_event_to_kibana(self, event_type, src_ip, details):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "module": "orchestrator",
            "event_type": event_type,
            "src_ip": src_ip,
            "details": details
        }
        logger.info(json.dumps(log_entry))

    def create_case(self, title, description, severity):
        payload = {"title": title, "description": description, "severity": severity, "tags": ["orchestrator"]}
        if self.dry_run: return str(int(time.time()))
        try:
            resp = requests.post(f"{CONFIG['API_URL']}/case", json=payload, headers=self.headers, verify=False)
            if resp.status_code == 200: return resp.json().get('id')
        except: pass
        return None

    def add_evidence_to_case(self, case_id, evidence_data):
        content = f"**AUTOMATED EVIDENCE ATTACHMENT**\n{json.dumps(evidence_data, indent=2)}"
        if self.dry_run:
            logger.info(f"CASE UPDATE [{case_id}]: Report Updated -> {evidence_data.get('filename', 'Unknown')}")
            return True
        try:
            payload = {"content": content, "format": "markdown"}
            requests.post(f"{CONFIG['API_URL']}/case/{case_id}/comments", json=payload, headers=self.headers, verify=False)
            return True
        except: return False

    def generate_professional_report(self, target_ip, case_id, risk_level, sandbox_data=None):
        report_lines = []
        report_lines.append("="*80)
        report_lines.append(f"{'FORENSIC EVIDENCE REPORT':^80}")
        report_lines.append("="*80)
        report_lines.append(f"CASE ID:       {case_id}")
        report_lines.append(f"TARGET IP:     {target_ip}")
        report_lines.append(f"GENERATED:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"STATUS:        {'FINAL - MALWARE CONFIRMED' if sandbox_data else 'PRELIMINARY - INVESTIGATING'}")
        report_lines.append("="*80 + "\n")

        # SECTION 1: MALWARE ANALYSIS
        if sandbox_data:
            report_lines.append("[SECTION 1: MALWARE ANALYSIS SUMMARY]")
            report_lines.append("-" * 80)
            report_lines.append(f"Filename:      {sandbox_data.get('filename', 'N/A')}")
            report_lines.append(f"Verdict:       {sandbox_data.get('vt_verdict', 'UNKNOWN')}")
            report_lines.append(f"SHA256 Hash:   {sandbox_data.get('file_hash', 'N/A')}")
            report_lines.append(f"VirusTotal:    {sandbox_data.get('vt_score', 'N/A')}")
            report_lines.append(f"Analysis Time: {sandbox_data.get('timestamp', 'N/A')}")
            report_lines.append("\n")

        # SECTION 2: NETWORK ARTIFACTS
        report_lines.append("[SECTION 2: NETWORK ARTIFACTS (SURICATA)]")
        report_lines.append("-" * 80)
        eve_path = CONFIG['TEST_LOG_FILE'] if self.dry_run else CONFIG['LOG_FILE']
        try:
            with open(eve_path, 'r') as f:
                for line in f:
                    if target_ip in line:
                        try:
                            data = json.loads(line)
                            ts = data.get('timestamp', '')[:19]
                            sig = data.get('alert', {}).get('signature', 'Unknown Alert')
                            report_lines.append(f"{ts} | {sig}")
                        except: pass
        except: report_lines.append("No Suricata logs found.")
        report_lines.append("\n")

        # SECTION 3: HONEYPOT SESSION
        report_lines.append("[SECTION 3: HONEYPOT SESSION (COWRIE)]")
        report_lines.append("-" * 80)
        cowrie_path = CONFIG['TEST_COWRIE_LOG'] if self.dry_run else CONFIG['COWRIE_LOG_FILE']
        try:
            with open(cowrie_path, 'r') as f:
                for line in f:
                    if target_ip in line:
                        try:
                            data = json.loads(line)
                            ts = data.get('timestamp', '')[11:19] 
                            event_id = data.get('eventid', '')
                            if 'command.input' in event_id:
                                report_lines.append(f"{ts} | [CMD]     {data.get('input')}")
                            elif 'login.success' in event_id:
                                report_lines.append(f"{ts} | [LOGIN]   Success (User: {data.get('username')})")
                            elif 'session.file_download' in event_id:
                                url = data.get('url', 'unknown')
                                outfile = data.get('outfile', 'unknown')
                                report_lines.append(f"{ts} | [FILE]    Downloaded {url} -> {outfile}")
                                if not sandbox_data:
                                    self.trigger_sandbox(target_ip, f"Cowrie Download: {url}", "HONEYPOT_FILE", case_id)
                            elif 'session.connect' in event_id:
                                report_lines.append(f"{ts} | [CONNECT] New connection")
                        except: pass
        except: report_lines.append("No Cowrie logs found.")
        report_lines.append("\n")

        # SECTION 4: ACTIVE DEFENSE RULES
        report_lines.append("[SECTION 4: AUTOMATED DEFENSE RULES]")
        report_lines.append("-" * 80)
        try:
            if os.path.exists(RULES_FILE):
                with open(RULES_FILE, 'r') as f:
                    for line in f:
                        if target_ip in line:
                            report_lines.append(f"ACTIVE | {line.strip()}")
                        elif sandbox_data and sandbox_data.get('file_hash') in line:
                            report_lines.append(f"ACTIVE | {line.strip()}")
            else:
                report_lines.append("No active rules found.")
        except: report_lines.append("Error reading rules file.")
        
        return "\n".join(report_lines)

    def gather_forensics(self, target_ip, case_id, risk_level, sandbox_data=None):
        evidence_filename = f"case_{case_id}_evidence.txt"
        evidence_path = os.path.join(EVIDENCE_DIR, evidence_filename)
        
        report_content = self.generate_professional_report(target_ip, case_id, risk_level, sandbox_data)
        
        with open(evidence_path, "w") as f:
            f.write(report_content)
        
        sha256 = hashlib.sha256()
        with open(evidence_path, "rb") as f:
            for b in iter(lambda: f.read(4096), b""): sha256.update(b)
        file_hash = sha256.hexdigest()

        if sandbox_data:
            logger.info(f"FORENSICS: Final Report Generated & Archived for {target_ip}")
            self.add_evidence_to_case(case_id, {"filename": evidence_filename, "hash": file_hash, "type": "FINAL_REPORT"})
        else:
            logger.info(f"FORENSICS: Preliminary Report Generated for {target_ip}")

    def redirect_traffic(self, attacker_ip):
        if self.dry_run: return True
        cmd = f"sudo iptables -t nat -A PREROUTING -s {attacker_ip} -p tcp --dport 22 -j REDIRECT --to-port 2222"
        ssh_command = ["ssh", "-i", CONFIG["SSH_KEY_PATH"], "-o", "StrictHostKeyChecking=no", f"{CONFIG['VICTIM_USER']}@{CONFIG['VICTIM_IP']}", cmd]
        try: subprocess.run(ssh_command, check=True, capture_output=True); return True
        except: return False

    def locate_file_from_logs(self, community_id):
        return f"malware_sample_{community_id[-6:]}.bin" if self.dry_run else None

    def trigger_sandbox(self, src_ip, signature, community_id, case_id):
        filename = f"case_{case_id}_sample.bin"
        filepath = os.path.join(SANDBOX_IN_DIR, filename)
        with open(filepath, "w") as f: f.write(f"DUMMY MALWARE CONTENT FOR {signature}")
        self.log_event_to_kibana("SANDBOX_INITIATED", src_ip, {"filename": filename, "case_id": case_id})

    def check_sandbox_reports(self):
        for report_path in glob.glob(os.path.join(REPORTS_DIR, "*_report.json")):
            try:
                with open(report_path, "r") as f: report = json.load(f)
                filename = report.get("filename", "")
                
                case_id = None
                if filename.startswith("case_"):
                    parts = filename.split("_")
                    if len(parts) > 1: case_id = parts[1]
                
                if report.get("vt_verdict") == "MALICIOUS":
                    # 1. BLOCK THE FILE HASH
                    self.rule_manager.generate_hash_rule(report.get("file_hash"), filename)
                    
                    # 2. ESCALATION: BLOCK THE IP ADDRESS (The Fix)
                    target_ip = "192.168.1.100" # In real system, lookup CaseID->IP map
                    sid = self.rule_manager.generate_block_rule(target_ip, "Honeypot Malware Escalation")
                    
                    if sid:
                        logger.warning(f"ESCALATION: Blocking IP {target_ip} due to malware confirmation.")
                        self.log_event_to_kibana("RESPONSE_ESCALATION", target_ip, {"action": "block_ip", "reason": "malware_confirmed"})

                    # 3. GENERATE FINAL REPORT
                    if case_id:
                        self.gather_forensics(target_ip, case_id, "HIGH", sandbox_data=report)

                    self.log_event_to_kibana("RESPONSE_FEEDBACK", "N/A", {"action": "block_hash", "hash": report.get("file_hash")})

                shutil.move(report_path, os.path.join(ARCHIVE_DIR, os.path.basename(report_path)))
            except Exception as e:
                logger.error(f"Error processing report: {e}")

    def update_score(self, src_ip, points):
        current_time = time.time()
        if src_ip not in self.suspicion_scores:
            self.suspicion_scores[src_ip] = 0
            self.active_incidents[src_ip] = {'timestamp': current_time, 'triggered': False}

        if (current_time - self.active_incidents[src_ip]['timestamp']) > CONFIG['DECAY_TIME']:
             self.suspicion_scores[src_ip] = 0
             self.active_incidents[src_ip]['triggered'] = False

        self.suspicion_scores[src_ip] += points
        self.active_incidents[src_ip]['timestamp'] = current_time
        return self.suspicion_scores[src_ip]

    def process_alert(self, alert_json):
        if alert_json.get('event_type') != 'alert': return
        alert = alert_json.get('alert', {})
        src_ip = alert_json.get('src_ip')
        community_id = alert_json.get('community_id', 'unknown_id')
        signature = alert.get('signature', 'Unknown')
        severity = alert.get('severity', 3)

        points = 100 if (severity == 1 or "malware" in signature.lower()) else (2 if "scan" in signature.lower() else 1)
        new_score = self.update_score(src_ip, points)

        if new_score > 0:
            self.log_event_to_kibana("RISK_UPDATE", src_ip, {"score": new_score, "signature": signature})

        if new_score >= CONFIG['SCORE_THRESHOLD'] and not self.active_incidents[src_ip]['triggered']:
            self.active_incidents[src_ip]['triggered'] = True
            dashboard_url = f"https://192.168.100.10/kibana/app/dashboards?query=source.ip:{src_ip}"
            
            if points >= 100:
                 desc = f"Malware Detected: {signature}.\n\nView Activity: {dashboard_url}"
                 case_id = self.create_case(f"[HIGH] {src_ip}", desc, "high")
                 sid = self.rule_manager.generate_block_rule(src_ip, signature)
                 self.trigger_sandbox(src_ip, signature, community_id, case_id)
                 self.gather_forensics(src_ip, case_id, "HIGH")
                 if sid: self.log_event_to_kibana("RESPONSE_HIGH", src_ip, {"action": "block_ip", "rule_sid": sid})
            else:
                 desc = f"Suspicious Scanning: {signature}.\n\nView Activity: {dashboard_url}"
                 case_id = self.create_case(f"[MED] {src_ip}", desc, "medium")
                 self.redirect_traffic(src_ip)
                 self.gather_forensics(src_ip, case_id, "MEDIUM")
                 self.log_event_to_kibana("RESPONSE_MED", src_ip, {"action": "redirect", "case_id": case_id})

    def run(self):
        file_path = CONFIG['TEST_LOG_FILE'] if self.dry_run else CONFIG['LOG_FILE']
        if not os.path.exists(file_path): return
        print(f"Orchestrator running. JSON Output -> {OUTPUT_LOG}")
        with open(file_path, 'r') as f:
            if not self.dry_run: f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    try: self.process_alert(json.loads(line))
                    except: pass
                else: time.sleep(0.1)
                self.check_sandbox_reports()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", action="store_true")
    args = parser.parse_args()
    Orchestrator(dry_run=args.local).run()