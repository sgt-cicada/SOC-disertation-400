import os
import time
import hashlib
import logging
import json
import requests
from datetime import datetime

# --- CONFIGURATION ---
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with real key or keep specific string for simulation

# FIX: Dynamic path to ensure it matches Orchestrator's location
# Go up one level from 'src' to find the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCH_DIR = os.path.join(BASE_DIR, "sandbox_in")
REPORT_DIR = os.path.join(BASE_DIR, "sandbox_reports")

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("VirusTotal-Scanner")

def calculate_hash(filepath):
    """Generates SHA256 hash for lookup."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def query_virustotal(file_hash):
    """Queries VT API v3 for the file hash."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            total = sum(stats.values())
            return {
                "status": "found",
                "score": f"{malicious}/{total}",
                "verdict": "MALICIOUS" if malicious > 0 else "CLEAN"
            }
        elif response.status_code == 404:
            return {"status": "not_found", "score": "0/0", "verdict": "UNKNOWN"}
        else:
            return {"status": "error", "score": "N/A", "verdict": "API_ERROR"}
            
    except Exception as e:
        return {"status": "error", "score": "N/A", "verdict": str(e)}

def process_file(filepath):
    filename = os.path.basename(filepath)
    logger.info(f"Processing: {filename}")
    
    # 1. Get Hash
    file_hash = calculate_hash(filepath)
    logger.info(f"SHA256: {file_hash}")
    
    # 2. Query VT
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        # Simulation Mode
        logger.warning("No API Key configured. Simulating malicious response.")
        vt_result = {"status": "simulated", "score": "45/70", "verdict": "MALICIOUS"}
        time.sleep(2)
    else:
        vt_result = query_virustotal(file_hash)
    
    # 3. Generate Structured Report
    report = {
        "timestamp": datetime.now().isoformat(),
        "filename": filename,
        "file_hash": file_hash,
        "vt_verdict": vt_result['verdict'],
        "vt_score": vt_result['score'],
        "scan_status": "complete"
    }
    
    # 4. Save Report
    report_path = os.path.join(REPORT_DIR, f"{filename}_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)
        
    logger.info(f"Report Generated: {report_path}")

def main():
    if not os.path.exists(WATCH_DIR): os.makedirs(WATCH_DIR)
    if not os.path.exists(REPORT_DIR): os.makedirs(REPORT_DIR)
    
    # DEBUG PRINT: Verify this matches your folder structure on startup
    print(f"DEBUG: Watching Absolute Path: {WATCH_DIR}")
    
    logger.info("VirusTotal Scanner watching for files...")
    
    while True:
        try:
            for filename in os.listdir(WATCH_DIR):
                filepath = os.path.join(WATCH_DIR, filename)
                
                if os.path.isfile(filepath) and not filename.startswith("."):
                    time.sleep(1) # Wait for write to finish
                    process_file(filepath)
                    try:
                        os.remove(filepath)
                    except:
                        pass
        except Exception as e:
            logger.error(f"Loop Error: {e}")
            
        time.sleep(2)

if __name__ == "__main__":
    main()