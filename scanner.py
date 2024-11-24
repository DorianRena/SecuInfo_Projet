import os
import hashlib
import re
from datetime import datetime

from virustotal_client import VirusTotalClient
from database import Database
from logger import AntivirusLogger
from typing import List, Optional, Dict

from dotenv import load_dotenv
load_dotenv()

class SimpleAntivirus:
    def __init__(self):
        self.db = Database()
        self.logger = AntivirusLogger()

        self.vt_client = VirusTotalClient(os.getenv("API_KEY_VIRUS"))
        print("Clé API :", os.getenv("API_KEY_VIRUS"))

    def calculate_file_hash(self, filepath: str) -> Optional[str]:
        """Calculate MD5 hash of a file."""
        hash_md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.logger.log_error(f"Error calculating hash for {filepath}", e)
            return None

    def check_virustotal(self, filepath: str, file_hash: str) -> Optional[Dict]:
         """Check file against VirusTotal database."""
         if not self.vt_client:
             return None

         self.logger.log_info(f"Checking VirusTotal database for {filepath}")

         # First try to query existing hash
         results = self.vt_client.scan_hash(file_hash)

         # If hash not found, submit the file for scanning
         if not results:
             self.logger.log_info(f"File not found in VirusTotal database. Submitting {filepath} for analysis...")
             return self.vt_client.scan_file(filepath)

         return results

    def check_signatures(self, filepath: str) -> Optional[dict]:
        """Check if file matches known malware signatures."""
        file_hash = self.calculate_file_hash(filepath)
        if file_hash:
            # Check local database
            local_match = self.db.get_signature(file_hash)
            if local_match:
                self.logger.log_threat_detected(filepath, "Local signature match", local_match)
                return {"source": "local", "match": local_match}

            # Check VirusTotal
            vt_results = self.check_virustotal(filepath, file_hash)
            if vt_results:
                self.logger.log_threat_detected(filepath, "VirusTotal detection", vt_results)
                return {"source": "virustotal", "match": vt_results}
        return None

    def check_patterns(self, filepath: str) -> List[str]:
        """Check file for suspicious patterns."""
        suspicious_matches = []
        suspicious_patterns = self.db.get_suspicious_patterns()

        try:
            with open(filepath, 'r') as f:
                content = f.read()
                for pattern in suspicious_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        match_info = f"Suspicious pattern found: {pattern}"
                        suspicious_matches.append(match_info)
                        self.logger.log_threat_detected(filepath, "Suspicious pattern", {"pattern": pattern})
        except Exception as e:
            self.logger.log_error(f"Error checking patterns in {filepath}", e)
        return suspicious_matches

    def display_virustotal_results(self, results: Dict):
        """Display VirusTotal scan results."""
        total_detections = sum(1 for engine in results.values() if engine["category"] == "malicious")
        total_engines = len(results)

        print(f"\nVirusTotal Results:")
        print(f"Detections: {total_detections}/{total_engines}")

        if total_detections > 0:
            print("\nDetections by antivirus engines:")
            for engine, result in results.items():
                if result["category"] == "malicious":
                    detection_info = f"{engine}: {result['result']}"
                    print(f"  - {detection_info}")
                    self.logger.log_info(f"VirusTotal detection: {detection_info}")

    def scan_file(self, filepath: str) -> None:
        """Scan a single file."""
        self.logger.log_scan_start(filepath)
        print(f"\nScanning: {filepath}")

        if not os.path.exists(filepath):
            self.logger.log_error(f"File not found: {filepath}")
            print("File not found!")
            return

        # Check file size
        size = os.path.getsize(filepath)
        self.logger.log_info(f"File size: {size} bytes")
        print(f"File size: {size} bytes")

        # Check signatures
        signature_match = self.check_signatures(filepath)
        if signature_match:
            if signature_match["source"] == "local":
                match = signature_match["match"]
                threat_info = {
                    "name": match['name'],
                    "description": match['description'],
                    "severity": match['severity']
                }
                self.logger.log_threat_detected(filepath, "Local database match", threat_info)
                print(f"⚠️ MALWARE DETECTED (Local Database):")
                print(f"  Name: {match['name']}")
                print(f"  Description: {match['description']}")
                print(f"  Severity: {match['severity'].upper()}")
            elif signature_match["source"] == "virustotal":
                match = signature_match["match"]
                self.display_virustotal_results(match["results"])

                total_detections = sum(1 for engine in match["results"].values() if engine["category"] == "malicious")

                if total_detections > 0:
                    self.logger.log_threat_detected(filepath, "VirusTotal detection", match["results"])

                    print("⚠️ MALWARE DETECTED (VirusTotal)")

                    self.db.add_signature(
                        match["hash-md5"],
                        filepath,
                        "Virus Total analysis",
                        "high"
                    )
        else:
            # Check patterns
            suspicious = self.check_patterns(filepath)
            if suspicious:
                print("⚠️ Suspicious patterns found:")
                for pattern in suspicious:
                    print(f"  - {pattern}")
            else:
                self.logger.log_info(f"No threats detected in {filepath}")
                print("✅ No threats detected")

        self.logger.log_scan_complete(filepath)

    def scan_directory(self, directory: str) -> None:
        """Scan all files in a directory."""
        self.logger.log_scan_start(directory)
        print(f"\nStarting scan of directory: {directory}")
        start_time = datetime.now()
        print(f"Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    self.scan_file(filepath)
        except Exception as e:
            self.logger.log_error(f"Error scanning directory {directory}", e)

        end_time = datetime.now()
        duration = end_time - start_time
        self.logger.log_info(f"Directory scan completed. Duration: {duration}")
        print(f"\nScan completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total scan duration: {duration}")
