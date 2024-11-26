import os
import hashlib
import re
import shutil
import stat
import subprocess
from datetime import datetime

from virustotal_client import VirusTotalClient
from database import Database
from logger import AntivirusLogger, send_notification, replace_notification
from typing import List, Optional, Dict

from dotenv import load_dotenv
load_dotenv()

class SimpleAntivirus:
    def __init__(self, result_dir: str = "results"):
        self.db = Database()
        self.logger = AntivirusLogger()

        if not os.getenv("API_KEY_VIRUS"):
            self.logger.log_error("VirusTotal API key not found. VirusTotal checks will be disabled.")

        self.vt_client = VirusTotalClient(os.getenv("API_KEY_VIRUS"))

        self.quarantine_dir = os.path.expanduser("~/Quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)

        self.result_dir = result_dir
        os.makedirs(self.result_dir, exist_ok=True)

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
         else:
             self.logger.log_info(f"File found in VirusTotal database.")

         return results

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

        # local check
        file_hash = self.calculate_file_hash(filepath)
        if not file_hash:
            return

        local_match_signature = self.db.get_signature(file_hash)
        if local_match_signature:
            self.logger.log_threat_detected(filepath, "Local signature match", local_match_signature)
            print(f"MALWARE DETECTED (Local Database):")
            print(f"  Name: {local_match_signature['name']}")
            print(f"  Severity: {local_match_signature['severity'].upper()}")

            self.move_to_quarantine(filepath)
            send_notification("Threat Detected", f"Threat detected in file: {filepath}")
            return

        is_in_quarantine = False
        original_permissions = os.stat(filepath).st_mode
        quarantine_path = None

        last_notify_id = None

        # author
        author = self.get_author(filepath)
        if author:
            local_match_author = self.db.get_signature_by_author(author)
            if local_match_author:
                quarantine_path = self.move_to_quarantine(filepath)
                is_in_quarantine = True
                print(f"MALWARE SUSPECTED (Local Database):")
                print(f"  Name: {local_match_author['name']}")
                last_notify_id = int(send_notification("Suspicious File Detected", f"Suspicious file detected: {filepath}"))

        # pattern
        suspicious = self.check_patterns(filepath)
        if suspicious:
            print("Suspicious patterns found:")
            for pattern in suspicious:
                print(f"  - {pattern}")

            if not is_in_quarantine:
                quarantine_path = self.move_to_quarantine(filepath)
                is_in_quarantine = True

            last_notify_id = int(send_notification("Suspicious File Detected", f"Suspicious file detected: {filepath}"))

        if is_in_quarantine:
            vt_results = self.check_virustotal(quarantine_path, file_hash)
        else:
            vt_results = self.check_virustotal(filepath, file_hash)

        if vt_results:
            self.save_virustotal_results(vt_results, filepath)

            total_detections = vt_results["stats"]["malicious"] + vt_results["stats"]["suspicious"]

            # Gestion en fonction du résultat de l'analyse
            if total_detections == 0:
                self.logger.log_info("No threats detected.")

                if is_in_quarantine:
                    self.move_to_origine(quarantine_path, filepath, original_permissions)
                    replace_notification("File Clean", f"File clean: {filepath}", str(last_notify_id))
                    print("No threats detected. File restored.")
                else:
                    send_notification("File Clean", f"File clean: {filepath}")
                    print("No threats detected.")

            else:
                # Déplacer en quarantaine si le fichier est dangereux ou suspect
                if not is_in_quarantine:
                    self.move_to_quarantine(filepath)

                self.db.add_signature(
                    vt_results["hash-md5"],
                    filepath,
                    author if author else "Unknown",
                    "high"
                )

                self.logger.log_threat_detected(filepath, "VirusTotal detection", vt_results)
                self.display_virustotal_results(vt_results["results"])

                if last_notify_id:
                    replace_notification("Threat Detected", f"Threat detected in file: {filepath}", str(last_notify_id))
                else:
                    send_notification("Threat Detected", f"Threat detected in file: {filepath}")

        if not vt_results and is_in_quarantine:
            self.move_to_origine(quarantine_path, filepath, original_permissions)
            replace_notification("File Clean", f"File clean: {filepath}", str(last_notify_id))

        print(f"Scan complete for: {filepath}")
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

    def move_to_quarantine(self, file_path):
        """ Fonction pour déplacer le fichier en quarantaine """
        quarantine_path = os.path.join(self.quarantine_dir, os.path.basename(file_path))
        shutil.move(file_path, quarantine_path)
        os.chmod(quarantine_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
        self.logger.log_info(f"File moved to quarantine: {quarantine_path}")
        return quarantine_path

    def move_to_origine(self, file_path, original_file_path, original_permissions):
        """ Fonction pour déplacer le fichier vers son répertoire d'origine """
        shutil.move(file_path, original_file_path)
        os.chmod(original_file_path, original_permissions)
        self.logger.log_info(f"File moved back to original location: {original_file_path}")

    def get_author(self, file_path):
        """ Fonction pour récupérer les métadonnées du fichier avec exiftool """
        try:
            result = subprocess.run(['exiftool', file_path], capture_output=True, text=True)
            metadata = result.stdout
            author = None
            for line in metadata.splitlines():
                if "Creator" in line or "Author" in line:
                    author = line.split(":")[1].strip()
            return author
        except Exception as e:
            return None

    def save_virustotal_results(self, vt_result, filepath: str):
        """ Fonction pour enregistrer les résultats de l'analyse VirusTotal """
        filename = os.path.basename(filepath)

        with open(os.path.join(self.result_dir, f"vt_{filename}.json"), "w") as f:
            f.write(str(vt_result))
