﻿import logging
import subprocess
from datetime import datetime
import os
from typing import Optional


def send_notification(title: str, message: str):
    try:
        return subprocess.run(["notify-send", "-p", title, message], capture_output=True, text=True).stdout
    except Exception as e:
        print(f"Error sending notification: {str(e)}")
        return None

def replace_notification(title: str, message: str, id_notif: str):
    try:
        subprocess.run(["notify-send", "-r", id_notif, title, message])
    except Exception as e:
        print(f"Error sending notification: {str(e)}")

class AntivirusLogger:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        self._setup_logging()

    def _setup_logging(self):
        """Set up logging configuration."""
        # Create logs directory if it doesn't exist
        os.makedirs(self.log_dir, exist_ok=True)

        # Set up file handler for detailed logs
        log_file = os.path.join(self.log_dir, f"antivirus_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

        self.logger = logging.getLogger("antivirus")
        self.logger.info("Logging initialized")
        self.remove_old_logs(10)

    def remove_old_logs(self, max_logs: int = 5):
        """Remove old log files to keep log directory clean."""
        log_files = sorted([f for f in os.listdir(self.log_dir) if f.endswith(".log")], reverse=True)
        for log_file in log_files[max_logs:]:
            os.remove(os.path.join(self.log_dir, log_file))

    def log_scan_start(self, path: str):
        """Log the start of a scan operation."""
        self.logger.info(f"Starting scan of: {path}")

    def log_scan_complete(self, path: str):
        """Log the completion of a scan operation."""
        self.logger.info(f"Completed scan of: {path}")

    def log_threat_detected(self, path: str, threat_type: str, details: Optional[dict] = None):
        """Log detected threats."""
        self.logger.warning(f"Threat detected in {path}")
        self.logger.warning(f"Threat type: {threat_type}")
        if details:
            self.logger.warning(f"Details: {details}")

    def log_error(self, message: str, error: Optional[Exception] = None):
        """Log errors."""
        if error:
            self.logger.error(f"{message}: {str(error)}")
        else:
            self.logger.error(message)

    def log_info(self, message: str):
        """Log general information."""
        self.logger.info(message)