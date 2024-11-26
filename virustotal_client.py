import requests
import time
from typing import Optional, Dict


class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

    def scan_file(self, file_path: str) -> Optional[Dict]:
        """Upload and scan a file with VirusTotal."""
        try:
            # Get file size
            with open(file_path, "rb") as f:
                files = {"file": f}
                response = requests.post(
                    f"{self.base_url}/files",
                    headers=self.headers,
                    files=files
                )
                response.raise_for_status()
                analysis_id = response.json()["data"]["id"]

                # Wait for analysis to complete (with timeout)
                timeout = 60  # seconds
                start_time = time.time()
                while True:
                    if time.time() - start_time > timeout:
                        print("Analysis timeout reached")
                        return None

                    result = self.get_analysis_results(analysis_id)
                    if result and result["status"] == "completed":
                        return self.scan_hash(result["hash-md5"])

                    time.sleep(5)  # Wait before checking again

        except Exception as e:
            print(f"Error scanning file with VirusTotal: {e}")
            return None

    def scan_hash(self, file_hash: str) -> Optional[Dict]:
        """Query VirusTotal for existing file hash analysis."""
        try:
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self.headers
            )

            if response.status_code == 200:
                data = response.json()

                return {
                    "status": "completed",
                    "stats": data["data"]["attributes"]["last_analysis_stats"],
                    "results": data["data"]["attributes"]["last_analysis_results"] if "last_analysis_results" in data["data"]["attributes"] else None,
                    "hash-md5": data["data"]["attributes"]["md5"],
                    "full_data": data["data"],
                }
            elif response.status_code == 404:
                return None
            else:
                response.raise_for_status()

        except Exception as e:
            print(f"Error querying VirusTotal: {e}")
            return None

    def get_analysis_results(self, analysis_id: str) -> Optional[Dict]:
        """Get analysis results for a submitted file."""
        try:
            response = requests.get(
                f"{self.base_url}/analyses/{analysis_id}",
                headers=self.headers
            )
            response.raise_for_status()
            data = response.json()
            result_analysis = data["data"]["attributes"]
            return {
                "status": result_analysis["status"],
                "stats": result_analysis["stats"],
                "results": result_analysis["results"] if "results" in result_analysis else None,
                "hash-md5": data["meta"]["file_info"]["md5"],
                "full_data": data["data"],
                "file_metadata": data["meta"]
            }
        except Exception as e:
            print(f"Error getting analysis results: {e}")
            return None
