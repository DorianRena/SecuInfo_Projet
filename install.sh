#!/bin/sh
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install libnotify-bin notify-osd exiftool -y
sudo apt-get install python3 python3-pip python3-tk python3-dotenv python3-watchdog python3-requests -y

# Backup current crontab to a file
crontab -l > mycron 2>/dev/null || true

# Define the cron job
CRON_JOB="@reboot XDG_RUNTIME_DIR=/run/user/$(id -u) python3 $(pwd)/main_analyse.py &"

# Check if the cron job already exists
if ! grep -Fq "$CRON_JOB" mycron; then
  echo "$CRON_JOB" >> mycron
  crontab mycron
  echo "Cron job added: $CRON_JOB"
  nohup python3 "$(pwd)/main_analyse.py" > main_analyse.log 2>&1 &
else
  echo "Cron job already exists, skipping..."
fi

# Clean up
rm -f mycron

# Check if .env exists
if [ ! -f .env ]; then
  echo ".env file not found. You can get your VirusTotal API key here : https://www.virustotal.com/gui/my-apikey"
  echo "Please enter your VirusTotal API key:"
  read -r VT_API_KEY
  echo "VT_API_KEY=$VT_API_KEY" > .env
  echo ".env file created with your VirusTotal API key."
else
  echo ".env file already exists, skipping..."
fi