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
else
  echo "Cron job already exists, skipping..."
fi

# Clean up
rm -f mycron

echo "Installation terminée"
python3 main_analyse.py
