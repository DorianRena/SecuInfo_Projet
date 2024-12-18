#!/bin/sh
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install libnotify-bin notify-osd exiftool -y
sudo apt-get install python3 python3-pip python3-tk python3-dotenv python3-watchdog python3-requests -y

# Check if .env exists
if [ ! -f .env ]; then
  echo ".env file not found. You can get your VirusTotal API key here : https://www.virustotal.com/gui/my-apikey"
  echo "Please enter your VirusTotal API key:"
  read -r API_KEY_VIRUS
  echo "API_KEY_VIRUS=$API_KEY_VIRUS" > .env
  echo ".env file created with your VirusTotal API key."
else
  echo ".env file already exists, skipping..."
fi

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

# setup application
sudo cp pta_icon.png /usr/share/icons/
cp Analyse.sh "/home/$(whoami)/"
echo "python3 $(pwd)/main_ui.py" > "/home/$(whoami)/Analyse.sh"
chmod +x "/home/$(whoami)/Analyse.sh"
echo "[Desktop Entry]
Type=Application
Name=Petrificus Totalus
Exec=/home/$(whoami)/Analyse.sh
Terminal=true
Icon=/usr/share/icons/pta_icon.png
Comment=Lancer le script main_analyse.py avec l'environnement virtuel
Categories=Development;
" > PetrificusTotalus.desktop
sudo mv PetrificusTotalus.desktop /usr/share/applications/PetrificusTotalus.desktop
