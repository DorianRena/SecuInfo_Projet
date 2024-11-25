#!/bin/sh
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install python3 python3-pip python3-tk python3-dotenv python3-watchdog python3-requests -y
crontab -l > mycron
echo "@reboot XDG_RUNTIME_DIR=/run/user/$(id -u) python3 $(pwd)/main_analyse.py &" >> mycron
crontab mycron
rm mycron
echo "Installation terminée"
python3 main_analyse.py
# This script installs the necessary packages for the program to run, and adds a cron job to run the program at startup.