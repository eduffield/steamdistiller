# SteamDistiller
Python script for sniffing Steam IHS Discovery Packets.
The script must be launched with root, be sure to install any dependencies with superuser.

## System Requirements
This script uses python3, wireshark, and tshark. The following command can install each on a Debian-based system.
```
sudo apt-get install python3 wireshark tshark
```
On a Red Hat/Fedora-based system, these can be installed with
```
sudo dnf install python3 wireshark wireshark-cli
```

## Python Requirements
This script uses the python libraries pyshark, html5lib, and BeautifulSoup4. The following command can install each on a linux system.
```
sudo pip install pyshark html5lib bs4
```
## Usage
```
sudo python3 steamdistill.py [-h] [-w]
```
options:
-h          shows the help message and exits,
-w          writes results a file named log.txt
## Screenshots
![Example](https://eduffield.github.io/images/screen2.png)
