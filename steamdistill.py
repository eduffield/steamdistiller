#!/usr/bin/env
import pyshark
import requests
import html5lib
from bs4 import BeautifulSoup

class Output:
    def __init__(self):
        self.items = []
        print("%-18s %-22s %-24s %-12s" % ("IP", "Hostname", "Username", "Link"))

    def put(self, ip=None, name=None, userid=None):
        if not userid in self.items:
            self.items.append(userid)
            username, link = checkweb(userid)
            print("%-18s %-22s %-24s %-12s" % ("[" + ip + "]", name, username, link))

def checkweb(userid):
    weburl = "https://steamcommunity.com/profiles/" + str(userid)
    link = "\x1b]8;;" + weburl +"\aView Profile\x1b]8;;\a"

    page = requests.get(weburl)
    soup = BeautifulSoup(page.content, "html5lib")
    username = soup.find("span", attrs = {"class": "actual_persona_name"}).text

    return username, link

def works():
    out = Output()
    cap = pyshark.LiveCapture(interface='wlp3s0')
    for packet in cap.sniff_continuously():
        if hasattr(packet, "steam_ihs_discovery"):
            usrip = packet.ip.src

            if hasattr(packet.steam_ihs_discovery, "body_status_hostname"):
                usrname = packet.steam_ihs_discovery.body_status_hostname
            if hasattr(packet.steam_ihs_discovery, "body_status_user_steamid"):
                usrid = packet.steam_ihs_discovery.body_status_user_steamid
            out.put(usrip, usrname, usrid)

def readpack():
    cap = pyshark.FileCapture('/home/user1/Downloads/ths.pcapng')
    pak = cap[2832]

    usrip = pak.ip.src
    usrname = pak.steam_ihs_discovery.body_status_hostname
    usrid = pak.steam_ihs_discovery.body_status_user_steamid

    out = Output()
    out.put(usrip, usrname, usrid)

if __name__ == "__main__":
    print("Steam Distiller v0.3 -- Steam In-Home Discovery Packet Sniffer")
    print("Copyright 2022-2023 Evan Duffield")
    print("Usage:   sudo python3 steamdistill.py\n")
    works()