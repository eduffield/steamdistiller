#!/usr/bin/env
try:
    import pyshark
    from pyshark.tshark import tshark
    import requests
    import html5lib
    from bs4 import BeautifulSoup
    from datetime import datetime
    import argparse
except ImportError:
    print("Error: You have missing dependencies!")
    exit(1)

class Output:
    def __init__(self, writetofile=False):
        self.items = []
        self.writetofile = writetofile
        if self.writetofile == True:
            self.log = open("log.txt", "a")
            startdate = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
            self.log.write(startdate)
            self.log.write("\n%-18s %-22s %-24s %-12s\n" % ("IP", "Hostname", "Username", "Link"))
        print("\n%-18s %-22s %-24s %-12s" % ("IP", "Hostname", "Username", "Link"))

    def put(self, ip=None, name=None, userid=None):
        if not userid in self.items:
            self.items.append(userid)
            username, link, nohypertextlink = checkweb(userid)
            if self.writetofile == True:
                self.log.write(("%-18s %-22s %-24s %-12s\n" % ("[" + ip + "]", name, username, nohypertextlink)))
            print("%-18s %-22s %-24s %-12s" % ("[" + ip + "]", name, username, link))

    def closefile(self):
        self.log.write("\n\n")
        self.log.close()

def getinterface():
    all_interfaces = tshark.get_all_tshark_interfaces_names()
    numberofinterfaces = len(all_interfaces)
    valid = False
    while not valid:
        print("Choose an interface to read:")
        for i in range(1, numberofinterfaces+1):
            print(f"{i}. {all_interfaces[i-1]}")
        print(f"Choice (1-{numberofinterfaces}): ", end="")
        usrinput = input()
        try:
            choiceint = int(usrinput)
            if choiceint > 0 and choiceint < numberofinterfaces + 1:
                    choice = all_interfaces[choiceint-1]
                    valid = True
            else:
                print("Invalid input. Was you choice an integer in range?")
        except:
            print("Invalid input. Was you choice an integer in range?")
    return choice


def checkweb(userid):
    weburl = "https://steamcommunity.com/profiles/" + str(userid)
    link = "\x1b]8;;" + weburl +"\aView Profile\x1b]8;;\a"

    page = requests.get(weburl)
    soup = BeautifulSoup(page.content, "html5lib")
    username = soup.find("span", attrs = {"class": "actual_persona_name"}).text

    return username, link, weburl

if __name__ == "__main__":
    args = argparse.ArgumentParser(description="Steam Distiller v0.4 -- Steam In-Home Discovery Packet Sniffer by Evan Duffield")
    args.add_argument("-w", dest="log", action="store_const", const=True, help="Writes results a file named log.txt")
    logactive = False
    logactive = args.parse_args().log
    
    print("Steam Distiller v0.4 -- Steam In-Home Discovery Packet Sniffer")
    print("Copyright 2022-2023 Evan Duffield")
    print("usage: steamdistill.py [-h] [-w]\n")

    sniff_interface = getinterface()
    out = Output(logactive)

    try:
        cap = pyshark.LiveCapture(interface=sniff_interface)
        #cap = pyshark.LiveCapture(interface='wlo1')
        for packet in cap.sniff_continuously():
            if hasattr(packet, "steam_ihs_discovery"):
                usrip = packet.ip.src

                if hasattr(packet.steam_ihs_discovery, "body_status_hostname"):
                    usrname = packet.steam_ihs_discovery.body_status_hostname
                if hasattr(packet.steam_ihs_discovery, "body_status_user_steamid"):
                    usrid = packet.steam_ihs_discovery.body_status_user_steamid
                out.put(usrip, usrname, usrid)
    except KeyboardInterrupt or EOFError:
        if logactive == True:
            out.closefile()
        exit(0)