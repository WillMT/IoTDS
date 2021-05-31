import PySimpleGUI as sg
import os.path
import webbrowser
import logging
import socket, sys, os, time, ipaddress, sched
import signal
import pyshark
import threading

from scapy.all import *

def get_localinfo():
    host = socket.gethostname()
    local = socket.gethostbyname(host)
    return local
    
GATEWAY = get_localinfo()
interface = "eth0"
n_range = "192.168.1.0/24"

def arp_scanning(iprange="%s" % n_range):
    p = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=iprange)
    re,nore = srp(p,iface=interface,timeout=2)
    result=[]
    print("scanning %d machine" %len(re))
    for s,r in re:
        result.append([r[ARP].psrc,r[ARP].hwsrc])
    result.sort()
    for ip,mac in result:
        print(ip,">>",mac)

                  
arp_scanning()
