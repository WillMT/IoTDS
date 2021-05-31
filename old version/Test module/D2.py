import PySimpleGUI as sg
import os.path
import webbrowser
import logging
import socket, sys, os, time, ipaddress, sched
import signal
import pyshark
import threading

from scapy.all import *

def Nmonitor():
    monitor = pyshark.LiveCapture(interface='eth0')
    #monitor.sniff(timeout=60)
    sniff =  monitor.sniff_continuously()
    for i in sniff:
        try:
            for IP in sniff:
                ip_src=sniff[IP].src
                ip_dst=sniff[IP].dst
                if sniff[IP].src[i] == sniff[IP].src[i+1]:
                    print('same packet detect')
                    return 

                  
Nmonitor()
