import PySimpleGUI as sg
import os.path
import webbrowser
import logging
import socket, sys, os, time, ipaddress, sched
import signal
import pyshark
import threading

from scapy.all import *
#from threading import Thread
#from optparse import OptionParser
#from struct import *
#from time import sleep

#from detection import *
logging.basicConfig(filename='detection_log.log',level=logging.DEBUG)

#====== Please update the information below for network detection============
def get_localinfo():
    host = socket.gethostname()
    local = socket.gethostbyname(host)
    return local
    
GATEWAY = get_localinfo()
interface = "eth0"
n_range = "192.168.11.0/24"


time_now = time.strftime("%I:%M:%S")
date_now = time.strftime("%d/%m/%Y\n")
#=============================================================================


#GUI layout
def main():
	syscol=[[sg.Frame('System information',[
			[sg.T("This detection system needs a root privilege to run the detection function, if not using root, some function may malfunction.",size=(54,2))]
			],border_width=1)],
		[sg.Frame('IoT Gateway',[
			[sg.T("For IoT device management, please use Home assistant system as the IoT gateway.",size=(54,2))],
            [sg.T("If the page didn't open, please use the link : http://localhost:8123 to open the Home Assistant admin page.",size=(54,2))],
			[sg.B("Open Home assistant",size=(50,1))],
			],border_width=1)],
		[sg.Frame('Detection System',[
            [sg.T("This is the network monitor feature, for monitoring the ARP request and reply, and display when the request on the status.",size=(54,2))],
			[sg.B('Start Detection system', bind_return_key=True,size=(23,1)),sg.Button("EXIT",size=(22,1))]
			],border_width=1)],
		[sg.Frame('Packet capture',[
			[sg.T("This feature is capture the network packet for the IDS or wireshark to analysis, it will capture for 5 minutes.",size=(54,2))],
			[sg.B('Capture', bind_return_key=True,size=(23,1)),sg.B('Open Wireshark', bind_return_key=True,size=(22,1))],
			[sg.B('Suricata PCAP Analysis', bind_return_key=True,size=(23,1))],
            [sg.T("The suricata analysis will create in the application folder after the PCAP analysis.",size=(54,2))]
			],border_width=1)],		
		]
		
	stscol=[[sg.Frame('IDS system running status',[
			[sg.Output(size=(70,30), background_color='black', text_color='white')],		
			],border_width=1)]
		]
		
	layout = [
		[sg.Column(syscol),sg.VSeperator(),sg.Column(stscol),]
		]
			
	window = sg.Window('IoTDS detection system', layout)

	#======loop==========================
	while True:
		event, values = win_read(window)	
		print(event)	
		if event in (sg.WIN_CLOSED,'EXIT'):
			break
			
		elif event == 'Change to root':
			cm = 'sudo su'
			runCommand(cmd=value[cm],window=window)
			
		elif event == 'Open Home assistant':
			webbrowser.open('http://localhost:8123/',new=0)
			
		elif event == 'Start Detection system':
			print('IDS start')
			prt_networkinfo()
			Nthreading()
			Get_gatewayMac(GATEWAY)
		elif event == 'Capture':
			#print('Capturing packet for 5 minutes')
			#capture()
			cap_thread()
			print('Capture complete')
		elif event == 'Open Wireshark':
			print('Opening wireshark')
			runCommand(cmd='wireshark',window=window)
		elif event == 'Suricata PCAP Analysis':
			print('Analysis with suricata, starting suricata engine')
			suricata_thread()
			print('The result will place in the application directory after analysis')
	window.close()
	
def win_read(window):
	return window.read()

def runCommand(cmd, timeout=0, window=None):
	nop = None
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	output = ''
	for line in p.stdout:
		line = line.decode(errors='replace' if (sys.version_info) < (3, 5) else 'backslashreplace').rstrip()
		output += line
		print(line)
		window.refresh() if window else nop 
	retval = p.wait(timeout)
	return (retval, output)

#============function threading==========
	
def Nthreading():
    arpscan = threading.Thread(target=arp_scanning,daemon=True)
    arpscan.start()
    print("Starting network range scanning, it takes 10 second....")
    time.sleep(10)
    print('starting sniff & monitor the interface %s' % interface)
    sniffarp = threading.Thread(target=sniff_networkarp,daemon=True)
    #mon = threading.Thread(target=Nmonitor,daemon=True)
    sniffarp.start()
    #mon.start()
    
def suricata_thread():
    analysis = threading.Thread(target=suricata_pcap,daemon=True)
    analysis.start()

def suricata_pcap():
    runCommand(cmd='suricata -c /etc/suricata/suricata.yaml -r Capture.pcap -s /etc/suricata/rules')

def cap_thread():
    cap = threading.Thread(target=capturepcap,daemon=True)
    #time.sleep(300)
    #print('capture complete')
    cap.start()

#============IDS function=======================

#Print startup message
def prt_networkinfo():
    print("Network detection system start: ")
    time.sleep(2)
    print("* Gateway is %s" % GATEWAY)
    time.sleep(2)
    print("** Interface configured : %s" % interface)
    time.sleep(2)
    print("*** Network Range set: %s" % n_range)
    time.sleep(2)
    logging.info('Logging start @ date:%s' % date_now + ' & time:%s' % time_now)
    logging.info('Gateway IP: %s' % GATEWAY)
    logging.info('Interface: %s' % interface)
    logging.info('Network range to defend: %s' % n_range)

#current ip in use detection
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

#get mac
def Get_gatewayMac(ip_address):
    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
      timeout=2, retry=2)
    for s, r in response:
        return r[Ether].src
    return None
    logging.info('Gateway Layer 2 address is: %s' % r[Ether].src)
    global GATEWAYMAC 
    GATEWAYMAC = "%s" % r[Ether].src

#ARP info print
def arp_display(packet):
    if packet[ARP].op == 1: 
        logging.info('[*] ARP request - %s is asking for L2 of %s' % (packet[ARP].psrc, packet[ARP].pdst))
        return '[*] ARP request- %s is asking for L2 of %s' % (packet[ARP].psrc, packet[ARP].pdst)

    if packet[ARP].op == 2: 
        logging.info('[*] ARP reply - %s L3 address is %s' % (packet[ARP].hwsrc, packet[ARP].psrc))
        return '[*] ARP reply - %s L3 address is %s' % (packet[ARP].hwsrc, packet[ARP].psrc)

# network monitor
def Nmonitor():
    monitor = pyshark.LiveCapture(interface='%s' % interface)
    pkt = monitor.sniff_continuously
    for packet in pkt(packet_count=10):
        print ('Continuous Traffic detected: ')

def Nmonitor2():
    monitor = pyshark.LiveCapture(interface='%s' % interface)
    #monitor.sniff(timeout=60)
    pkt = monitor.sniff_continuously
    for packet in monitor.sniff_continuously(packet_count=10):
        print ('Continuous Traffic detected: ')

def Nmon():
    sttime = time.time()
    cap1 = pyshark.LiveCapture(interface='%s' % interface)
    for concap in cap1.sniff_continuously():
    	if timeout and time.time() - start > timeout:
    	    break
    	yield item
        
#packet capture
def capturepcap():
    pkt = sniff(timeout=300)
    print('wait for capture 300s')
    wrpcap('Capture.pcap',pkt)

    time.sleep(300)
    print('Capture complete')

def pcap_capture():
    fl = "arp and dst %s" % GATEWAY
    sniff(filter = fl , prn = arp_display)

def sniff_networkarp():
    f = "arp and dst %s" % GATEWAY
    sniff(filter = f , prn = arp_display)

    
#if __main__ == '__main__':
main()
