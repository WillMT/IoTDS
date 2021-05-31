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
n_range = "192.168.1.0/24"


time_now = time.strftime("%I:%M:%S")
date_now = time.strftime("%d/%m/%Y\n")
#=============================================================================



def main():
	syscol=[[sg.Frame('System information',[
			[sg.T("This detection system needs a root privilege to run the detection function.",size=(54,2))],[
			sg.B("Change to root.",size=(50,1))],
			],border_width=1)],
		[sg.Frame('IoT Gateway',[
			[sg.T("For IoT device management, please use Home assistant system as the IoT gateway.",size=(54,4))],
			[sg.B("Open Home assistant",size=(50,1))],
			],border_width=1)],
		[sg.Frame('Detection System',[
			[sg.B('Start Detection system', bind_return_key=True,size=(22,1)),sg.Button("EXIT",size=(22,1))]
			],border_width=1)]	
		]
	stscol=[[sg.Frame('IDS system running status',[
			[sg.Output(size=(70,30), background_color='black', text_color='white')],		
			],border_width=1)]
		]
	layout = [
		[sg.Column(syscol),sg.VSeperator(),sg.Column(stscol),]
		]	
	window = sg.Window('Simple detection system', layout)

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
		window.refresh() if window else nop        # yes, a 1-line if, so shoot me

	retval = p.wait(timeout)
	return (retval, output)
	
def Nthreading():
    arpscan = threading.Thread(target=arp_Nrange,daemon=True)
    arpscan.start()
    print("Starting network range scanning, it takes 10 second....")
    time.sleep(10)
    print('starting sniff & monitor the interface %s' % interface)
    sniffarp = threading.Thread(target=sniff_networkarp,daemon=True)
    mon = threading.Thread(target=Nmonitor,daemon=True)
    sniffarp.start()
    mon.start()
    


#============IDS function
#============Print startup message=============
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

def arp_Nrange(iprange="%s" % n_range):

    logging.info('Sending ARP packet to network range %s' % n_range)
    reply, noreply = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=iprange), timeout=5)
    collection = []

    for snd, rcv in reply:
        result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
        logging.info('%s' % result)
        collection.append(result)
	    
    #for elem in collection:
        #print(elem)


def Get_gatewayMac(ip_address):

    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
      timeout=2, retry=2)
    for s, r in response:
        return r[Ether].src
    return None

    logging.info('Gateway Layer 2 address is: %s' % r[Ether].src)
    global GATEWAYMAC 
    GATEWAYMAC = "%s" % r[Ether].src

def arp_display(packet):
    if packet[ARP].op == 1: 
        logging.info('[*] ARP request - %s is asking for L2 of %s' % (packet[ARP].psrc, packet[ARP].pdst))
        #return '[*] ARP request- %s is asking for L2 of %s' % (packet[ARP].psrc, packet[ARP].pdst)

    if packet[ARP].op == 2: 
        logging.info('[*] ARP reply - %s L3 address is %s' % (packet[ARP].hwsrc, packet[ARP].psrc))
        #return '[*] ARP reply - %s L3 address is %s' % (packet[ARP].hwsrc, packet[ARP].psrc)


def defenseive_arps(GATEWAY, GATEWAYMAC):

    un_poison_victim = ARP()
    un_poison_victim.op = 2
    un_poison_victim.psrc = gateway
    un_poison_victim.pdst = victim_L3
    un_poison_victim.hwdst = GATEWAYMAC

    un_poison_gateway = ARP()
    un_poison_gateway.op = 2
    un_poison_gateway.psrc = victim_L3
    un_poison_gateway.pdst = gateway
    un_poison_gateway.hwdst = victim_MAC

    send(un_poison_victim)
    send(un_poison_gateway)
    time.sleep(2)

def Nmonitor():
    #Check continuous packet detect within 60s
    monitor = pyshark.LiveCapture(interface='%s' % interface)
    #monitor.sniff(timeout=60)
    monitor.sniff(timeout=600)
    count=0
    for packet in monitor.sniff_continuously(packet_count=10):
        print ('Continuous Traffic detected: ')
        count=count+1
        print(count)
        monitor.clear()
        #print(packet.count)
        #print (packet)	
	
def Nmon():
    sttime = time.time()
    cap1 = pyshark.LiveCapture(interface='%s' % interface)
    for concap in cap1.sniff_continuously():
    	if timeout and time.time() - start > timeout:
    	    break
    	yield item
    	
    

def sniff_networkarp():
    f = "arp and dst %s" % GATEWAY
    #print(filt)
    sniff(filter = f , prn = arp_display)
    #arp_Nrange(iprange="%s" % n_range)
    #sniff(filter = "arp and dst 192.168.1.246", prn = arp_display)
    #windows.refresh()
    
#if __main__ == '__main__':
main()
