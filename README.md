#IoTDS - IoT devices monitoring and spoofing attack detection system.

The IoTDS is an attack detecting system that uses a variety of applications with the Home Assistant and Suricata, with the ARP spoofing detection functions. The idea is to build up an all-in-one IoT management and network attack detection system. This application is built upon its own understanding of IoT and ARP spoofing detection. The big goal is to build a network monitoring system which can detect the spoofing attack on the IoT device. 
To begin with the IoTDS there is serval application and library needs to be installed before to run the application, to ensure all function in the application can running well.
There are four main types of application need to install before the application can be running normal, They are:
```
1.	Operating system
2.	Python and related libraries
3.	Home assistant
4.	Suricata
```

##Basic system requirements
IoTDS is buildup with auto network monitoring with IDS analysis function. It developed on the single-board computer Raspberry Pi 4B with the 64 bits Ubuntu Linux system and tested on the Virtual machine with the same version of Ubuntu Linux. here is the tested operation system which can normally run the application:
```
-	Ubuntu Server 20.04 LTS 64Bit
-	Raspberry OS 32bit
```
The new version of Ubuntu 21.04 is not fully compatible with this setup guide as some application package installation methods may not support the new operating system. If any of the applications need to be manually installed, those application functions in the IoTDS may have problems.
For the expert user, the user can choose to install it manually, this setup guide is targeted to the normal user, which uses the easiest way to install all applications and libraries

#Operation system installation & system update
For the Raspberry Pi 4B, for easy installation, is recommended to uses the official Raspberry Pi Imager, which supports Windows, macOS, and Ubuntu OS, to download the necessary operating system and flash it to Linux operating system into the micro SD card. 
Users can use the following link to download the imager and flash it into the micro SD card.
```
https://www.raspberrypi.org/software/
```
After the flashing of the Linux, Turn on the system and complete the initial configuration. If your Raspberry pi 4B is an 8GB version, here to recommend using the Ubuntu 20.04 LTS 64-bit instead of using the raspberry pi OS which only has a 32-bit version which will get better performance on the monitoring. 

As the imager only provides the ubuntu server 20.04 LTS which is not having the UI. You can install it by the following command:
Full desktop with recommend application, as the file size it may take a while to install it.
sudo apt-get install ubuntu-desktop

or, Install the desktop-only version.
sudo apt-get install --no-install-recommends ubuntu-desktop


Here is recommended to use the root account to run the application with full permission, as some python library needs the root permission and some are not. It causes some mass if using the command to get the root permission by a normal user.

Then run the update command to update the system, 
First, use this command to check is any update.
Sudo apt update

Then use the following command to update the application which installed the system.
Sudo apt upgrade

Then the operating system installation is finished.


#Python and related library installation
This installation process will focus on the installation of the python application and related libraries. Here are those applications and libraries that will be installed.
```
-	Python pip
-	Scapy
-	Pyshark
-	PysimpleGUI
-	Tshark
```
First, check the version of the python3 installed in Linux, can use the command “Python3”, which will display the version, usually is python 3 with version 3.7 or above. If the version is too low, the user can try to update the Linux or change the version of the Linux to the newest version.
```
Python pip
```
Then install the package installer for python to simplify the library’s installation procedures, and ensure the installed version of the application is suitable for your current python version. To installation, use the following command to install it. 
```
Sudo apt install pip
```

##PysimpleGUI & tkinter
For the application’s UI can run normally, install the PysimpleGUI library. By using the pip3 package installer, install it by command.
```
Sudo Pip install pysimplegui
```
Apart from the PysimpleGUI, for running the PysimpleGUI application, it also relies to the Tkinter library, to install by command.
```
Sudo apt install python3-tk
```

##Scapy, Pyshark and tshark
Then, to install the library for the network monitoring, the first is to install the python Scapy library by the following command.
```
Sudo pip install scapy
```

Then install the library for the network sniffing feature, by the following command.
```
Sudo Pip install pyshark
```
The Pyshark libraries rely upon the tshark library to functions, installed by the following command.
```
Sudo apt install tshark
```
It will prompt out a Wireshark configuring windows and ask to allow non-superusers able to capture the packets. Choose yes and continue.

For the packet analysis feature by Wireshark, to installation by the following command.
```
Sudo apt install wireshark
```

#Home Assistant
Home Assistant is an open-source application for local IoT devices, to provide home automation and device management with security via this single system. It contains four versions of home assistant for users to choose to install.
-	Home assistant Operation system.
-	Home assistant Container
-	Home assistant Supervised
-	Home assistant Core

Experience users can choose to install Home Assistant manually, by the official instruction.
```
https://www.home-assistant.io/installation/ 
```
Here recommend installing the docker version with the supervised version of Home assistant to ensure it addon function to support more IoT protocol and output method.

For non-experience users, it is recommended to use the Github project “IOTstack” which provides an easy installation of a supervised or normal docker version with a command, although some addon functions in the supervised version may malfunction. But it still enough for this project usage. This method is only supported for the Linux version below ubuntu 20.04, the newest version’s docker version is not supported 
Here is the simple instruction.
1.	Install the curl:
```
sudo apt install -y curl
```
2.	Add home assistant’s curl repository
```
curl -fsSL https://raw.githubusercontent.com/SensorsIot/IOTstack/master/install.sh | bash
```
3.	It will copy the repository to your user home folder, and check and install the docker for the IoTstack running. Then use this command to run up the setup menu.
```
cd ~/IOTstack
./menu.sh
```

Once the menu is open, it will check up on the necessary application in your system, and ask for install if some application is missing.
If it cannot find the folder or the menu hasn’t opened up, try to search the “IOTstack” folder on the user’s directory and open the following command “./meun.sh” to open the menu.


Here recommend using the supervised version of a home assistant. To install it, some dependencies application is needs.
```
sudo apt install -y apparmor apparmor-profiles apparmor-utils
sudo apt install -y software-properties-common apt-transport-https ca-certificates dbus
sudo apt install -y network-manager
```

Then get into “Native installs” in the menu and select Hass.io(Supervisor), Following the installation step and choose the right device type, in the setup guide is using raspberry pi 4 with 64 bit, it will take a while to install all container. Once the installation complete, the docker service will automatically restart. 
Last, can use the docker command to check the Hass.io docker is startup or not.
```
Docker stats
```

Users can also choose the normal home assistant version, choose the “build stack” and select the “home assistant” in the container list and then compose the stack in the “docker commands” page. 

#Suricata
Suricata has released an official PPA installation method instead of the manual installation for the Ubuntu Linux system. Please use the following command to install it.
```
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata jq
```
It adds the Suricata official repository to Ubuntu Linux’s apt repository, then runs the apt update to check the repository and install the Suricata and the jquery. 

After the installation of Suricata, you can use the command to check the version of Suricata and the service status of Suricata by the following command.
```
sudo suricata --build-info
sudo systemctl status suricata
```
Then update the Suricata by the following command
```
sudo suricata-update
```
Once the update install, you need to restart Suricata or restart the system to make sure Suricata is run properly with the updated rules. Restart Suricata by command.
```
sudo systemctl restart suricata
```

After the install, user can try to configure the suricata
To test the Suricata is running properly, using the command. 

