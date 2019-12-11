from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp

netSSID = 'FUZZ'            #Network name here
iface = 'wlan1mon'          #Interface name here

dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
addr2='00:0a:eb:2d:72:55', addr3='00:0a:eb:2d:72:55')
beacon = Dot11Beacon()
ssid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))

frame = RadioTap()/dot11/beacon/ssid

sendp(frame, iface=iface, inter=0.100, loop=1)