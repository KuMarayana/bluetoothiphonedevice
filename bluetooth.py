from scapy.all import *
from bluetooth import *
def retBtAddr(addr):
    btAddr=str(hex(int(addr.replace(':', ''), 16) + 1))[2:]
    btAddr=btAddr[0:2]+":"+btAddr[2:4]+":"+btAddr[4:6]+":"+\
        btAddr[6:8]+":"+btAddr[8:10]+":"+btAddr[10:12]
    return btAddr

def checkBluetooth(btAddr):
    btName = lookup_name(btAddr)
    if btName:
        print '[*] bluetooth device detection: ' + btName
    else:
        print '[*] failed scan bluetooth.'

def wifiPrint(pkt):
    iPhone_QUI = '00:00:00:00:00'
    if pkt.haslayer(Dot11):
        wifiMac = pkt.getlayer(Dot11).addr2
        if iPhone_QUI == wifiMac[:8]:
            print '[*] iphone mac detection: ' + wifiMac
            btAddr = retBtAddr(wifiMac)
            print '[*] Testing Bluetooth Mac: ' + btAddr
            checkBluetooth(btAddr)
    conf.iface = 'wlan0'
    sniff(prn=wifiPrint)