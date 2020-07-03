#!/usr/bin/env python3
import sys
import platform
import nmap 
from scapy.all import *
import requests
import socket
import subprocess
from colorama import Fore, Back, Style 
print("###################################information gathering tool###################################")
print(Fore.RED + "proggramed by kono dio da :D anyway if you have any idea or suggestion ")
print
print(Fore.BLUE + "contact me by:")
print("email:backtrack292@gmail.com")
print("twitter:@khalijyandroid") 
print(Fore.GREEN + "version:1.2")
print(Fore.WHITE + "################################################################################################")
print
print(Fore.YELLOW + "options:")
print("1 ping target")
print("2 scan headers for http/https website ")
print("3 port scaning")
print("4 OS detect")
print("5 scan network")
print("6 exit")
print
selectednumber=int(input(Fore.WHITE + "select the option= "))
if selectednumber == 1:
 targetip=raw_input("enter the target ip ")
 numberofpackets=int(input("enter the number of packets "))
 print("pinging the target")
 icmp=IP(dst=targetip)/ICMP()*numberofpackets
 resp=sr1(icmp,timeout=10)
 if resp == None:
  print("host is down")
 else:
  print("host is up")
 sys.exit()
if selectednumber == 2:
 URL=raw_input("enter the URL ")
 r=requests.get(URL)

 print("status code = "+ str(r.status_code))
 print(r.headers)
 sys.exit()
if selectednumber == 3:
 target=raw_input("enter the target IP address ")
 def portscaning(target):
  minimumrange=int(raw_input("enter the start port : "))
  maximumrange=int(raw_input("enter the end port : "))
  try: 
   for port in range(minimumrange,maximumrange):
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    result=sock.connect_ex((target,port))
    if result == 0:
     print("Port {}  open".format(port))
    sock.close()
   print("the scan is completed")
  except KeyboardInterrupt: 
        print("\n Exitting Program !!!!") 
        sys.exit() 
  except socket.gaierror:
        print("\n Hostname Could Not Be Resolved !!!!") 
        sys.exit() 
  except socket.error: 
        print("\ Server not responding !!!!") 
 print(portscaning(target))
 sys.exit()
print
if selectednumber == 4:
 target1=raw_input("enter the target IP : ") 
 nm = nmap.PortScanner()
 machine = nm.scan(target1, arguments='-O')
 if 'osclass' in nm[target1]:
        osclass = nm[target1]['osclass']
        print('OsClass.type : {0}'.format(osclass['type']))
        print('OsClass.vendor : {0}'.format(osclass['vendor']))
        print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
        print('OsClass.osgen : {0}'.format(osclass['osgen']))
        print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
        print('')
 sys.exit()
if selectednumber == 5:
 try:
  print(" 1 scan with range ")
  print(" 2 full scan ")
  selectednumber5=int(input("select option"))
 except KeyboardInterrupt: 
  print("\n Exitting Program !!!!") 
  sys.exit() 
 except socket.gaierror:
  print("\n Hostname Could Not Be Resolved !!!!") 
  sys.exit() 
 except socket.error: 
  print("\ Server not responding !!!!") 
 try:
  if selectednumber5 == 2:
   for ping in range(1,255):
    address = "192.168.0." + str(ping) 
    res = subprocess.call(['ping', '-c', '3', address]) 
    if res == 0: 
     print
     print(format(address)+ " is live")
     print
     print("#######################################################")
 except KeyboardInterrupt: 
  print("\n Exitting Program !!!!") 
  sys.exit() 
 except socket.gaierror:
  print("\n Hostname Could Not Be Resolved !!!!") 
  sys.exit() 
 except socket.error: 
  print("\ Server not responding !!!!") 
  sys.exit()
 try:
  if selectednumber5 == 1:
   minimum=int(input("enter the start range"))
   maximum=int(input("enter the end range"))
   for ping in range(minimum,maximum):
    address = "192.168.0." + str(ping) 
    res = subprocess.call(['ping', '-c', '3', address]) 
    if res == 0: 
     print
     print(format(address)+ " is live")
     print
     print("#######################################################")
 except KeyboardInterrupt: 
  print("\n Exitting Program !!!!") 
  sys.exit() 
 except socket.gaierror:
  print("\n Hostname Could Not Be Resolved !!!!") 
  sys.exit() 
 except socket.error: 
  print("\ Server not responding !!!!") 
  sys.exit()
  sys.exit()


if selectednumber == 6:
 sys.exit()

 


