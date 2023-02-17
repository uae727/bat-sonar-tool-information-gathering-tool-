#!/usr/bin/env python3
import sys
import platform
import nmap 
from scapy.all import *
import requests
import socket
import subprocess
import time
from colorama import Fore, Back, Style 
import scapy.all as scapy
import requests
import json
print("###################################"+Fore.RED+"The bat sonar"+Fore.WHITE+"###################################")
print(Fore.RED + " information gathering tool proggramed by kono dio da :D anyway if you have any idea or suggestion ")
print
print(Fore.BLUE + "contact me by:")
print("email:backtrack292@gmail.com")
print("twitter:@khalijyandroid") 
print(Fore.GREEN + "version:1.4")
print(Fore.WHITE + "####################################################################################")
print
print(Fore.YELLOW + "options:")
print("1 ping target")
print("2 scan headers for http/https website ")
print("3 port scaning")
print("4 OS detect")
print("5 scan network")
print("6 capture network traffic and analyze it Using AI ")
print("7 exit")
print
selectednumber=int(input(Fore.WHITE + "select the option= "))
if selectednumber == 1:
 targetip=raw_input("enter the target ip ")
 numberofpackets=int(input("enter the number of packets "))
 print("pinging the target")
 start_time = time.time()
 icmp=IP(dst=targetip)/ICMP()*numberofpackets
 resp=sr1(icmp,timeout=10)
 if resp == None:
  print("host is down")
 else:
  print("host is up")
 print("the operation took %s seconds" % (time.time() - start_time))
 sys.exit()
if selectednumber == 2:
 URL=raw_input("enter the URL ")
 start_time = time.time()
 r=requests.get(URL)

 print("status code = "+ str(r.status_code))
 print(r.headers)
 print("the operation took %s seconds" % (time.time() - start_time))
 sys.exit()
if selectednumber == 3:
 target=raw_input("enter the target IP address ")
 def portscaning(target):
  minimumrange=int(raw_input("enter the start port : "))
  maximumrange=int(raw_input("enter the end port : "))
  try:
   start_time = time.time() 
   for port in range(minimumrange,maximumrange):
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    result=sock.connect_ex((target,port))
    if result == 0:
     print("Port {}  open".format(port))
    if result != 0:
     print("Port {}  closed".format(port))
    sock.close()
   print("the scan is completed")
   print("the operation took %s seconds" % (time.time() - start_time))
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
 start_time = time.time() 
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
 print("the operation took %s seconds" % (time.time() - start_time))
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
   start_time = time.time()
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
  print("the operation took %s seconds" % (time.time() - start_time))
  sys.exit()
 try:
  if selectednumber5 == 1:
   minimum=int(input("enter the start range"))
   maximum=int(input("enter the end range"))
   start_time = time.time()
   for ping in range(minimum,maximum):
    address = "192.168.0." + str(ping) 
    res = subprocess.call(['ping', '-c', '3', address]) 
    if res == 0: 
     print
     print(format(address)+ " is live")
     print
     print("#######################################################")
   print("the operation took %s seconds" % (time.time() - start_time))
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
 def capture_and_analyze():
    # Define a filter to capture only the relevant network traffic (e.g. HTTP, HTTPS, DNS, etc.)
    capture_filter = "tcp port 80 or tcp port 443 or udp port 53"

    # Start capturing network traffic using Scapy
    captured_packets = scapy.sniff(filter=capture_filter, count=100)

    # Extract the payload of each captured packet
    payloads = [packet.load for packet in captured_packets]

    # Convert the payloads to text and concatenate them into a single string
    text = ""
    for payload in payloads:
        try:
            text += payload.decode("utf-8")
        except UnicodeDecodeError:
            continue

    # Analyze the text using the OpenAI API and ChatGPT
    api_key = "YOUR_API_KEY" # Replace with your OpenAI API key
    api_url = "https://api.openai.com/v1/engines/davinci-codex/completions"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    prompt = "Analyze the following network traffic and report back any harmful activities:\n\n" + text
    data = {"prompt": prompt, "max_tokens": 1024, "temperature": 0.5}

    response = requests.post(api_url, headers=headers, data=json.dumps(data))
    response_json = json.loads(response.text)
    output = response_json["choices"][0]["text"]

    # Print the output from ChatGPT
    print(output)

# Call the function to capture and analyze network traffic
capture_and_analyze()
  
  
if selectednumber == 7:
 sys.exit()

 


