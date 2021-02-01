import argparse
import subprocess
import os
import geoip2.database

import dpkt
import socket
import csv
import pyfiglet
from colorama import Fore, Back, Style

#CW2 Mario Perez
#Python Project: Discover non en-US accept languages from PCAP
# & enriching it with GeoIP information

def parser():
    pass

def rp_banner():
    banner =pyfiglet.figlet_format("Rosetta PWN")
    print(Fore.RED, banner)
    print(Style.RESET_ALL)

def csv_header():
    headerList = ["ts","id.orig_h","id.orig_p","orig_country",
            "id.resp_h","id.resp.p","resp_country","http.accept_language"]
    with open("rpParsedPCAP.csv", 'w') as file:
        dw = csv.DictWriter(file, delimiter=',', fieldnames=headerList)
        dw.writeheader()

def printPcap(pcap):
    #gi = pygeoip.GeoIP('GeoLiteCity.dat')
    path = 'database/GeoLite2-City.mmdb'
    with geoip2.database.Reader(path) as reader:
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
                sport = tcp.sport
                dport = tcp.dport
                http = dpkt.http.Request(tcp.data)
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                accept_languages = []
#### Filter out a the HTTP traffic using 'en-US' #####
                http_headers = str(http.headers['accept-language'])
                if dport == 80 and http_headers and len(tcp.data) > 0:
                    interesting = ['en-US,', 'en-US;', 'es', '*']
                    for i in interesting:
                        if i in http_headers and not 'en-US,en:q=0.5' in http_headers:
#### Print out netflow inforamtion to include GeoIP and Language data ####
                            fields = [ts, src, sport, reader.city(str(src)).iso_code, dst, dport, reader.city(str(dst)).iso_code, http.headers['accept-language']]
                            for field in fields:
                                accept_languages.append(field)
#### Write netflow data into a CSV file and will append more data #####
                            with open("rpParsedPCAP.csv", "a", newline="") as csvfile:
                                print(accept_languages)
                                filewriter = csv.writer(csvfile)
                                filewriter.writerow(accept_languages)
            except:
                pass

def main():
    #pcap_path, csv_path = parser()
    rp_banner()
    csv_header()
    f = open('2015-08-31-traffic-analysis-exercise.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    printPcap(pcap)

if __name__ == '__main__':
    main()
