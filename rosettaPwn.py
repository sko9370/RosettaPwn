import argparse
import dpkt
import socket
import pygeoip
import csv
import pyfiglet
from colorama import Fore, Back, Style

#CW2 Mario Perez
#Python Project: Discover non en-US accept languages from PCAP
# & enriching it with GeoIP information

"""
Resources:
https://pypi.org/project/pygeoip/
	* Pure Python GeoIP API
	* This library is based on Maxmind’s GeoIP C API.
https://pypi.org/project/dpkt/
	* Fast, simple packet creation / parsing, with definitions for the basic TCP/IP protocols
https://docs.python.org/3.8/library/socket.html
	* Low level networking and interprocess communication.
https://pypi.org/project/python-csv/
	* Python tools for manipulating csv files.
https://pypi.org/project/pyfiglet/#description
	* creates fancy text in large size with the help of the screen characters.
https://pypi.org/project/colorama/
	*Cross-platform colored terminal text.
"""

################################################################################
#### Rosetta PWN banner adding color
################################################################################
def rp_banner():
    banner =pyfiglet.figlet_format("Rosetta PWN")
    print(Fore.RED, banner)
    print(Style.RESET_ALL)
################################################################################
# Create a CSV file & add Header.
################################################################################
def csv_header():
    headerList = ["ts","id.orig_h","id.orig_p","orig_country","id.resp_h","id.resp.p","resp_country","http.accept_language"]
    with open("rpParsedPCAP.csv", 'w') as file:
        dw = csv.DictWriter(file, delimiter=',', fieldnames=headerList)
        dw.writeheader()
#################################################################################
#### Set the GeoIP database of country <-------> IPs and Iterate through packets
#################################################################################
def printPcap(pcap):
    gi = pygeoip.GeoIP('GeoLiteCity.dat')

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
                        fields = [ts, src, sport, gi.country_name_by_addr(str(src)), dst, dport, gi.country_name_by_addr(str(dst)), http.headers['accept-language']]
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
    pcap_path, csv_path = parser()
    rp_banner()
    csv_header()
    f = open('/mnt/c/Users/Mario/Desktop/Education/Python/Project_http3.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    printPcap(pcap)

if __name__ == '__main__':
    main()
