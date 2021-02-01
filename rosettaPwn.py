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

def rp_banner():
    banner = pyfiglet.figlet_format("Rosetta PWN")
    print(Fore.RED, banner)
    print(Style.RESET_ALL)

def parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output',
        type = str,
        help = 'Path to csv file to be written, default to rpParsed.csv')
    parser.add_argument('-l', '--license',
        type = str,
        help = 'License Key to download GeoLite2 City database')
    parser.add_argument('-d', '--database',
        type = str,
        help = 'Path to database file if in custom location')
    parser.add_argument('pcap_path',
        type = str,
        help = 'Path to pcap file to be parsed')
    args = parser.parse_args()
    if not args.output:
        csv_path = 'rpParsed.csv'
    return csv_path, args.license, args.database, args.pcap_path

def download_geoip(license_key):
    dl_link = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=' + license_key + '&suffix=tar.gz'
    subprocess.run(['wget', '-O', 'geolite2city.tar.gz', dl_link])
    print('Downloading geolite2city database using license key')

def preprocess():
    subprocess.run(['tar', '-xzf', 'geolite2city.tar.gz'])
    print('Extracting database folder')
    # clean up
    subprocess.run(['rm', 'geolite2city.tar.gz'])
    files = os.listdir('.')
    for f in files:
        if 'GeoLite2-City_' in f:
            # just in case there's a database directory already
            subprocess.run(['rm', '-r', 'database'])
            subprocess.run(['mv', f, 'database'])
            break
    print('Rename folder to "database"')

def parse_pcap(pcap_path, database):
    pcap_file = open(pcap_path, 'rb')
    pcap = dpkt.pcap.Reader(pcap_file)
    reader = geoip2.database.Reader(database)
    interesting = ['en-US,', 'en-US;', 'es', '*']

    interesting_languages = []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        tcp = ip.data
        sport = tcp.sport
        dport = tcp.dport
        if dport != 80:
            continue
        try:
            request = dpkt.http.Request(tcp.data)
            accept_language = request.headers['accept-language']
        except:
            continue

        try:
            src_country = reader.city(src).country.iso_code
        except:
            # errors out if local ip address used
            src_country = 'Local'
        try:
            dst_country = reader.city(dst).country.iso_code
        except:
            dst_city = 'Local'

        not_interesting = ['Local', 'US']
        add = False
        for i in interesting:
            if accept_language == 'en-US,en;q=0.9':
                break
            elif i in accept_language:
                add = True
                break
        if src_country not in not_interesting or dst_country not in not_interesting:
            add = True

        if add:
            fields = [ts, src, sport, src_country,
                dst, dport, dst_country, accept_language]
            interesting_languages.append(fields)
        else:
            continue

    pcap_file.close()
    reader.close()

    return interesting_languages

def write_csv(csv_path, data):
    headerList = ["ts","id.orig_h","id.orig_p","orig_country",
        "id.resp_h","id.resp.p","resp_country","http.accept_language"]
    with open(csv_path, 'w', newline = '') as csv_file:
        cw = csv.writer(csv_file, delimiter=',')
        cw.writerow(headerList)
        for line in data:
            cw.writerow(line)
    print('Writing csv to: {}'.format(csv_path))

def print_results(data):
    for row in data:
        print(row)

def main():
    rp_banner()
    csv_path, license, database, pcap_path = parser()
    default_db_path = 'database/GeoLite2-City.mmdb'
    if database:
        interesting_languages = parse_pcap(pcap_path, database)
    elif license:
        download_geoip(license)
        preprocess()
        interesting_languages = parse_pcap(pcap_path, default_db_path)
    else:
        try:
            interesting_languages = parse_pcap(pcap_path, default_db_path)
        except:
            print('no database, use "-l" with license key to download database')
            return
    write_csv(csv_path, interesting_languages)
    print_results(interesting_languages)
    return

if __name__ == '__main__':
    main()
