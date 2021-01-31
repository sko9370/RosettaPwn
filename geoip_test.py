#!/usr/bin/env python3

import argparse
import subprocess
import os
import geoip2.database


def parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('license',
        type = str,
        help = 'License Key to download GeoLite2 City database')
    args = parser.parse_args()
    return args.license

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

def read_db():
    path = 'database/GeoLite2-City.mmdb'
    with geoip2.database.Reader(path) as reader:
        # should be US
        response = reader.city('100.50.10.190')
        print(response.country.iso_code)
        # should be AF (Afghanistan)
        response = reader.city('27.116.56.10')
        print(response.country.iso_code)

def main():
    license_key = parser()
    download_geoip(license_key)
    preprocess()
    read_db()


if __name__ == "__main__":
    main()
