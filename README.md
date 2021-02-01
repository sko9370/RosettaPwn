# RosettaPwn

## Setup
1. navigate inside RosettaPwn to the same directory as `setup.py`
2. run `pip install rosettaPwn` (or `pip install .`) to install all dependencies
3. when using for the first time, either manually download GeoLite2 City database or use a license key to have it downloaded for you

## Usage
- `python3 rosettaPwn.py [-h] [-o OUTPUT] [-l LICENSE] [-d DATABASE] pcap_path`
- `-o OUTPUT, --output OUTPUT` Path to csv file to be written, default to rpParsed.csv
- `-l LICENSE, --license LICENSE` License Key to download GeoLite2 City database
- `-d DATABASE, --database DATABASE` Path to database file if in custom location

## Requirements
- python3
- License key from MaxMind for GeoIP database
    - account is free to make at [MaxMind](https://www.maxmind.com)
    - create a License Key
    - copy and save License Key

## Todo

## Resources
- https://github.com/maxmind/GeoIP2-python
- https://www.maxmind.com

## Original Author
- CW2 Perez
