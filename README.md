# RosettaPwn

## Setup
1. navigate inside RosettaPwn to the same directory as `setup.py`
2. run `pip install rosettaPwn` (or `pip install .`) to install all dependencies

## Usage

## Requirements
- python3
- License key from MaxMind for GeoIP database
    - account is free to make at [MaxMind](https://www.maxmind.com)
    - create a License Key
    - copy and save License Key

## Todo
- integrate geoip2 to replace pygeoip and deprecated `.dat` database format
- add commandline options using argparse
    - add option if user wants to skip new database download
    - add option to designate path to read pcap
    - add option to designate path to write csv output

## Resources
- https://github.com/maxmind/GeoIP2-python
- https://www.maxmind.com
