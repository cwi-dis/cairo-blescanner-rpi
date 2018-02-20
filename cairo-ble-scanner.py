#!/usr/bin/env python
import sys
from blescanner import start_scan
from time import time
from json import dumps
if __name__ == '__main__':
    for packet in start_scan():
        if 'advertisements' in packet:
            if 'nearable' in packet['advertisements']:
                packet['time'] = time()
                print dumps(packet)
                sys.stdout.flush()