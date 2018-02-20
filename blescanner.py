"""Python-based scanner for BLE packets.

BLE iBeaconScanner based on:
https://github.com/adamf/BLE/blob/master/ble-scanner.py
https://code.google.com/p/pybluez/source/browse/trunk/examples/advanced/inquiry-with-rssi.py

LEscan:
https://github.com/pauloborges/bluez/blob/master/tools/hcitool.c
Opcodes:
https://kernel.googlesource.com/pub/scm/bluetooth/bluez/+/5.6/lib/hci.h
Functions used by LEscan:
https://github.com/pauloborges/bluez/blob/master/lib/hci.c#L2782

Performs a simple device inquiry, and returns a list of BLE advertisements
discovered device

NOTE: Python's struct.pack() will add padding bytes unless you make the
endianness explicit. Little endian should be used for BLE. Always start a
struct.pack() format string with "<"
"""

import os
import sys
import struct
import bluetooth._bluetooth as bluez
import binascii

from packet_parsers import parse_payload

DEBUG = False

LE_META_EVENT = 0x3e
LE_PUBLIC_ADDRESS = 0x00
LE_RANDOM_ADDRESS = 0x01
LE_SET_SCAN_PARAMETERS_CP_SIZE = 7
OGF_LE_CTL = 0x08
OCF_LE_SET_SCAN_PARAMETERS = 0x000B
OCF_LE_SET_SCAN_ENABLE = 0x000C
OCF_LE_CREATE_CONN = 0x000D

LE_ROLE_MASTER = 0x00
LE_ROLE_SLAVE = 0x01

# These are actually subevents of LE_META_EVENT
EVT_LE_CONN_COMPLETE = 0x01
EVT_LE_ADVERTISING_REPORT = 0x02
EVT_LE_CONN_UPDATE_COMPLETE = 0x03
EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE = 0x04

# Advertisement event types
ADV_IND = 0x00
ADV_DIRECT_IND = 0x01
ADV_SCAN_IND = 0x02
ADV_NONCONN_IND = 0x03
ADV_SCAN_RSP = 0x04


def noparser(data):
    return data


def debug(*message):
    if DEBUG:
        print " ".join(map(str, message))


class BleScanner:
    def __init__(self):
        self.sock = None
        self.old_filter = None

    def open(self, dev_id):
        self.sock = bluez.hci_open_dev(dev_id)

    def printpacket(self, pkt):
        for c in pkt:
            sys.stdout.write("%02x " % struct.unpack("B", c)[0])
        sys.stdout.write(repr(pkt) + ' ')

    def get_packed_bdaddr(self, bdaddr_string):
        packable_addr = []
        addr = bdaddr_string.split(':')
        addr.reverse()
        for b in addr:
            packable_addr.append(int(b, 16))
        return struct.pack("<BBBBBB", *packable_addr)

    def packed_bdaddr_to_string(self, bdaddr_packed):
        data = struct.unpack("<BBBBBB", bdaddr_packed[::-1])
        return ':'.join('%02x' % i for i in data)

    def hci_enable_le_scan(self):
        self.hci_toggle_le_scan(0x01)

    def hci_disable_le_scan(self):
        self.hci_toggle_le_scan(0x00)

    def hci_toggle_le_scan(self, enable):
        cmd_pkt = struct.pack("<BB", enable, 0x00)

        bluez.hci_send_cmd(
            self.sock,
            OGF_LE_CTL,
            OCF_LE_SET_SCAN_ENABLE,
            cmd_pkt
        )

    def hci_le_set_scan_parameters(self):
        old_filter = self.sock.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    def enable_filter(self):
        assert not self.old_filter

        self.old_filter = self.sock.getsockopt(
            bluez.SOL_HCI,
            bluez.HCI_FILTER,
            14
        )

        # perform a device inquiry on bluetooth device #0
        # The inquiry should last 8 * 1.28 = 10.24 seconds
        # before the inquiry is performed, bluez should flush its cache of
        # previously discovered devices
        flt = bluez.hci_filter_new()
        bluez.hci_filter_all_events(flt)
        bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
        self.sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, flt)

    def disable_filter(self):
        assert self.old_filter
        self.sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, self.old_filter)
        self.old_filter = None

    def parse_advertisement(self):
        while True:
            pkt = self.sock.recv(255)
            ptype, event, plen = struct.unpack("BBB", pkt[:3])
            assert ptype == bluez.HCI_EVENT_PKT # We are filtering for those only, so complain if we get anything else.
            if DEBUG: print "-------------- received", ptype, event, plen 
            if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
                if DEBUG: print "was event EVT_INQUIRY_RESULT_WITH_RSSI"
            elif event == bluez.EVT_NUM_COMP_PKTS:
                if DEBUG: print "was event EVT_NUM_COMP_PKTS"
            elif event == bluez.EVT_DISCONN_COMPLETE:
                if DEBUG: print "was event EVT_DISCONN_COMPLETE"
                return None
            elif event == LE_META_EVENT:
                subevent, = struct.unpack("<B", pkt[3])
                if DEBUG: print "-------------- subevent", subevent
                pkt = pkt[4:]
                if subevent == EVT_LE_CONN_COMPLETE:
                    pass # self.le_handle_connection_complete(pkt)
                elif subevent == EVT_LE_ADVERTISING_REPORT:
                    preamble, = struct.unpack("<B", pkt[0])
                    pkt = pkt[1:]
                    if DEBUG: print "-------------- numreports", preamble
                    assert preamble == 1
                    # See structure le_advertising_info in /usr/include/bluetooth/hci.h
                    while preamble > 0:
                        preamble -= 1
                        adv_evt_type, adv_bdaddr_type, adv_length = struct.unpack("<BBxxxxxxB", pkt[:9])
                        adv_bdaddr = pkt[2:8]
                        adv_data = pkt[9:9+adv_length]
                        # Remove the data from pkt
                        pkt = pkt[9+adv_length:]
                        # Store in item
                        item = dict(
                            raw_evt_type=adv_evt_type, 
                            raw_bdaddr_type=adv_bdaddr_type, 
                            bdaddr=self.packed_bdaddr_to_string(adv_bdaddr)
                            )
                        item['raw_advertisements'] = binascii.hexlify(adv_data)
                        # If we have one byte left we think it is the rssi, but this is guessed from existing code.
                        if len(pkt) == 1:
                            rssi, = struct.unpack("<b", pkt)
                            item['rssi'] = rssi
                        # We don't understand raw_event_type, it seems to be a bluez-ism. only keep if non-zero.
                        if adv_evt_type == 0:
                            del item['raw_evt_type']
                        # Now try to parse things, and replace the raw data if successful
                        if adv_bdaddr_type in (LE_PUBLIC_ADDRESS, LE_RANDOM_ADDRESS):
                            del item['raw_bdaddr_type']
                            item['bdaddr_type'] = 'public' if adv_bdaddr_type == LE_PUBLIC_ADDRESS else 'random'
                        # And parse the advertisement data
                        advertisements, allCorrect = parse_payload(adv_data)
                        if advertisements:
                            item['advertisements'] = advertisements
                            sergioSeesTheLight = False
                            if allCorrect and sergioSeesTheLight:
                                del item['raw_advertisements']
                    return item
                else:
                    if DEBUG: print "was subevent", subevent
            else:
                if DEBUG: print "was event", event

def start_scan():
    scanner = BleScanner()
    scanner.open(0)
    scanner.hci_le_set_scan_parameters()
    scanner.hci_enable_le_scan()
    scanner.enable_filter()

    try:
        while True:
            evt = scanner.parse_advertisement()
            yield evt
    finally:
        scanner.disable_filter()
        scanner.hci_disable_le_scan()



if __name__ == "__main__":
    for packet in start_scan():
        print packet
