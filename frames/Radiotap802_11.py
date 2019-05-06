import struct 

class Radiotap802_11():
    def __init__(self, packet):
        self.len_of_header = struct.unpack('h', packet[2:4])[0]
        self.radio_tap_header = packet[:self.len_of_header].encode('hex')
        self.beacon_frame = packet[self.len_of_header:self.len_of_header + 24].encode('hex')

        self.frame_type = self.beacon_frame[:2]
        self.destination = self.beacon_frame[8:20]
        self.source = self.beacon_frame[20:32]
        self.bssid_id = self.beacon_frame[32:44]

        try:
            len_of_ssid = ord(packet[63])
            self.ssid = packet[64:64 + len_of_ssid] 
        except:
            self.ssid = "Unknown"

        try:
            self.channel = ord(packet[64 + len_of_ssid + 12])
        except:
            self.channel = 0

    def isBeaconFrame(self):
        return self.frame_type == "80"

    def isAckBlockFrame(self):
        return self.frame_type == "84"

    def isQOSFrame(self):
        return self.frame_type == "88"

    @staticmethod
    def getRadiotapHeader():
        r_rev = 0
        r_pad = 0
        r_len = 26
        r_preset_flags = 0x0000482f
        r_timestamp = 0
        r_flags = 0
        r_rate = 2
        r_freq = 2437
        r_ch_type = 0xa0
        r_signal = -48
        r_antenna = 1
        r_rx_flags = 0

        return struct.pack('BBHIQBBHHbBH', r_rev, r_pad, r_len, r_preset_flags, r_timestamp, r_flags, r_rate, r_freq, r_ch_type, r_signal, r_antenna, r_rx_flags)