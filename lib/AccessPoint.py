import time
from lib.MACAddress import MACAddress

class AccessPoint:
    def __init__(self, ssid, channel, mac):
        self.ssid = ssid
        self.channel = channel
        self.mac = mac
        self.last_beacon = time.time()
        self.targets = []

    def getPrettyTargetList(self):
        target_list = []
        for target in self.targets:
            target_list.append(MACAddress.formatRawMAC(target.mac))
        return target_list