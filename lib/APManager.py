import time
from lib.MACAddress import MACAddress
from lib.Logger import Logger

class APManager():
    def __init__(self):
        self.ap_list = []
        self.locked_ap = None

    def update(self):
        for ap in self.ap_list:
            if (time.time() - ap.last_beacon) > 10:
                self.ap_list.remove(ap)
                continue
            if self.locked_ap is None and len(ap.targets) > 0:
                self.locked_ap = ap
                return True
            for target in ap.targets:
                if (time.time() - target.last_seen) > 10:
                    ap.targets.remove(target)
        return False

    def addTarget(self, target, ap_ssid):
        for ap in self.ap_list:
            if ap.mac in ap_ssid:
                ap.targets.append(target)
                return

    def addAP(self, ap):
        if not self.isAPKnown(ap):
            self.ap_list.append(ap)
        else:
            for ap_obj in self.ap_list:
                if ap.ssid in ap_obj.ssid:
                    ap_obj.last_beacon = time.time()

    def isAPKnown(self, ap):
        for access_point in self.ap_list:
            if ap.ssid in access_point.ssid:
                return access_point
        return False

    def getPrettyAPList(self):
        pretty_ap_list = []
        for ap in self.ap_list:
            mac = MACAddress.formatRawMAC(ap.mac)
            pretty_ap_list.append("{} {}".format(mac, ap.ssid))
        return pretty_ap_list