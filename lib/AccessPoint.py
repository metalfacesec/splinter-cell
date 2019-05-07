import time

class AccessPoint:
    def __init__(self, ssid, channel, mac):
        self.ssid = ssid
        self.channel = channel
        self.mac = mac
        self.last_beacon = time.time()
        self.targets = []

    def updateLastBeaconTime(self, ap):
        pass