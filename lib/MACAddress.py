class MACAddress():
    @staticmethod
    def formatRawMAC(mac):
        return "{}:{}:{}:{}:{}:{}".format(mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:12])