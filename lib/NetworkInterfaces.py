from lib.Logger import Logger

class NetworkInterfaces():
    @staticmethod
    def getNetworkInterfaces():
        interfaces = []

        lines = open("/proc/net/dev", "r").readlines()
        for line in lines:
            dev_info_array = filter(None, line.split(" "))
        
            if ':' in dev_info_array[0] and 'lo:' not in dev_info_array[0]:
                interfaces.append(dev_info_array[0].split(":")[0])

        return interfaces