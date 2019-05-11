import time

class Target:
    def __init__(self, mac):
        self.mac = mac
        self.last_seen = time.time()