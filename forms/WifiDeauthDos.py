import npyscreen
from lib.Logger import Logger
from attacks.WifiDeautAttack import WifiDeautAttack

class WifiDeauthDos(npyscreen.ActionForm):
    def create(self):
        self.ap_list = self.add(npyscreen.SelectOne, values=[], name="Select AP:")

        self.interface = None
        self.attack_started = False

    def while_editing(self):
        if not self.attack_started:
            self.attack_started = True
            WifiDeautAttack.run(self)

    def on_ok(self):
        pass