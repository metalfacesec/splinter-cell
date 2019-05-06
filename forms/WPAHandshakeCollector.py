import npyscreen
from lib.Logger import Logger
from lib.NetworkInterfaces import NetworkInterfaces
from attacks.WpaHandshakeGrabber import WpaHandshakeGrabber

class WPAHandshakeCollector(npyscreen.ActionForm):
    def create(self):
        self.interface = None
        self.attack_started = False

        self.status_text = self.add(npyscreen.FixedText, value="Waiting for test to start", editable=False)
        self.ap_list = self.add(npyscreen.TitlePager, vales=[], name="Access Points:")

    def while_editing(self):
        if not self.attack_started:
            self.attack_started = True
            WpaHandshakeGrabber.run(self)

    def on_ok(self):
        pass