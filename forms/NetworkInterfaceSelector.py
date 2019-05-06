import npyscreen
from lib.Logger import Logger
from lib.NetworkInterfaces import NetworkInterfaces

class NetworkInterfaceSelector(npyscreen.ActionForm):
    def create(self):
        self.destination = None
        self.interface = self.add(npyscreen.SelectOne, values=[])

    def while_editing(self):
        if not self.interface.values:
            self.interface.values = NetworkInterfaces.getNetworkInterfaces()
        
    def on_ok(self):
        self.parentApp.getForm(self.destination).interface = self.interface.values[self.interface.value[0]]
        self.parentApp.change_form(self.destination)