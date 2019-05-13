import npyscreen
from forms.MainMenu import MainMenu
from forms.WifiDeauthDos import WifiDeauthDos
from forms.WPAHandshakeCollector import WPAHandshakeCollector
from forms.NetworkInterfaceSelector import NetworkInterfaceSelector

class SpinterCell(npyscreen.NPSAppManaged):
    def onStart(self):
        self.addForm("MAIN", MainMenu, name="Splinter Cell", color="IMPORTANT",)
        self.addForm("wpa_handshake_collection", WPAHandshakeCollector, name="WPA Handshake Collection", color="WARNING",)
        self.addForm("wifi_deauth_dos", WifiDeauthDos, name="Wifi Deauth DOS", color="WARNING",)
        self.addForm("network_interface_selector", NetworkInterfaceSelector, name="Network Interface Selector", color="WARNING",)
        
    def onCleanExit(self):
        npyscreen.notify_wait("Goodbye!")
    
    def change_form(self, name):
        self.switchForm(name)      
        self.resetHistory()

def main():
    SC = SpinterCell()
    SC.run()

if __name__ == '__main__':
    main()

