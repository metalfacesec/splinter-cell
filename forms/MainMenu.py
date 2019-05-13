import npyscreen

class MainMenu(npyscreen.ActionForm):
    def create(self):
        self.attack_type = self.add(npyscreen.SelectOne, values=["Thoth", "WPA Handshake Collector", "Wifi Deauth"])
        
    def on_ok(self):
        item_selected = self.attack_type.value[0]
        if item_selected == 1:
            self.parentApp.getForm("network_interface_selector").destination = 'wpa_handshake_collection'
            self.parentApp.change_form("network_interface_selector")
        elif item_selected == 2:
            self.parentApp.getForm("network_interface_selector").destination = 'wifi_deauth_dos'
            self.parentApp.change_form("network_interface_selector")