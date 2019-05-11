import npyscreen

class MainMenu(npyscreen.ActionForm):
    def create(self):
        self.attack_type = self.add(npyscreen.SelectOne, values=["Thoth", "WPA Handshake Collector"])
        
    def on_ok(self):
        item_selected = self.attack_type.value[0]
        if item_selected == 1:
            self.parentApp.getForm("network_interface_selector").destination = 'wpa_handshake_collection'
            self.parentApp.change_form("network_interface_selector")