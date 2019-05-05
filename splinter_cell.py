import npyscreen

def myFunction(*args):
    F = npyscreen.Form(name='Splinter Cell')
    F.add(npyscreen.TitleMultiLine, name="Select An Attack", values=['WPA Handshake Extractor', 'Wifi list'])
    F.edit()

if __name__ == '__main__':
    npyscreen.wrapper_basic(myFunction)
    print "Blink and you missed it!"