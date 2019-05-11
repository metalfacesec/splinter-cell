import datetime

class Logger():
    @staticmethod
    def log(msg):
        current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        f = open("./logs/splinter_cell.log","a+")
        f.write("[{}]{}\n".format(current_date, msg))
        f.close()
