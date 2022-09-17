from datetime import datetime
import random


class Utils:

    def generate_session_id() -> str:
        date = str(datetime.today().day) + str(datetime.today().month) + str(datetime.today().year)
        random_num = str (random.randint(100000000, 999999999))
        return date + '-' + random_num