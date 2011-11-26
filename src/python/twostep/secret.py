import time
import base64
import os
import struct
from hmac import HMAC
from hashlib import sha1


class Secret:
    """
    Class wrapper for user secret key.
    """
    
    secret = None

    def __init__(self, key=None):
        if key:
            self.secret = base64.b32decode(key)
        else:
            self.secret = os.urandom(10)

    def get_key(self):
        return base64.b32encode(self.secret)

    def get_qrcode(self, username, domain):
        """
        Returns a reference to the google chart API to generate 
        the QR code, can be included in page as an <img>
        """

        url = "https://chart.googleapis.com/chart"
        url += "?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/"
        url += username + "@" + domain + "%3Fsecret%3D"
        url += base64.b32encode(self.secret)
        return url

    def auth(self, code, type='totp'):
        """
        Authenticates a provided auth code against the secret key.
        """

        if type == 'totp':
            # get current time, convert to byte array, and take the sha1
            time_int = int(time.time()/30)
            time_b = struct.pack(">q", time_int)
            sha = HMAC(self.secret, time_b, sha1).digest()

            # grab a chunk of 4 bytes using the LSB
            offset = ord(sha[-1]) & 0x0F
            chunk = sha[offset:offset+4]
            
            code_exp = struct.unpack(">L", chunk)[0]
            code_exp &= 0x7FFFFFFF;
            code_exp %= 1000000;

            if ("%06d" % code_exp) == str(code):
                return True

            return False
        elif type == 'hotp':
            raise NotImplemented
        else:
            raise Exception
