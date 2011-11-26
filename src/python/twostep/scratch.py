import os

def gen_codes(num=5, length=8):
    codes = [ os.urandom(length) for i in range(num) ]
    return codes
