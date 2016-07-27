from ctypes import *
import sys

class SavedAP(Structure):
    _pack_ = True
    _fields_ = [
                ('bssid',    c_uint8*6),
                ('password', c_char*8),
                ('padding',  c_uint8*2),
               ]
    def __repr__(self):
        bssid = ''.join(["%02x:" % x for x in self.bssid])[:-1]
        return "AP with BSSID %s and password %s" % (bssid, self.password)

    def empty(self):
        return list(self.bssid) == [0xff]*6

if len(sys.argv) > 1:
    filename = sys.argv[1]
else:
    filename = 'saved_passwords.bin'
with file(filename) as f:
    while True:
        saved_ap = SavedAP.from_buffer_copy(f.read(sizeof(SavedAP)))
        if saved_ap.empty():
            break
        print(saved_ap)
