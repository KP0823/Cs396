import codecs
import hashlib

key= b'TheQuickBrownFoxJumpsOverLazyDog!'
date=21
def encode(key,date):
    newKey = key
    for i in range(date):
        nums=hashlib.sha256(key).hexdigest()
        newKey = bytes.fromhex(nums)  +b'\x21'
    return codecs.encode(newKey, "hex")
print(encode(key, date)) 