import codecs
import hashlib
key= b'TheQuickBrownFoxJumpsOverLazyDog!'
def encode(key, days):
    newKey = key
    for i in range(days):
        newKey = bytes.fromhex(hashlib.sha256(key).hexdigest()) + b'\x21'
    return codecs.encode(newKey, "hex")
# Key was made 10/4 ... (25-4=21)
print(encode(key, 21)) 