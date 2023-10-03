import codecs

def decrypt(ciphertexts):
  cipher_xor = hex(int(ciphertexts[1], 16) ^ int(ciphertexts[2], 16))[2:]
  print(cipher_xor)
  for common_words in [b" the ", b" be ", b" to ", b" a ", b" you ", b' is ', b' can ', b' that ']:
    print(common_words)
    encoded_word = codecs.encode(common_words,"hex")
    index = 0
    while index < len(cipher_xor)-len(encoded_word):
      drag = hex(int(cipher_xor[index:index+len(encoded_word)],16) ^ int(encoded_word,16))[2:]
      # print(drag)
      if len(drag)%2!=0:
        drag = drag + "0"
      print(str(codecs.decode(drag,"hex")) + str(index//2))
      index+=2
    print("")

  key_5_10 = hex(int(ciphertexts[1][10:20], 16) ^ int(codecs.encode(b' can ',"hex"), 16))
  print(key_5_10)
  print(str(codecs.decode(key_5_10[2:],"hex")))
  print("")

  for ciphertext in ciphertexts:
    region_decode = hex(int(ciphertext[10:20],16) ^ int(key_5_10,16))[2:]
    print(str(codecs.decode(region_decode,"hex")))

  key_4_11 = hex(int(ciphertexts[5][8:22], 16) ^ int(codecs.encode(b' would ',"hex"), 16))
  print(key_4_11)
  print(str(codecs.decode(key_4_11[2:],"hex")))
  print("")

  for ciphertext in ciphertexts:
    region_decode = hex(int(ciphertext[8:22],16) ^ int(key_4_11,16))[2:]
    print(str(codecs.decode(region_decode,"hex")))

  key_3_11 = hex(int(ciphertexts[9][6:22], 16) ^ int(codecs.encode(b' we are ',"hex"), 16))
  print(key_3_11)
  print(str(codecs.decode(key_3_11[2:],"hex")))
  print("")

  for ciphertext in ciphertexts:
    region_decode = hex(int(ciphertext[6:22],16) ^ int(key_3_11,16))[2:]
    print(str(codecs.decode(region_decode,"hex")))

  key_0_16 = hex(int(ciphertexts[0][0:32], 16) ^ int(codecs.encode(b'Testing testing ',"hex"), 16))
  print(key_0_16)
  print(str(codecs.decode(key_0_16[2:],"hex")))
  print("")

  for ciphertext in ciphertexts:
    region_decode = hex(int(ciphertext[0:32],16) ^ int(key_0_16,16))[2:]
    print(str(codecs.decode(region_decode,"hex")))

  key_0_33 = hex(int(ciphertexts[0][0:66], 16) ^ int(codecs.encode(b'Testing testing can you read this',"hex"), 16))
  print(key_0_33)
  print(str(codecs.decode(key_0_33[2:],"hex")))
  print("")

  for ciphertext in ciphertexts:
    region_decode = hex(int(ciphertext[0:66],16) ^ int(key_0_33,16))[2:]
    print(str(codecs.decode(region_decode,"hex")))

  print("")

  english_key = "TheQuickBrownFoxJumpsOverLazyDog!"
  hex_key = hex(int(codecs.encode(b'TheQuickBrownFoxJumpsOverLazyDog!', "hex"),16))
  print(hex_key)
  print(str(codecs.decode(hex_key[2:],"hex")))

  for ciphertext in ciphertexts:
    # print(ciphertext)
    # print(str(codecs.decode(ciphertext,"hex")))
    region_decode = hex(int(ciphertext,16) ^ int(hex_key,16))[2:]
    print(str(codecs.decode(region_decode,"hex")))
  
  return english_key


ciphertexts = ["01060134071a170a2c16061909660c0a3305191f143d17151a3541130a64040258",
                "110606230c1917022d1c4f1c0b231f0b6a1c03161c3d1b0406250e1459370e0144",
                "011b0071061d11042c154f070f351c0f2507090353291917523f04190c36061358",
                "070d062407001712620107181b2a0b5828104d11533b1915523c13131636061358",
                "1b06007c01000e0e62020e134e23011b380c1d041a2018451b3f41091c271a1544",
                "241a04320100000e621f0e1c0b354f196a050802152a1511523f04190c36061358",
                "0d071071141b064b23110c1803360311391d041e146f1708133608141e64050843",
                "171a1c21010604192302070e4e2f1c582c141e131a2117111b22065a1f2d0a0b45",
                "000000711d00070f271c4f1a0b351c192d101e50123d13450029171f18280a030f",
                "1907013407074308300b1f0301211d193a1d14501a3c5617173d14130b210b4600"]

print(decrypt(ciphertexts))