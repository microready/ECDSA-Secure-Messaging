#!/usr/bin/env python3
# John Keenan, MicroReady Inc.
# 5/2/2021

from ecdsa import SigningKey,SECP256k1
import random
import hashlib

msg = b"There, I guess King George will be able to read that without his spectacles!"
altered_msg = b"There, I guess King George will be able to read that with his spectacles!"

print("John Hancock's Message")
print(msg.decode('utf-8'))
print('')
print("John Hancock's Message ( Altered )")
print(altered_msg.decode('utf-8'))
print('')

# generate private and public keys using curve SECP256K1
sk = SigningKey.generate(curve = SECP256k1) # uses NIST192p
sk_string = sk.to_string()
print('Random Private key: ' + sk_string.hex() )
vk = sk.verifying_key
vk_string = vk.to_string()
#print( 'full = ' + vk_string.hex())
vk_hex_string = vk_string.hex()
print('Public key:         ' + vk_hex_string[0:64] + ',' + vk_hex_string[64:128])
print('')

# Hash the message using SHA256
message_hash = hashlib.sha256(msg).digest()
print ('message hash = ' + message_hash.hex())

# Hash the altered message using SHA256
altered_message_hash = hashlib.sha256(altered_msg).digest()
print ('altered message hash = ' + altered_message_hash.hex())

print('')

# sign and verify message hash
print( "Message as sent")
signature = sk.sign(message_hash)
if vk.verify(signature, message_hash):
    print('signed hash is verified => message Integrity and Authenticity confirmed')
else:
    print('signed hash failed to verify')

print('\n***************************************************************************')
# sign and verify message hash with altered message
print( "Message altered")
signature = sk.sign(message_hash)
try:
    if vk.verify(signature, altered_message_hash):
        print('signed hash is verified => message Integrity and Authenticity confirmed')
    else:
        print('signed hash failed to verify')
except:
     print('signed hash failed to verify when message was altered')

print('')
# sign and verify message hash with different private key
print( "Signed with different Private Key")
rk = SigningKey.generate(curve = SECP256k1) # uses NIST192p
rk_string = rk.to_string()
print('New Random Private key: ' + rk_string.hex() )

signature = sk.sign(message_hash)
forged_signature = rk.sign(message_hash)
try:
    if vk.verify(forged_signature, message_hash):
        print('signed hash is verified => message Integrity and Authenticity confirmed')
    else:
        print("signed hash failed to verify with 'forged' signature using different private key")
except:
     print("signed hash failed to verify with 'forged' signature using different private key")
print('\n***************************************************************************')
