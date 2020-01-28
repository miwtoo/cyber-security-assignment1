from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
from base64 import b64encode

# Generate 1024-bit RSA key pair (private + public key)
keyPair = RSA.generate(bits=2048)
f = open('rsh_pri.pem','wb')
f.write(keyPair.export_key('PEM'))
f.close()

f = open('rsh_pub.pem','wb')
f.write(keyPair.publickey().export_key('PEM'))
f.close()


# Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
msg = b'0jcS9PCeUj/9XhdnSRNDLy2pFNCzIPsm1LKckQd4kP0='
hash = SHA256.new(msg)
signer = PKCS115_SigScheme(keyPair)
signature = signer.sign(hash)

print("msg with sha256 :", b64encode(hash.digest()).decode())

print("Signature:", binascii.hexlify(signature).decode('utf-8'))

print("Signature:", b64encode(signature).decode('utf-8'))

# Verify valid PKCS#1 v1.5 signature (RSAVP1)
msg = b'0jcS9PCeUj/9XhdnSRNDLy2pFNCzIPsm1LKckQd4kP0='
hash = SHA256.new(msg)
signer = PKCS115_SigScheme(keyPair)

try:
    signer.verify(hash, signature)
    print("Signature is valid.")
except:
    print("Signature is invalid.")