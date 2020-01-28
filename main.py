import json
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from base64 import b64decode
from Crypto.Util.Padding import unpad

from Crypto.Random import get_random_bytes
import codecs

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import binascii

from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme


def encryptionAES(text, modeType = 0):
     # 1 = binary , 0 = text
    # data = b"B5900374 Wongsacorn Chugasem"
    if modeType == 0 :
        data = text.encode()
    else :
        data = text

    # print("data = ")
    # print(codecs.encode(data, 'hex'))
    iv = None
    try :
        f = open("aesKey.json", "x")
        f.close()
        key = get_random_bytes(32)
        
    except FileExistsError :
        f = open("aesKey.json", "r")
        aesKey = json.loads(f.read())
        iv = b64decode(aesKey['iv'])
        key = b64decode(aesKey['key'])
        f.close()
    # key = get_random_bytes(32)
    key64 = b64encode(key).decode('utf-8')
    # print("key = ")
    # print(codecs.encode(key, 'hex'))
    # print(b64encode(key).decode('utf-8'))


    if iv == None :
        cipher = AES.new(key, AES.MODE_CBC)
    else :
        cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))

    iv = b64encode(cipher.iv).decode('utf-8')
    # print("iv = ")
    # print(codecs.encode(cipher.iv, 'hex'))

    ct = b64encode(ct_bytes).decode('utf-8')
    # print("ct = ")
    # print(codecs.encode(ct_bytes, 'hex'))

    # result = json.dumps({"text":text,'key':key64,'iv':iv, 'ciphertext':ct})

    f = open("aesKey.json", "w")
    f.write(json.dumps({'key':key64,'iv':iv}))
    f.close()

    # print(result)
    if modeType == 1 : 
        return ct_bytes
    else :
        return ct

def decryptionAES(text, modeType = 0):

    try :
        f = open("aesKey.json", "x")
        f.close()
        print("Key File Not Found")
        
    except FileExistsError :
        f = open("aesKey.json", "r")
        aesKey = json.loads(f.read())
        iv = b64decode(aesKey['iv'])
        key = b64decode(aesKey['key'])
        f.close()

    try:
        #b64 = json.loads(json_input)
        if modeType == 0 :
            ct = b64decode(text)
        else :
            ct = text
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        #print("The message was: ", pt)
        if modeType == 0 :
            return pt.decode('utf-8')
        else :
            return pt
    except ValueError :
        print("Incorrect ValueError")
    except KeyError :
        print("Incorrect KeyError")

def digital_signature(text) :
    # Generate 1024-bit RSA key pair (private + public key)
    try :
        f = open('rsa_pub.pem','x')
        f = open('rsa_pub.pem','r')
        keyPair = RSA.import_key(f.read())
        f.close()
    except FileExistsError:
        keyPair = RSA.generate(bits=2048)
        f = open('rsa_pri.pem','wb')
        f.write(keyPair.export_key('PEM'))
        f.close()

        f = open('rsa_pub.pem','wb')
        f.write(keyPair.publickey().export_key('PEM'))
        f.close()
    


    # Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
    msg = text.encode()
    hash = SHA256.new(msg)
    signer = PKCS115_SigScheme(keyPair)
    signature = signer.sign(hash)
    #print(signature)

    # print("msg with sha256 :", b64encode(hash.digest()).decode())

    # print("Signature:", binascii.hexlify(signature).decode('utf-8'))

    # print("Signature:", b64encode(signature).decode('utf-8'))
    return b64encode(signature).decode('utf-8')


def verify_signature(signature, text):
    # Verify valid PKCS#1 v1.5 signature (RSAVP1)
    f = open('rsa_pub.pem','r')
    keyPair = RSA.import_key(f.read())
    f.close()
    msg = text.encode()
    hash = SHA256.new(msg)
    signer = PKCS115_SigScheme(keyPair)

    try:
        signer.verify(hash, signature)
        print("Signature is valid.")
    except:
        print("Signature is invalid.")

#my_json = json.loads(encryptionAES("B5900374 Wongsacorn Chugasem"))
#print(my_json)


# print(my_json['ciphertext'])
print("Select Mode")
print("1 Encryption")
print("2 Decryption")
print("3 Verify Signature")

mode = input("Enter Mode: ")
filename = input("Enter file name: ")

if mode == "1" :
    print("Encryption Mode")
    try : 
        f = open(filename, "rt")
        data = encryptionAES(f.read())
        print(data)
        
        f3 = open("lock_" + filename, "wt")
        f3.write(data)
        f3.close()

        f4 = open("lock_sign_" + filename, "wt")
        f4.write(digital_signature(data))
        f4.close()

        f.close()
    except UnicodeDecodeError :
        f = open(filename, "rb")
        data = encryptionAES(f.read() ,1)
        # print(data)
        
        f3 = open("lock_" + filename, "wb")
        f3.write(data)
        f3.close()

        f.close()
    except FileNotFoundError :
        print("File Not Found")

elif mode == "2" :
    print("Decryption Mode")
    try :
        f = open(filename, "rt")
        data = decryptionAES(f.read())
        print(data)
        f2 = open("unlock_" + filename, "wt")
        f2.write(data)
        f2.close()
        f.close()

    except UnicodeDecodeError :
        f = open(filename, "rb")
        data = decryptionAES(f.read(), 1)
        #print(data)
        f2 = open("unlock_" + filename, "wb")
        f2.write(data)
        f2.close()
        f.close()
    except FileNotFoundError : 
        print("File Not Found")

elif mode == "3" :
    original_file = input("Enter signature file :")
    f = open(filename, "rt")
    f2 = open(original_file, "rt")
    verify_signature(b64decode(f.read()), f2.read())
    f2.close()
    f.close()
else :
    print("Wrong")

# f4 = open("picture.png", "rb")
# data = encryptionAES(b64encode(f4.read()).decode('utf-8'))
# my_json = json.loads(data)

# f5 = open("pictureData.json", "wt")
# f5.write(data)
# f5.close()

# f6 = open("pictureEncryption.png", "wb")
# f6.write(my_json['ciphertext'])
# f6.close()

# f4.close()