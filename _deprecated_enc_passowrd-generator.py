import datetime
import base64
import numpy
from Crypto import Random
from Crypto.Cipher import AES
from nacl.public import PrivateKey, PublicKey, SealedBox

def encryptPassword(app_id, key_id, public_key, password, time):

    def parsePkey(key):  # function n(t) {
        n = []  # const n = [];
        for o in range(0, len(key), 2):  # for (let o = 0; o < t.length; o += 2)
            n.append(int(key[o:o + 2], 16))  # n.push(parseInt(t.slice(o, o + 2), 16));
        return n  # return new Uint8Array(n)

    def js_set(list1, arr, pos):
        list1[pos:pos + len(arr)] = arr

    o = 100
    u = o + len(password)

    if 64 != len(public_key):
        print("Invalid Public Key")

    public_key = parsePkey(public_key)
    y = numpy.frombuffer(bytearray(u), dtype=numpy.uint8)
    f = 0
    y[f] = 1
    f += 1
    y[f] = int(key_id)  # Sets 2nd byte to key_id
    f += 1  # Parsed public_key and Array y match with Javascript at this point

    key = Random.get_random_bytes(32)  # = subtle.generateKey 256 bits
    iv = Random.get_random_bytes(12)
    tag_length = 16
    aes = AES.new(key, AES.MODE_GCM, mac_len=tag_length, nonce=iv)
    cipher_text, cipher_tag = aes.encrypt_and_digest(bytearray(password, 'utf-8'))
    cipher_text = cipher_text + cipher_tag
    public_key_seal = PublicKey(bytes(public_key))

    tmp_sealed = SealedBox(public_key_seal)
    sealed = numpy.frombuffer(tmp_sealed.encrypt(bytes(key)), dtype=numpy.uint8)
    y[f] = len(sealed)  # y[f] = 255 & sealed.length
    y[f + 1] = 0  # y[f + 1] = sealed.length >> 8 & 255
    f += 2
    js_set(y, sealed, f)  # y.set(sealed, f)
    f += 32
    f += 48

    s = numpy.frombuffer(cipher_text, dtype=numpy.uint8) # const s = new Uint8Array(ciphertext)
    c = s[-16:]  # const c = s.slice(-16)
    h = s[0:-16]  # const h = s.slice(0, -16)
    js_set(y, c, f)  # y.set(c, f)
    f += 16
    js_set(y, h, f)  # y.set(h, f)

    enc_pass = str(base64.b64encode(y).decode('utf-8')) # let t = btoa(y)

    return '#PWD_INSTAGRAM_BROWSER' + ':' + app_id + ':' + time + ':' + enc_pass


def main():
    APP_ID = '6'
    KEY_ID = '89'
    PUBLIC_KEY = '2e5b022acd391257cec16e261ea9e1c9a4f1680a364e94748f7a9a9905e94c13'
    PASSWORD = 'password'
    time = str(int((datetime.datetime.now().timestamp() * 1000)))

    enc_password = encryptPassword(APP_ID, KEY_ID, PUBLIC_KEY, PASSWORD, time)
    print(enc_password)
