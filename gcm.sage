from Crypto.Cipher import AES
from Crypto.Util import strxor

def xor(a,b):
    return strxor.strxor(a,b)

#Converts a 128bit string into a polynomial in GF(2^128) 
#x has to be the unknown in the polynomial. 
def strToPoly(s,x):
    if len(s) != 16:
        raise Exception("Need 128 bit string")
    res = 0
    for i in range(16):
        res *= x^8
        temp = s[i]
        for j in range(8):
            res += x^j* ((temp >>j)&1)
    return res

#Converts a polynomial in GF(2^128) into a 128 bitstring
def polyToStr(p):
    coefs = p.polynomial().coefficients(sparse=False)
    coefs.reverse()
    res = 0
    for c in coefs:
        res*= 2
        if c == 1:
            res += 1 
    resStr  = b""
    for i in range(16):
        resStr = (int(res & 0xff)).to_bytes(1,"little") + resStr
        res = res >> 8
    return resStr

#Multiply the 128bit string by the polynomial H. 
#Returns a 128bit-string 
def multByH(b,H,x):
    p = strToPoly(b,x)
    return polyToStr(p*H)

#Increases by 1 ctr which is a bitstring counter. 
def increaseCounter(ctr):
    i = len(ctr) - 1
    while ctr[i] == 255 :
        i = i - 1
    res = ctr[:i]+(ctr[i]+int(1)).to_bytes(1,"little")+ctr[i+1:]
    return res

def authenticate(key, ct, T):
    if len(ct)%16 != 0:
        raise Exception("Error: the content to authenticate need to have a length multiple of 128 bits")
    cipher = AES.new(key, AES.MODE_ECB)
    G.<y> = PolynomialRing(GF(2)) #Ring of polynomials over Z_2
    F.<x> = GF(2^128, modulus = y^128 + y^7 + y^2 + y + 1) #GF(2^128) with the GCM modulus
    H = strToPoly(cipher.encrypt(b"\x00"*16), x)
    tag = b"\x00"*16
    for i in range(len(ct)//16):
        tag = xor(tag, ct[16*i: 16*(i+1)])
        tag = multByH(tag, H,x)
    #Final authentication steps
    length = b"\x00"*8 + len(ct).to_bytes(8, "little") #No AD and 64bits for message
    tag = xor(length, tag)
    tag = multByH(tag, H, x)
    tag = xor(tag, T)
    return tag

def CTR(key, IV, m):
    cipher = AES.new(key, AES.MODE_ECB)
    if len(m)%16 != 0:
        raise Exception("ERROR: the message length has to be a multiple of 128bits")
    if len(IV) != int(12):
        raise Exception ("requires 96bit IV")
    ctr = (IV + b"\x00"*3+b"\x02") 
    ciphertext = []
    for i in range(len(m)//16):
        #Encrypt bloc
        current = m[16*i: 16*(i+1)]
        res = xor(current, cipher.encrypt(ctr))
        ciphertext.append(res)
        ctr = increaseCounter(ctr)
    return b"".join(ciphertext)

#Performs the GCM Encryption function whithout AD
#key is the key of 128 bits. 
#IV the IV of 96 bits. 
#m the message to encrypt. It has to be a multiple of 128 bits. 
#Returns a ciphertext and a tag
def GCM_Encrypt(key, IV, m):
    ciphertext = CTR(key, IV, m)
    cipher = AES.new(key, AES.MODE_ECB)
    tag = authenticate(key, ciphertext, cipher.encrypt((IV + b"\x00"*3+b"\x01")))
    return (ciphertext, tag)
