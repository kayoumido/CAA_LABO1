from Crypto.Cipher import AES
from Crypto.Util import strxor


def xor(a, b):
    return strxor.strxor(a, b)

# Converts a 128bit string into a polynomial in GF(2^128)
# x has to be the unknown in the polynomial.


def strToPoly(s, x):
    if len(s) != 16:
        raise Exception("Need 128 bit string")
    res = 0
    for i in range(16):
        res *= x ^ 8
        temp = s[i]
        for j in range(8):
            res += x ^ j * ((temp >> j) & 1)
    return res

# Converts a polynomial in GF(2^128) into a 128 bitstring
def polyToStr(p):
    coefs = p.polynomial().coefficients(sparse=False)
    coefs.reverse()
    res = 0
    for c in coefs:
        res *= 2
        if c == 1:
            res += 1
    resStr = b""
    for i in range(16):
        resStr = (int(res & 0xff)).to_bytes(1, "little") + resStr
        res = res >> 8
    return resStr

# Multiply the 128bit string by the polynomial H.
# Returns a 128bit-string
def multByH(b, H, x):
    p = strToPoly(b, x)
    return polyToStr(p*H)

# Increases by 1 ctr which is a bitstring counter.
def increaseCounter(ctr):
    i = len(ctr) - 1
    while ctr[i] == 255:
        i = i - 1
    res = ctr[:i]+(ctr[i]+int(1)).to_bytes(1, "little")+ctr[i+1:]
    return res


def authenticate(key, ct, T):
    if len(ct) % 16 != 0:
        raise Exception(
            "Error: the content to authenticate need to have a length multiple of 128 bits")
    cipher = AES.new(key, AES.MODE_ECB)
    G.<y> = PolynomialRing(GF(2))  # Ring of polynomials over Z_2
    F.<x> = GF(2^128, modulus = y^128 + y^7 + y^2 + y + 1) #GF(2^128) with the GCM modulus
    H = strToPoly(cipher.encrypt(b"\x00"*16), x)
    tag = b"\x00"*16
    for i in range(len(ct)//16):
        tag = xor(tag, ct[16*i: 16*(i+1)])
        tag = multByH(tag, H, x)
    # Final authentication steps
    # No AD and 64bits for message
    length = b"\x00"*8 + len(ct).to_bytes(8, "little")
    tag = xor(length, tag)
    tag = multByH(tag, H, x)
    tag = xor(tag, T)
    return tag


def CTR(key, IV, m):
    cipher = AES.new(key, AES.MODE_ECB)
    if len(m) % 16 != 0:
        raise Exception(
            "ERROR: the message length has to be a multiple of 128bits")
    if len(IV) != int(12):
        raise Exception("requires 96bit IV")
    ctr = (IV + b"\x00"*3+b"\x02")
    ciphertext = []
    for i in range(len(m)//16):
        # Encrypt bloc
        current = m[16*i: 16*(i+1)]
        res = xor(current, cipher.encrypt(ctr))
        ciphertext.append(res)
        ctr = increaseCounter(ctr)
    return b"".join(ciphertext)


def GCM_Encrypt(key, IV, m):
    """
    Performs the GCM Encryption function whithout AD
    key is the key of 128 bits.
    IV the IV of 96 bits.
    m the message to encrypt. It has to be a multiple of 128 bits.
    Returns a ciphertext and a tag
    """
    ciphertext = CTR(key, IV, m)
    cipher = AES.new(key, AES.MODE_ECB)
    tag = authenticate(key, ciphertext, cipher.encrypt(
        (IV + b"\x00"*3+b"\x01")))
    return (ciphertext, tag)


def GCM_Decrypt(key, IV, c):
    ciphertext, given_tag = c
    cipher = AES.new(key, AES.MODE_ECB)
    tag = authenticate(key, ciphertext, cipher.encrypt(
        (IV + b"\x00"*3+b"\x01")))

    if not given_tag == tag:
        raise Exception("Invalid ciphertext")

    return CTR(key, IV, ciphertext)


def attack():
    pass

def main():
    # Source for message: https://veganipsum.me/
    # message = b"Thai almond milk green pepper Italian linguine puttanesca shaved almonds double dark chocolate blacberies plums salted green tea lime tasty Thai dragon pepper macadamia nut cookies smoky maple tempeh glaze avocado summer chocolate cookie apples peppermint."
    # key     = b"Thirty two byte key for AES 256!"
    # IV      = b"some very IV"

    # encrypted_message = GCM_Encrypt(key, IV, message)
    # decrypted_message = GCM_Decrypt(key, IV, encrypted_message)

    # print(message == decrypted_message)

    m  = b"Thai almond milk green pepper !!"
    k1 = b"Thirty two byte key for AES 256!"
    k2 = b"Fourty foo kyte cey for DES 625!"
    N  = b"\xAB"*12
    
    (ct, tag) = GCM_Encrypt(k1, N, m)

    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    blocks.reverse()

    G.<y> = PolynomialRing(GF(2))  # Ring of polynomials over Z_2
    F.<x> = GF(2^128, modulus = y^128 + y^7 + y^2 + y + 1) #GF(2^128) with the GCM modulus

    cipher = AES.new(k1, AES.MODE_ECB)
    H1 = strToPoly(cipher.encrypt(b"\x00"*16), x)
    A1 = cipher.encrypt((N + b"\x00"*3+b"\x01"))

    cipher = AES.new(k2, AES.MODE_ECB)
    H2 = strToPoly(cipher.encrypt(b"\x00"*16), x)
    A2 = cipher.encrypt((N + b"\x00"*3+b"\x01"))

    ct_len = strToPoly(b"\x00"*8 + (int(len(ct) + 16)).to_bytes(8, "little"), x)
    
    power = 3
    encrypted_free_block = strToPoly(A2, x) + strToPoly(A1, x) + ct_len * (H2 + H1)

    for block in blocks:
        encrypted_free_block = encrypted_free_block + strToPoly(block, x) * (H2**power + H1**power)
        power = power + 1

    encrypted_free_block = polyToStr(encrypted_free_block / (H1**2 + H2**2))
    free_block = CTR(k1, N, encrypted_free_block)

    new_tag = strToPoly(A1, x) + ct_len * H1 + strToPoly(encrypted_free_block, x) * H1**2
    power = 3
    for block in blocks:
        new_tag = new_tag + strToPoly(block, x) * H1**power
        power = power + 1

    new_tag = polyToStr(new_tag)

    ciphertext = b"".join([ct, encrypted_free_block])
    # print(ciphertext)
    # print(ct)
    decrypted_message = GCM_Decrypt(k2, N, (ciphertext, new_tag))
    print(decrypted_message)
    encrypted_message = GCM_Encrypt(k2, N, decrypted_message)
    decrypted_message = GCM_Decrypt(k1, N, encrypted_message)

    print(decrypted_message)
    # ct, tag = Enc(m||stuff)
    # print(b"".join([m, free_block]))

    # encrypted_message = GCM_Encrypt(k1, N, b"".join([m, free_block]))
    # decrypted_message = GCM_Decrypt(k2, N, encrypted_message)

    # m1 = m||bla
    # m2 = someth
    # Enc(m1, N, k1) = Enc(m2, N, k2) = (c, tag)
    # Dec(c, N, k1) = m1
    # Dec(c, N, k2) = m2

if __name__ == '__main__':
    main()
