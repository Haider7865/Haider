#Task 1:


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m

def generate_keys(p=211, q=223, e=17):
    # Using larger primes so messages fit inside modulus
    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        raise ValueError("e and phi(n) must be coprime")

    d = modinv(e, phi)

    return (n, e), (n, d)

# Convert text to integer and back
def text_to_int(msg: str) -> int:
    return int.from_bytes(msg.encode('utf-8'), 'big')

def int_to_text(m: int) -> str:
    try:
        return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
    except:
        return "<decode error>"

def encrypt_integer(m_int: int, pubkey: tuple) -> int:
    n, e = pubkey
    return pow(m_int, e, n)

def decrypt_integer(c_int: int, privkey: tuple) -> int:
    n, d = privkey
    return pow(c_int, d, n)

def encrypt_message(msg: str, pubkey: tuple) -> int:
    m_int = text_to_int(msg)
    if m_int >= pubkey[0]:
        raise ValueError("Message too large for RSA modulus. Use larger primes.")
    return encrypt_integer(m_int, pubkey)

def decrypt_message(cipher_int: int, privkey: tuple) -> str:
    m_int = decrypt_integer(cipher_int, privkey)
    return int_to_text(m_int)

# -------------------------------
# EXAMPLE RUN
# -------------------------------

if __name__ == '__main__':
    public, private = generate_keys()   # uses improved primes
    name = "Alice"                      # now works without error

    print("Public key:", public)
    print("Private key:", private)

    cipher = encrypt_message(name, public)
    print("Encrypted (int):", cipher)

    plain = decrypt_message(cipher, private)
    print("Decrypted text:", plain)


#Task 2:


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generate_rsa_2048():
    key = RSA.generate(2048)
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()
    return private_key_pem, public_key_pem, key

def encrypt_message(message: bytes, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)

def decrypt_message(ciphertext: bytes, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)

if __name__ == '__main__':
    message = b"Hello from COMSATS student"
    priv_pem, pub_pem, keyobj = generate_rsa_2048()
    print("Private key (PEM, trimmed):\n", priv_pem[:200], b"...\n")
    print("Public key (PEM, trimmed):\n", pub_pem[:200], b"...\n")
    pub = keyobj.publickey()
    ciphertext = encrypt_message(message, pub)
    print("Ciphertext (hex):", ciphertext.hex())
    plaintext = decrypt_message(ciphertext, keyobj)
    print("Recovered plaintext:", plaintext.decode('utf-8'))


#Task 3:

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_keypair(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

def sign_message(message: bytes, private_key):
    h = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(message: bytes, signature: bytes, public_key):
    h = SHA256.new(message)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == '__main__':
    msg = b"This message will be signed."
    priv, pub = generate_keypair()
    sig = sign_message(msg, priv)
    print("Signature (hex):", sig.hex())
    ok = verify_signature(msg, sig, pub)
    print("Verification (original message):", ok)
    # modify the message
    msg2 = b"This message will be signed?"
    ok2 = verify_signature(msg2, sig, pub)
    print("Verification (modified message):", ok2)
