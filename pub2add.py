################################################################################
import hashlib
from binascii import hexlify
################################################################################

# base 58 Bitcoin alphabet
b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def encode(b):
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n = int('0x0' + hexlify(b).decode('utf8'), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod (n, 58)
        res.append(b58[r])
    res = ''.join(res[::-1])

    # Encode leading zeros as base58 zeros
    import sys
    czero = b'\x00'
    if sys.version > '3':
        # In Python3 indexing a bytes returns numbers, not characters.
        czero = 0
    pad = 0
    for c in b:
        if c == czero: pad += 1
        else: break
    return b58[0] * pad + res

seed = 'inspire primary subway humble gown walnut odor evoke quality talk '\
        'utility super'
print('seed', seed)

# Public key from a known safely stored private key
# pub_hex = '0400ef6082981b8fc6ea9caf28b77e27d412a50ae11fa05a87dfe29ad4b0eaea9d3'\
        # '48b179bb9e2ef9c61e196082c8e77ce8ac456d47fed20f3274bdcea626910dd'
pub_hex = '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'
pub = bytes.fromhex(pub_hex)
print('pubkey', pub)

# Perform SHA-256 hashing on the public key
m = hashlib.sha256()
m.update(pub)
pub_sha256 = m.digest()
print('pub_sha256', pub_sha256)

# Perform RIPEMD-160 hashing on the result of SHA-256
h = hashlib.new('ripemd160')
h.update(pub_sha256)
pub_double = h.digest()
print('\npub_double', pub_double)

# Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
version_byte = bytes.fromhex('00')
pub_double_full = version_byte + pub_double
print('version bytes added', pub_double_full)

# Perform SHA-256 hash on the extended RIPEMD-160 result
shan1 = hashlib.sha256()
shan1.update(pub_double_full)
shan1 = shan1.digest()
print('\nFirst SHA256:', shan1)

# Perform SHA-256 hash on the result of the previous SHA-256 hash
shan2 = hashlib.sha256()
shan2.update(shan1)
shan2 = shan2.digest()
print('\nSecond SHA256:', shan2)

# Append the first 4 bytes of the second SHA-256 hash (checksum)
# This is the 25-byte binary Bitcoin Address.
checksum = shan2[:4]
twenty5byte = pub_double_full + checksum
print('twenty5byte', twenty5byte)

# Convert the result from a byte string into a base58 string using Base58Check
# encoding.
leg_address = encode(twenty5byte)

# Convert to cashaddress
from cashaddress import convert

address = convert.to_cash_address(leg_address)
print('\n'+address)

