import requests
import json
from Crypto.Util.Padding import pad, unpad


def _is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    print(padding)
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def _xor_blocks(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


data = requests.get('https://aes.cryptohack.org/paper_plane/encrypt_flag/').text
data = json.loads(data)
print(data)
c0 = data['c0']
m0 = data['m0']
ciphertext = data['ciphertext']
c1 = bytes.fromhex(ciphertext[:32])
print(c1)

# b = b''
# m = _xor_blocks(c1, bytes.fromhex(m0))
# while len(b) < 16:
#     size = len(b)
#     for i in range(256):
#         if len(b) == 0 and i == 1:
#             continue
#         send = int.to_bytes((size + 1) ^ c1[15 - size] ^ i)
#         for j in range(size):
#             send += int.to_bytes((size + 1) ^ c1[16 - size + j] ^ b[j])
#         encrypted_flag = (c1[:15 - size] + send).hex() + ciphertext[32:]
#         new_m0 = _xor_blocks(m, bytes.fromhex(encrypted_flag[:32])).hex()
#         # print(len(encrypted_flag))
#         # print(_xor_blocks(bytes.fromhex(encrypted_flag[:32]), bytes.fromhex(new_m0)) == m)
#         data = requests.get(f'https://aes.cryptohack.org/paper_plane/send_msg/{encrypted_flag}/{new_m0}/{c0}/').text
#         if 'msg' in data:
#             b = int.to_bytes(i) + b
#             break
#     print(b)
# b'3gr4m}\n\n\n\n\n\n\n\n\n\n'
b1 = b''
c = bytes.fromhex(c0)
print(c0)
print(ciphertext[:32])
while len(b1) < 16:
    size = len(b1)
    for i in range(32, 128, 1):
        send = int.to_bytes((size + 1) ^ i ^ c[15 - size])
        for j in range(size):
            send += int.to_bytes((size + 1) ^ b1[j] ^ c[16 - size + j])
        new_c0 = (c[:15 - size] + send).hex()
        data = requests.get(f'https://aes.cryptohack.org/paper_plane/send_msg/{ciphertext[:32]}/{m0}/{new_c0}/').text
        if 'msg' in data:
            b1 = int.to_bytes(i) + b1
            break
    print(b1)
# b'crypto{h3ll0_t3l'
