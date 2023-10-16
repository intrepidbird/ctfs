KEY_LENGTH = 10
DATA_LENGTH = 53
MAGIC_NUM = 0x12

keys1 = ["s3cR", "vsct"]
keys2 = ["3ts3", "fvsct"]
keys3 = "iamfr"
keys4 = "now0k"
keys5 = "keyw0"
keys6 = "wkeyw"

keys = ['']*4

encrypted_part1 = [126, 123, 107, 124, 110, 115, 127, 59, 60, 99, 87, 60, 102, 124, 57, 87, 108, 59, 106, 125, 111, 111, 59, 122, 123, 87]
encrypted_part2 = [60, 122, 59, 87, 102, 56, 87, 101, 60, 124, 107, 96, 87, 110, 56, 122, 87, 124, 96, 59, 87, 59, 57, 59, 59, 63, 117]
encrypted = encrypted_part1 + encrypted_part2

keys[0] = keys1[0] + keys2[0]
keys[1] = keys1[1] + keys2[1]
keys[2] = keys3 + keys4
keys[3] = keys5 + keys6

def decrypt_recursive_xor(input, depth=0):
    if depth >= 4:
        return input

    input = decrypt_recursive_xor(input, depth + 1)
    input ^= ord(keys[depth][depth])
    
    return input

def decrypt_real_function(input):
    return input ^ MAGIC_NUM

flag = ""
for i in range(DATA_LENGTH):
    decrypted_char = decrypt_real_function(encrypted[i])
    flag += chr(decrypt_recursive_xor(decrypted_char))

print("decrypted:", flag)

#vsctf{w34k_4nt1_d3bugg3rs_4r3_n0_m4tch_f0r_th3_31337}
