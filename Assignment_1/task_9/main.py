import os
import sys
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


plain1 = "################".encode()
plain2 = "#              #".encode()
plain3 = "#    START     #".encode()
plainX = "#     END      #".encode()
plainStart = [plain1, plain2, plain3, plain2, plain1]
plainEnd = [plain1, plain2, plainX, plain2, plain1]
key = get_random_bytes(16)  # I am not about to tell you!

cipher = AES.new(key, AES.MODE_ECB)


def run_xor(b1, b2):
    if len(b1) != len(b2):
        print("XOR: mismatching length of byte arrays")
        os.exit(-1)

    output = []

    for i in range(0, len(b1)):
        x = b1[i] ^ b2[i]
        t = "%x" % x
        if len(t) == 1:
            t = "0" + t
        output.append(t)
    return "".join(output)


def transcrypt(nonce, input_text):
    enc_nonce = cipher.encrypt(nonce)
    ciphertext = run_xor(enc_nonce, input_text)
    return ciphertext


def encrypt_input_file(filename):
    with open(filename, "r") as infh, open("encrypted.enc", "w") as outfh:
        i = 0
        for line in infh:
            line = line.rstrip("\n")
            nonce = "000000000000000" + str(i)
            res = transcrypt(nonce.encode(), line.encode())
            outfh.write(str(i) + "," + res + "\n")
            i = (i + 1) % 10


def break_input_file(filename):
    # YOUR JOB STARTS HERE
    first_half = []
    second_half = []

    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            line_b = bytes.fromhex(line[2:])
            # split into two halfs in order to xor them with the starting or ending sequence
            if int(line[0]) < 5:
                first_half.append(line_b)
            else:
                second_half.append(line_b)
    result = []
    for i in range(int(len(first_half) / 5)):
        for j in range(5):
            index = (5 * i) + j
            first_half_c1_c2 = run_xor(first_half[j], first_half[index])
            c1_c2_b = bytes.fromhex(first_half_c1_c2)
            result.append(run_xor(c1_c2_b, plainStart[j]))

        for j in range(5):
            index = (5 * i) + j
            second_half_c1_c2 = run_xor(
                second_half[j + len(second_half) - 5], second_half[index]
            )
            c1_c2_b = bytes.fromhex(second_half_c1_c2)
            result.append(run_xor(c1_c2_b, plainEnd[j]))

    with open("decrypted.txt", "w") as outf:
        for entry in result:
            outf.write(bytes.fromhex(entry).decode(errors="replace") + "\n")
    # YOUR JOB ENDS HERE


def main(args):
    if len(args) > 1:
        filename = args[1]
        break_input_file(filename)
    else:
        print("Please provide an file to break!")


if __name__ == "__main__":
    main(sys.argv)
