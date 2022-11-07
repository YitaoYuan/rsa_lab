#
# 袁一滔 YitaoYuan 1900012803
#

import sys
import getopt
import random
import math

def power_with_modulo(x, pw, mod):
    assert(pw >= 0 and mod >= 0 and x >= 0)
    res = 1
    while pw:
        if pw & 1:
            res = res * x % mod
        x = x * x % mod
        pw >>= 1
    return res

# def is_prime2(p):
#     for i in range(2, int(math.sqrt(p) + 1.01)):
#         if p % i == 0:
#             return False
#     return True

def miller_rabin_test(p, a):
    phi = p - 1
    cnt = 0
    while (phi & 1) == 0:
        phi >>= 1
        cnt += 1
    power_a = power_with_modulo(a, phi, p)
    for _ in range(cnt):
        next_power_a = power_a * power_a % p
        if next_power_a == 1 and not (power_a == 1 or power_a == p - 1):
            return False
        power_a = next_power_a
    return power_a == 1


def is_prime(p):
    primes = [  
        2 ,3 ,5 ,7 ,11,13,17,19,23,29,
        31,37,41,43,47,53,59,61,67,71,
        73,79,83,89,97
    ]
    if p in primes:
        return True
    if p < primes[-1]:
        return False
    for i in primes:
        if p % i == 0:
            return False
    for i in primes:
        if miller_rabin_test(p, i) == False:
            return False
    return True

def gen_random(require_carry, bit_len):
    if require_carry:
        # 1.5 ~ 2 * 2**(bit_len-1)
        return random.randint(3 << (bit_len - 2), (1 << bit_len) - 1)
    else:
        # 1 ~ 1.375 * 2**(bit_len-1)
        return random.randint(1 << (bit_len - 1), 11 << (bit_len - 4))

def gen_prime(require_carry, bit_len):
    while True:
        p = gen_random(require_carry, bit_len)
        if is_prime(p):
            return p


def gen_pq(require_carry, bit_len):
    p = gen_prime(require_carry, bit_len)
    q = gen_prime(require_carry, bit_len)
    while p == q:
        q = gen_prime(require_carry, bit_len)
    return (p, q)

# kx * y + ky * (x % y) == g
# kx * y + ky * (x - x//y*y) == g
# ky * x + (kx - x//y*ky) * y == g

def exgcd(x, y):
    if y == 0:
        return (1, 0, x)
    kx, ky, gcd = exgcd(y, x%y) 
    return (ky, kx - x//y*ky, gcd)

def get_inv(x, mod):
    k1, k2, gcd = exgcd(x, mod)
    if gcd == 1:
        return (k1 % mod + mod) % mod
    return 0

def select_ed(phi_n):
    while True:
        e = random.randint(phi_n >> 1, phi_n - 1)
        d = get_inv(e, phi_n)
        if d != 0:
            return e, d

def gen_key(bit_len):
    if bit_len < 14:
        print("Bit length is too small.")
        sys.exit(0)
    
    p, q = gen_pq((bit_len & 1) ^ 1, (bit_len + 1)// 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e, d = select_ed(phi_n)
    print("Public key:")
    print("n = {}".format(n))
    print("e = {}".format(e))
    print("Private key:")
    print("p = {}".format(p))
    print("q = {}".format(q))
    print("d = {}".format(d))

def encrypt_or_decrypt(data, power, modulo):
    split_data = []
    while data:
        split_data.append(data % (modulo-1) + 1) # [1, modulo-1]
        data //= (modulo-1)

    split_data = [power_with_modulo(x, power, modulo) for x in split_data]

    data = 0
    for x in split_data: # x is in [1, modulo-1]
        data = data * (modulo-1) + (x - 1)
    print(data)

def usage():
    print("Usage: python3 rsa.py [-h|--help]                   Show this help.")
    print("       python3 rsa.py -g <bit length>               Generate RSA keys.")
    print("       python3 rsa.py {-e|-d} <int> -n <int> <int, plaintext or ciphertext>");
    print("                                                    Encrypt or decrypt.")

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hg:e:d:n:", ["help"])
    except getopt.GetoptError:
        usage()
        sys.exit(1)
    
    help_flag = gen_flag = encrypt_flag = decrypt_flag = modulo_flag = False

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help_flag = True
        elif opt == "-g":
            gen_flag = True
            gen_bit_len = int(arg)
            assert(gen_bit_len > 0)
        elif opt == "-e":
            encrypt_flag = True
            power = int(arg)
            assert(power > 0)
        elif opt == "-d":
            decrypt_flag = True
            power = int(arg)
            assert(power > 0)
        elif opt == "-n":
            modulo_flag = True
            modulo = int(arg)
            assert(modulo > 0)

    if help_flag:
        usage()
        sys.exit(0)
    elif gen_flag:
        if encrypt_flag or decrypt_flag or modulo_flag or len(args) != 0:
            usage()
            sys.exit(1)
    elif encrypt_flag:
        if decrypt_flag or not modulo_flag or len(args) != 1:
            usage()
            sys.exit(1)
    elif decrypt_flag:
        if not modulo_flag or len(args) != 1:
            usage()
            sys.exit(1)
        
    if gen_flag:
        gen_key(gen_bit_len)
    elif encrypt_flag or decrypt_flag:
        data = int(args[0])
        assert(data > 0)
        encrypt_or_decrypt(data, power, modulo)
    else:
        usage()
        
main()