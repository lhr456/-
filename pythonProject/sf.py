import sympy  # 用于判断素数和进行一些数论相关操作
import random


def extended_gcd(a, b):
    """
    扩展欧几里得算法，用于求解ax + by = gcd(a, b)中的x和y
    :param a: 整数a
    :param b: 整数b
    :return: gcd(a, b), x, y
    """
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y


def generate_primes(num_primes, lower_bound=100, upper_bound=1000):
    """
    生成指定个数的大素数
    :param num_primes: 要生成的素数个数
    :param lower_bound: 素数生成范围下限（可调整）
    :param upper_bound: 素数生成范围上限（可调整）
    :return: 包含生成的素数的列表
    """
    primes = []
    while len(primes) < num_primes:
        candidate = random.randint(lower_bound, upper_bound)
        if sympy.isprime(candidate):
            primes.append(candidate)
    return primes


def generate_key_pair(num_primes):
    """
    生成高维拓展的RSA密钥对
    :param num_primes: 选择的素数个数
    :return: 公钥 (e, n) 和私钥 (d, n)
    """
    primes = generate_primes(num_primes)
    n = 1
    for prime in primes:
        n *= prime
    phi_n = 1
    for prime in primes:
        phi_n *= (prime - 1)

    # 选择e，使其与phi_n互质且满足范围要求
    e = random.randint(2, phi_n - 1)
    while sympy.gcd(e, phi_n)!= 1:
        e = random.randint(2, phi_n - 1)

    # 计算私钥d，通过扩展欧几里得算法解同余方程d * e ≡ 1 (mod phi_n)
    gcd, d, _ = extended_gcd(e, phi_n)
    if gcd!= 1:
        raise ValueError("计算私钥时出现问题，e和phi_n不互质")
    while d < 0:
        d += phi_n
    return (e, n), (d, n)


def encrypt(message, public_key):
    """
    使用公钥加密消息
    :param message: 要加密的消息（这里简单处理为整数形式，实际应用中可转换）
    :param public_key: 公钥 (e, n)
    :return: 加密后的密文
    """
    e, n = public_key
    return pow(message, e, n)


def decrypt(ciphertext, private_key):
    """
    使用私钥解密消息
    :param ciphertext: 加密后的密文
    :param private_key: 私钥 (d, n)
    :return: 解密后的消息（整数形式，实际应用中可转换回原始格式）
    """
    d, n = private_key
    return pow(ciphertext, d, n)

# 示例用法，选择3个素数来生成密钥对并进行加密解密操作
if __name__ == "__main__":
    num_primes = 10
    public_key, private_key = generate_key_pair(num_primes)
    print("公钥:", public_key)
    print("私钥:", private_key)
    message = 12341541  # 这里简单示例，实际可处理更复杂消息（需转换为合适整数形式）
    encrypted_message = encrypt(message, public_key)
    print("加密后的消息:", encrypted_message)
    decrypted_message = decrypt(encrypted_message, private_key)
    print("解密后的消息:", decrypted_message)