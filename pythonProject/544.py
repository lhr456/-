import pandas as pd
from sympy import isprime, mod_inverse
import random


class RSA:
    """
    RSA加密算法相关操作的类，包含密钥生成、加密、解密等功能。
    """

    def __init__(self):
        """
        初始化方法，目前无需要初始化的属性，可根据后续扩展需求添加。
        """
        pass

    def generate_prime_vector(self, n, lower_bound=2, upper_bound=1000, max_attempts=10000):
        """
        生成包含n个质数的向量。

        参数:
        - n: 要生成的质数的个数。
        - lower_bound: 生成质数的范围下限，默认为2。
        - upper_bound: 生成质数的范围上限，默认为1000。
        - max_attempts: 生成每个质数时的最大尝试次数，避免无限循环，默认为10000。

        返回:
        - pd.Series: 包含生成的质数的向量，索引为'p{i}'形式，i表示索引位置。
        """
        prime_vector = []
        attempt_count = 0
        while len(prime_vector) < n:
            attempt_count += 1
            if attempt_count > max_attempts:
                raise ValueError(f"在 {max_attempts} 次尝试内无法生成 {n} 个质数，请检查生成范围或尝试次数设置。")
            candidate = random.randint(lower_bound, upper_bound)
            if isprime(candidate):
                prime_vector.append(candidate)
        return pd.Series(prime_vector, index=[f'p{i}' for i in range(len(prime_vector))])

    def calculate_product_vector(self, prime_vector):
        """
        根据给定的质数向量计算乘积向量（n），实现向量中所有质数连乘。

        参数:
        - prime_vector: 包含质数的输入向量。

        返回:
        - pd.Series: 包含连乘结果的向量，索引为['n']。
        """
        product = 1
        for prime in prime_vector:
            product *= prime
        return pd.Series([product], index=['n'])

    def calculate_phi_vector(self, prime_vector):
        """
        根据给定的质数向量计算欧拉函数值向量（m）。

        参数:
        - prime_vector: 包含质数的输入向量。

        返回:
        - pd.Series: 包含欧拉函数值的向量，索引为['m']。
        """
        phi_value = 1
        for prime in prime_vector:
            phi_value *= (prime - 1)
        return pd.Series([phi_value], index=['m'])

    def choose_public_key(self, phi_vector):
        """
        选择公钥向量（e），随机生成一个满足与欧拉函数值互质条件的整数作为公钥。

        参数:
        - phi_vector: 包含欧拉函数值的向量。

        返回:
        - pd.Series: 包含公钥的向量，索引为['e']。
        """
        m = phi_vector['m']
        e = random.randint(2, m - 1)
        while True:
            if self.is_coprime(e, m):
                break
            e = random.randint(2, m - 1)
        return pd.Series([e], index=['e'])

    def is_coprime(self, a, b):
        """
        判断两个数是否互质。

        参数:
        - a: 整数a。
        - b: 整数b。

        返回:
        - bool: 如果a和b互质返回True，否则返回False。
        """
        return self.greatest_common_divisor(a, b) == 1

    def greatest_common_divisor(self, a, b):
        """
        计算两个数的最大公约数，使用欧几里得算法。

        参数:
        - a: 整数a。
        - b: 整数b。

        返回:
        - int: a和b的最大公约数。
        """
        while b!= 0:
            a, b = b, a % b
        return a

    def calculate_private_key(self, public_key_vector, phi_vector):
        """
        计算私钥向量（d），使用mod_inverse计算模逆元。

        参数:
        - public_key_vector: 包含公钥的向量。
        - phi_vector: 包含欧拉函数值的向量。

        返回:
        - pd.Series: 包含私钥的向量，索引为['d']，若无法计算模逆元则返回None。
        """
        try:
            e = public_key_vector['e']
            m = phi_vector['m']
            d = mod_inverse(e, m)
            return pd.Series([d], index=['d'])
        except ValueError:
            print("无法计算模逆元，公钥和phi值可能不符合要求，请检查输入。")
            return None

    def encrypt(self, message, public_key_pair):
        """
        使用公钥对消息进行加密。

        参数:
        - message: 要加密的消息，可以是字符串或者整数列表（如果已经做过预处理）。
        - public_key_pair: 包含公钥（e）和n的向量，索引为['e', 'n']。

        返回:
        - list: 加密后的消息列表，每个元素对应消息中每个部分加密后的结果。
        """
        if isinstance(message, str):
            message_int = [ord(char) for char in message]
        else:
            message_int = message

        encrypted_message = []
        e = public_key_pair['e']
        n = public_key_pair['n']
        for char in message_int:
            try:
                encrypted_char = pow(char, int(e), int(n))
                encrypted_message.append(encrypted_char)
            except:
                print("加密过程出现错误，请检查输入参数或算法实现。")
                return None
        return encrypted_message

    def decrypt(self, encrypted_message, private_key_pair):
        """
        使用私钥对加密后的消息进行解密。

        参数:
        - encrypted_message: 加密后的消息列表。
        - private_key_pair: 包含私钥（d）和n的向量，索引为['d', 'n']。

        返回:
        - str: 解密后的消息字符串，如果输入的是整数列表形式的加密消息，则返回对应的字符组成的字符串。
        """
        decrypted_message_int = []
        d = private_key_pair['d']
        n = private_key_pair['n']
        for char in encrypted_message:
            try:
                decrypted_char = pow(char, int(d), int(n))
                decrypted_message_int.append(decrypted_char)
            except:
                print("解密过程出现错误，请检查输入参数或算法实现。")
                return None

        if all(isinstance(x, int) for x in decrypted_message_int):
            return ''.join(chr(x) for x in decrypted_message_int)
        return decrypted_message_int


if __name__ == "__main__":
    rsa = RSA()

    # 生成质数向量（这里生成3个质数作为示例，可根据需要调整个数）
    prime_vector = rsa.generate_prime_vector(8)
    print("生成的质数向量:", prime_vector)

    # 计算乘积向量（n）
    product_vector = rsa.calculate_product_vector(prime_vector)
    print("乘积向量:", product_vector)

    # 计算欧拉函数值向量（m）
    phi_vector = rsa.calculate_phi_vector(prime_vector)
    print("欧拉函数值向量:", phi_vector)

    # 选择公钥向量（e）
    public_key_vector = rsa.choose_public_key(phi_vector)
    print("公钥向量:", public_key_vector)

    # 计算私钥向量（d）
    private_key_vector = rsa.calculate_private_key(public_key_vector, phi_vector)
    if private_key_vector is not None:
        print("私钥向量:", private_key_vector)

        # 公钥对和私钥对向量
        public_key_pair = pd.Series([public_key_vector['e'], product_vector['n']], index=['e', 'n'])
        private_key_pair = pd.Series([private_key_vector['d'], product_vector['n']], index=['d', 'n'])

        # 要加密的消息
        message = "Hell85988fgf fgfdgfdgfdgfyfo, RSA!"
        print("原始消息:", message)

        # 加密消息
        encrypted_message = rsa.encrypt(message, public_key_pair)
        if encrypted_message is not None:
            print("加密后的消息:", encrypted_message)

            # 解密消息
            decrypted_message = rsa.decrypt(encrypted_message, private_key_pair)
            print("解密后的消息:", decrypted_message)
    else:
        print("私钥生成失败，无法进行加密解密操作。")
