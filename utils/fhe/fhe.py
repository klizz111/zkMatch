from ..elgamal.elgamal import ElGamal
import random
import hashlib
from Crypto.Random import random as crypto_random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import *

class SecureMatchingSystem:
    
    def __init__(self, bits=512):
        self.bits = bits
        self.p = None
        self.g = None
        self.q = None
        
    def setup_system(self, p, g ,q):
        """设置系统公共参数 (p, g, q)"""
        if p is not None and g is not None and q is not None:
            self.p = p
            self.g = g
            self.q = q
        else:
            elgamal = ElGamal(self.bits)
            elgamal.keygen()
            self.p, self.g, _ = elgamal.get_pkg()
            self.q = elgamal.q
            elgamal.clean()
    
        return self.p, self.g, self.q

class User:
    """用户类"""
    
    def __init__(self, name, system, contact_info=""):
        self.name = name
        self.system = system
        self.p = system.p
        self.g = system.g
        self.q = system.q
        
        # Diffie-Hellman密钥对
        self.dh_private_key = None
        self.dh_public_key = None
        
        # 共享密钥
        self.shared_secret = None
        self.shared_private_key = None
        self.shared_y = None
        
        # 匹配选择
        self.choice = None  # True表示接受，False表示拒绝
        
        # 联系方式
        self.contact_info = contact_info or f"{name}@example.com"
        self.encrypted_contact = None
        self.contact_key_ciphertext = None
        
    def generate_dh_keypair(self):
        """生成Diffie-Hellman密钥对"""
        # 私钥 x ∈ [1, q-1]
        self.dh_private_key = crypto_random.randrange(1, self.q)
        # 公钥 y = g^x mod p
        self.dh_public_key = pow(self.g, self.dh_private_key, self.p)

        return self.dh_public_key
        
    def compute_shared_secret(self, other_public_key):
        """计算共享密钥"""
        # k = other_public_key^my_private_key mod p
        self.shared_secret = pow(other_public_key, self.dh_private_key, self.p)
        
        # 使用哈希函数派生ElGamal私钥
        hash_input = str(self.shared_secret).encode()
        hash_digest = hashlib.sha256(hash_input).digest()
        self.shared_private_key = int.from_bytes(hash_digest[:32], 'big') % self.q
        if self.shared_private_key == 0:
            self.shared_private_key = 1  # 确保私钥不为0
        
        self.shared_y = pow(self.g, self.shared_private_key, self.p)
        
        return self.shared_secret

    def prepare_contact_info(self):
        """准备加密的联系方式"""
        # 生成联系方式加密密钥
        contact_key_int = crypto_random.randrange(1, min(2**128, self.q))
        contact_key_bytes = contact_key_int.to_bytes(32, 'big')
        
        # 使用AES加密联系方式
        cipher = AES.new(contact_key_bytes, AES.MODE_ECB)
        padded_contact = pad(self.contact_info.encode('utf-8'), AES.block_size)
        self.encrypted_contact = cipher.encrypt(padded_contact)
        
        # 使用ElGamal加密联系方式密钥
        k = crypto_random.randrange(1, self.q)
        c1 = pow(self.g, k, self.p)
        c2 = (contact_key_int * pow(self.shared_y, k, self.p)) % self.p
        self.contact_key_ciphertext = (c1, c2)
        
        return self.encrypted_contact, self.contact_key_ciphertext

    def set_choice(self, choice):
        """设置匹配选择"""
        self.choice = choice

    def encrypt_choice(self):
        """加密匹配选择"""
        if self.shared_private_key is None:
            raise ValueError("共享私钥未设置")
        
        # 创建ElGamal实例
        elgamal = ElGamal(self.system.bits)
        elgamal.set_pkg(self.p, self.g, None)
        elgamal.q = self.q
        
        # 计算公钥 h = g^shared_private_key mod p
        public_key = pow(self.g, self.shared_private_key, self.p)
        elgamal.y = public_key
        
        if self.choice:
            # 接受：加密明文 1
            message = 1
        else:
            # 拒绝：加密随机数
            message = crypto_random.randrange(2, self.q)
        
        # 加密
        c1, c2 = elgamal.encrypt(message)
        elgamal.clean()
        
        return (c1, c2), message

    def decrypt_result(self, ciphertext):
        """解密匹配结果"""
        c1, c2 = ciphertext
        
        # 使用共享私钥解密
        s = pow(c1, self.shared_private_key, self.p)
        s_inv = pow(s, -1, self.p)
        result = (c2 * s_inv) % self.p
        
        # 判断结果
        is_match = (result == 1)
        
        return is_match, result
        
    def decrypt_contact_info(self, processed_contact_key_cipher, encrypted_contact):
        """解密联系方式"""
        try:
            c1, c2 = processed_contact_key_cipher
            
            # 解密经过同态处理的密钥密文
            s = pow(c1, self.shared_private_key, self.p)
            s_inv = pow(s, -1, self.p)
            decrypted_value = (c2 * s_inv) % self.p
            
            try:
                contact_key_bytes = decrypted_value.to_bytes(32, 'big')
                cipher = AES.new(contact_key_bytes, AES.MODE_ECB)
                padded_plaintext = cipher.decrypt(encrypted_contact)
                contact_info = unpad(padded_plaintext, AES.block_size).decode('utf-8')
                return contact_info
                    
            except (ValueError, UnicodeDecodeError, OverflowError):
                # 检查解密值是否在有效范围内
                max_valid_key = min(2**128, self.q)
                if decrypted_value < 1 or decrypted_value >= max_valid_key:
                    return None
                else:
                    return None
                
        except Exception:
            return None

class Platform:
    """平台类（第三方）"""
    
    def __init__(self, system):
        self.system = system
        self.p = system.p
        self.g = system.g
        self.q = system.q
    
    def homomorphic_multiplication(self, ciphertext1, ciphertext2):
        """同态乘法运算"""
        c1_1, c2_1 = ciphertext1
        c1_2, c2_2 = ciphertext2
        
        # 同态乘法: Enc(m1) * Enc(m2) = Enc(m1 * m2)
        c1_result = (c1_1 * c1_2) % self.p
        c2_result = (c2_1 * c2_2) % self.p
        
        return (c1_result, c2_result)

    def rerandomize(self, ciphertext):
        """对密文进行再随机化"""
        c1, c2 = ciphertext
        
        # 选择随机数 r
        r = crypto_random.randrange(1, self.q)
        
        # 对密文进行幂运算: Enc(m)^r = Enc(m^r)
        c1_new = pow(c1, r, self.p)
        c2_new = pow(c2, r, self.p)
        
        return (c1_new, c2_new)

    def process_matching(self, ciphertext1, ciphertext2):
        """处理匹配请求"""
        
        # 1. 同态乘法
        result_cipher = self.homomorphic_multiplication(ciphertext1, ciphertext2)
        
        # 2. 再随机化
        final_cipher = self.rerandomize(result_cipher)
        
        return final_cipher
        
    def process_secure_matching(self, user1_data, user2_data):
        """使用同态乘法将匹配结果与联系方式密钥绑定"""
        choice_cipher1, (contact1_encrypted, contact1_key_cipher) = user1_data
        choice_cipher2, (contact2_encrypted, contact2_key_cipher) = user2_data
        
        # 1. 同态乘法处理匹配选择
        result_cipher = self.homomorphic_multiplication(choice_cipher1, choice_cipher2)
        
        # 2. 再随机化匹配结果
        final_result_cipher = self.rerandomize(result_cipher)
        
        # 3. 用匹配结果绑定联系方式密钥
        contact2_key_for_user1 = self.homomorphic_multiplication(final_result_cipher, contact2_key_cipher)
        contact1_key_for_user2 = self.homomorphic_multiplication(final_result_cipher, contact1_key_cipher)
        
        return (final_result_cipher, 
                (contact2_key_for_user1, contact2_encrypted),  # user1获得user2的数据
                (contact1_key_for_user2, contact1_encrypted))  # user2获得user1的数据
