import random
import time
from Crypto.Util import number
from Crypto.Random import random as crypto_random

class ElGamal:
    def __init__(self, bits = 256):
        self.bits = bits
        self.is_cleaned = False
        self.p = None
        self.g = None
        self.y = None
        self.x = None
        self.q = None
        
        # 初始化随机数生成器
        seed = int(time.time() * 1000000) ^ id(self) ^ random.getrandbits(32)
        random.seed(seed)
    
    def __del__(self):
        if not self.is_cleaned:
            self.clean()
    
    def gen_safe_prime(self, bits):
        """生成安全素数 p = 2q + 1"""
        while True:
            # 生成素数 q
            q = number.getPrime(bits - 1)
            p = 2 * q + 1
            
            # 检查 p 是否为素数
            if number.isPrime(p):
                return p, q
    
    def keygen(self):
        """生成密钥对"""
        # 1. 生成素数 p = 2q + 1
        self.p, self.q = self.gen_safe_prime(self.bits)
        
        # 2. 选取生成元 g
        while True:
            # 生成随机数 h ∈ [2, p-1]
            h = crypto_random.randrange(2, self.p)
            
            # g = h^2 mod p
            self.g = pow(h, 2, self.p)
            if self.g > 1:
                break
        
        # 3. 生成私钥 x ∈ [1, q-1]
        self.x = crypto_random.randrange(1, self.q)
        
        # 4. 计算公钥 y = g^x mod p
        self.y = pow(self.g, self.x, self.p)
    
    def generate_private_key(self):
        """生成私钥"""
        self.q = (self.p - 1) // 2
        
        # 生成私钥 x ∈ [1, q-1]
        self.x = crypto_random.randrange(1, self.q)
        
        # 刷新公钥 y
        self.y = pow(self.g, self.x, self.p)
    
    def set_pkg(self, p, g, y):
        """设置公钥参数"""
        self.p = p
        self.g = g
        self.y = y
    
    def init_x(self):
        """初始化 x"""
        self.x = crypto_random.randrange(1, self.p)
    
    def get_pkg(self):
        """获取公钥参数"""
        return self.p, self.g, self.y
    
    def encrypt(self, m):
        """加密消息"""
        try:
            self.check_m(m)
        except ValueError as e:
            raise e
        
        # 生成随机数 k ∈ [1, q-1]
        k = crypto_random.randrange(1, self.q)
        
        # c1 = g^k mod p
        c1 = pow(self.g, k, self.p)
        
        # c2 = m * y^k mod p
        c2 = (m * pow(self.y, k, self.p)) % self.p
        
        return c1, c2
    
    def decrypt(self, c1, c2):
        """解密消息"""
        # s = c1^x mod p
        s = pow(c1, self.x, self.p)
        
        # m = c2 * s^(-1) mod p
        s_inv = pow(s, -1, self.p)
        m = (c2 * s_inv) % self.p
        
        return m
    
    def clean(self):
        """清理资源"""
        self.p = None
        self.g = None
        self.y = None
        self.x = None
        self.q = None
        self.is_cleaned = True
    
    def get_m(self):
        """生成随机消息 m ∈ [2, q-1]"""
        return crypto_random.randrange(2, self.q)
    
    def check_m(self, m):
        """检查消息是否有效"""
        if m >= self.p or m < 1:  
            raise ValueError(f"Invalid message: m must be in [1, p-1], got {m}")
        if m == 0:
            raise ValueError("Message cannot be 0")

# 使用示例
if __name__ == "__main__":
    # 创建 ElGamal 实例
    elgamal = ElGamal(512)  # 512 位
    
    # 生成密钥
    elgamal.keygen()
    
    # 打印公钥参数
    p, g, y = elgamal.get_pkg()
    print(f"p = {p}")
    print(f"g = {g}")
    print(f"y = {y}")
    
    # 生成消息
    message = elgamal.get_m()
    print(f"Original message: {message}")
    
    # 加密
    c1, c2 = elgamal.encrypt(message)
    print(f"Encrypted: c1 = {c1}, c2 = {c2}")
    
    # 解密
    decrypted = elgamal.decrypt(c1, c2)
    print(f"Decrypted message: {decrypted}")
    
    # 验证
    print(f"Encryption/Decryption successful: {message == decrypted}")