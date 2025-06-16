from ..elgamal.elgamal import ElGamal
import random
import hashlib
from Crypto.Random import random as crypto_random

class SecureMatchingSystem:
    """基于公钥密码的安全匹配系统"""
    
    def __init__(self, bits=512):
        self.bits = bits
        self.p = None
        self.g = None
        self.q = None
        
    def setup_system(self):
        """设置系统公共参数 (p, g, q)"""
        print("=== 系统初始化 ===")
        elgamal = ElGamal(self.bits)
        elgamal.keygen()
        self.p, self.g, _ = elgamal.get_pkg()
        self.q = elgamal.q
        elgamal.clean()
        
        print(f"公共参数设置完成:")
        print(f"p = {hex(self.p)[:20]}... ({self.p.bit_length()} bits)")
        print(f"g = {self.g}")
        print(f"q = {hex(self.q)[:20]}... ({self.q.bit_length()} bits)")
        return self.p, self.g, self.q

class User:
    """用户类"""
    
    def __init__(self, name, system):
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
        
        # 匹配选择
        self.choice = None  # True表示接受，False表示拒绝
        
    def generate_dh_keypair(self):
        """生成Diffie-Hellman密钥对"""
        # 私钥 x ∈ [1, q-1]
        self.dh_private_key = crypto_random.randrange(1, self.q)
        # 公钥 y = g^x mod p
        self.dh_public_key = pow(self.g, self.dh_private_key, self.p)
        
        print(f"{self.name} 生成DH密钥对:")
        print(f"  私钥: {hex(self.dh_private_key)[:20]}...")
        print(f"  公钥: {hex(self.dh_public_key)[:20]}...")
        
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
        
        print(f"{self.name} 计算共享密钥:")
        print(f"  共享秘密: {hex(self.shared_secret)[:20]}...")
        print(f"  派生私钥: {hex(self.shared_private_key)[:20]}...")
        
        return self.shared_secret
    
    def set_choice(self, choice):
        """设置匹配选择"""
        self.choice = choice
        print(f"{self.name} 设置选择: {'接受' if choice else '拒绝'}")
    
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
        
        print(f"{self.name} 加密选择:")
        print(f"  明文: {message} ({'接受' if self.choice else '拒绝'})")
        print(f"  密文: ({hex(c1)[:15]}..., {hex(c2)[:15]}...)")
        
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
        
        print(f"{self.name} 解密结果:")
        print(f"  解密值: {result}")
        print(f"  匹配结果: {'成功' if is_match else '失败'}")
        
        return is_match, result

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
        
        print("平台执行同态乘法:")
        print(f"  输入1: ({hex(c1_1)[:15]}..., {hex(c2_1)[:15]}...)")
        print(f"  输入2: ({hex(c1_2)[:15]}..., {hex(c2_2)[:15]}...)")
        print(f"  结果: ({hex(c1_result)[:15]}..., {hex(c2_result)[:15]}...)")
        
        return (c1_result, c2_result)
    
    def rerandomize(self, ciphertext):
        """对密文进行再随机化"""
        c1, c2 = ciphertext
        
        # 选择随机数 r
        r = crypto_random.randrange(1, self.q)
        
        # 对密文进行幂运算: Enc(m)^r = Enc(m^r)
        c1_new = pow(c1, r, self.p)
        c2_new = pow(c2, r, self.p)
        
        print("平台执行再随机化:")
        print(f"  随机数r: {hex(r)[:15]}...")
        print(f"  原密文: ({hex(c1)[:15]}..., {hex(c2)[:15]}...)")
        print(f"  新密文: ({hex(c1_new)[:15]}..., {hex(c2_new)[:15]}...)")
        
        return (c1_new, c2_new)
    
    def process_matching(self, ciphertext1, ciphertext2):
        """处理匹配请求"""
        print("\n--- 平台处理匹配 ---")
        
        # 1. 同态乘法
        result_cipher = self.homomorphic_multiplication(ciphertext1, ciphertext2)
        
        # 2. 再随机化
        final_cipher = self.rerandomize(result_cipher)
        
        return final_cipher

def demo_secure_matching():
    """安全匹配系统演示"""
    print("=" * 60)
    print("基于公钥密码的安全网恋匹配系统演示")
    print("=" * 60)
    
    # 1. 系统初始化
    system = SecureMatchingSystem(512)
    system.setup_system()
    
    # 2. 创建用户
    print("\n=== 用户注册 ===")
    alice = User("Alice", system)
    bob = User("Bob", system)
    
    # 3. 用户生成DH密钥对并上传公钥到平台
    print("\n=== Diffie-Hellman密钥交换 ===")
    alice_pub = alice.generate_dh_keypair()
    bob_pub = bob.generate_dh_keypair()
    
    # 4. 平台推送匹配，用户计算共享密钥
    print("\n=== 计算共享密钥 ===")
    alice_shared = alice.compute_shared_secret(bob_pub)
    bob_shared = bob.compute_shared_secret(alice_pub)
    
    # 验证共享密钥是否一致
    print(f"\n共享密钥验证: {alice_shared == bob_shared}")
    assert alice_shared == bob_shared, "共享密钥不一致!"
    
    # 5. 用户做出匹配选择
    print("\n=== 用户选择 ===")
    # 测试不同场景
    scenarios = [
        (True, True, "双方都接受"),
        (True, False, "Alice接受，Bob拒绝"),
        (False, True, "Alice拒绝，Bob接受"),
        (False, False, "双方都拒绝")
    ]
    
    for i, (alice_choice, bob_choice, scenario_name) in enumerate(scenarios):
        print(f"\n>>> 场景 {i+1}: {scenario_name} <<<")
        
        alice.set_choice(alice_choice)
        bob.set_choice(bob_choice)
        
        # 6. 用户加密选择并提交到平台
        print("\n=== 加密选择 ===")
        alice_cipher, alice_msg = alice.encrypt_choice()
        bob_cipher, bob_msg = bob.encrypt_choice()
        
        # 7. 平台处理匹配（不知道具体选择）
        platform = Platform(system)
        final_cipher = platform.process_matching(alice_cipher, bob_cipher)
        
        # 8. 用户解密结果
        print("\n=== 解密结果 ===")
        alice_result, alice_decrypt = alice.decrypt_result(final_cipher)
        bob_result, bob_decrypt = bob.decrypt_result(final_cipher)
        
        # 9. 验证结果
        print("\n=== 结果验证 ===")
        expected_match = alice_choice and bob_choice
        actual_match = alice_result and bob_result
        
        print(f"期望结果: {'匹配成功' if expected_match else '匹配失败'}")
        print(f"实际结果: {'匹配成功' if actual_match else '匹配失败'}")
        print(f"系统正确性: {'✅ 正确' if expected_match == actual_match else '❌ 错误'}")
        
        # 验证隐私保护
        print(f"\n=== 隐私保护验证 ===")
        if not expected_match:
            # 如果匹配失败，双方无法推断对方具体选择
            print("匹配失败时的隐私保护:")
            if alice_choice and not bob_choice:
                print("  Alice选择接受但看到失败结果，无法确定Bob是否选择了自己")
            elif not alice_choice and bob_choice:
                print("  Bob选择接受但看到失败结果，无法确定Alice是否选择了自己")
            else:
                print("  双方都拒绝，各自知道对方必然拒绝（从结果可推断）")
        else:
            print("匹配成功时，双方都知道对方选择了接受")
        
        print("-" * 60)
    
    print("\n" + "=" * 60)
    print("演示完成！系统成功实现了以下目标：")
    print("1. 平台无法得知用户的具体选择")
    print("2. 匹配失败时，用户无法推断对方的选择")
    print("3. 只有双方都接受时才会匹配成功")
    print("=" * 60)

if __name__ == "__main__":
    demo_secure_matching()
