from Crypto.Util.number import getPrime, isPrime
import random
from ..zk.dlogProof import dlogProof, dlogProofVerify

def generate_safe_prime(bits=512):
    """生成一个安全素数p，使得p-1有大的素因子"""
    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1
        if isPrime(p):
            return p

def find_generator(p):
    """找到模p的生成元"""
    # 对于安全素数p = 2q + 1，生成元的阶为q或2q
    for g in range(2, min(100, p)):
        if pow(g, 2, p) != 1 and pow(g, (p-1)//2, p) != 1:
            return g
    return 2  # 备用选择

def test_basic_functionality():
    """测试基本功能"""
    print("=== 基本功能测试 ===")
    
    # 生成参数
    p = getPrime(512)  # 512位素数
    g = find_generator(p)
    x = random.randint(1, p-2)  # 秘密值
    
    print(f"素数 p: {p}")
    print(f"生成元 g: {g}")
    print(f"秘密值 x: {x}")
    print()
    
    # 生成证明
    print("1. 生成零知识证明...")
    y, proof = dlogProof(x, g, p)
    c, z = proof
    
    print(f"公开值 y = g^x mod p: {y}")
    print(f"证明 (c, z): ({c}, {z})")
    print()
    
    # 验证证明
    print("2. 验证零知识证明...")
    is_valid = dlogProofVerify(y, g, p, proof)
    print(f"验证结果: {'通过' if is_valid else '失败'}")
    print()

def test_multiple_proofs():
    """测试多次证明的一致性"""
    print("=== 多次证明测试 ===")
    
    p = getPrime(256)  # 使用较小的素数加快测试
    g = find_generator(p)
    x = random.randint(1, p-2)
    
    success_count = 0
    total_tests = 10
    
    for i in range(total_tests):
        y, proof = dlogProof(x, g, p)
        is_valid = dlogProofVerify(y, g, p, proof)
        if is_valid:
            success_count += 1
        print(f"测试 {i+1}: {'通过' if is_valid else '失败'}")
    
    print(f"\n成功率: {success_count}/{total_tests} ({100*success_count/total_tests:.1f}%)")
    print()

def test_invalid_proofs():
    """测试无效证明的检测"""
    print("=== 无效证明测试 ===")
    
    p = getPrime(256)
    g = find_generator(p)
    x = random.randint(1, p-2)
    
    # 生成有效证明
    y, (c, z) = dlogProof(x, g, p)
    
    # 测试1: 修改c值
    print("1. 测试修改挑战值c...")
    invalid_c = (c + 1) % (p-1)
    is_valid = dlogProofVerify(y, g, p, (invalid_c, z))
    print(f"修改c后验证结果: {'通过' if is_valid else '失败'} (应该失败)")
    
    # 测试2: 修改z值
    print("2. 测试修改响应值z...")
    invalid_z = (z + 1) % (p-1)
    is_valid = dlogProofVerify(y, g, p, (c, invalid_z))
    print(f"修改z后验证结果: {'通过' if is_valid else '失败'} (应该失败)")
    
    # 测试3: 使用错误的y值
    print("3. 测试错误的公开值y...")
    wrong_y = (y * g) % p
    is_valid = dlogProofVerify(wrong_y, g, p, (c, z))
    print(f"错误y值验证结果: {'通过' if is_valid else '失败'} (应该失败)")
    print()

def test_performance():
    """性能测试"""
    print("=== 性能测试 ===")
    import time
    
    # 测试不同密钥长度的性能
    key_sizes = [256, 512, 1024]
    
    for bits in key_sizes:
        print(f"测试 {bits} 位密钥...")
        
        # 参数生成时间
        start_time = time.time()
        p = getPrime(bits)
        g = find_generator(p)
        x = random.randint(1, p-2)
        param_time = time.time() - start_time
        
        # 证明生成时间
        start_time = time.time()
        y, proof = dlogProof(x, g, p)
        proof_time = time.time() - start_time
        
        # 验证时间
        start_time = time.time()
        is_valid = dlogProofVerify(y, g, p, proof)
        verify_time = time.time() - start_time
        
        print(f"  参数生成: {param_time:.4f}s")
        print(f"  证明生成: {proof_time:.4f}s")
        print(f"  证明验证: {verify_time:.4f}s")
        print(f"  验证结果: {'通过' if is_valid else '失败'}")
        print()

def interactive_demo():
    """交互式演示"""
    print("=== 交互式演示 ===")
    print("这是一个离散对数零知识证明的演示")
    print("证明者想要证明：知道x使得y = g^x mod p，但不透露x的值")
    print()
    
    # 设置参数
    p = getPrime(256)
    g = find_generator(p)
    x = random.randint(1, p-2)
    
    print("系统参数:")
    print(f"  素数 p = {p}")
    print(f"  生成元 g = {g}")
    print()
    
    print("证明者拥有秘密值:")
    print(f"  x = {x}")
    print()
    
    # 计算公开值
    y = pow(g, x, p)
    print("证明者计算并公开:")
    print(f"  y = g^x mod p = {y}")
    print()
    
    print("现在证明者要证明知道x，但不透露x...")
    input("按Enter继续...")
    
    # 生成证明
    print("\n证明者生成零知识证明...")
    y_proof, (c, z) = dlogProof(x, g, p)
    print(f"  挑战值 c = {c}")
    print(f"  响应值 z = {z}")
    print()
    
    # 验证
    print("验证者验证证明...")
    is_valid = dlogProofVerify(y, g, p, (c, z))
    print(f"验证结果: {'证明有效！' if is_valid else '证明无效！'}")
    print()
    
    if is_valid:
        print("✓ 证明者成功证明了知道x，但没有透露x的具体值")
        print("✓ 这就是零知识证明的威力！")
    else:
        print("✗ 证明验证失败")

def main():
    """主函数"""
    print("离散对数零知识证明测试程序")
    print("=" * 50)
    print()
    
    try:
        # 运行所有测试
        test_basic_functionality()
        test_multiple_proofs()
        test_invalid_proofs()
        test_performance()
        interactive_demo()
        
        print("=" * 50)
        print("所有测试完成！")
        
    except Exception as e:
        print(f"测试过程中出现错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()