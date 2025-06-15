// ElGamal 加密算法 - 浏览器版本
class ElGamal {
    constructor(bits) {
        this.bits = bits;
        this.isCleaned = false;
        this.p = null;
        this.g = null;
        this.y = null;
        this.x = null;
        this.q = null;
        
        // 初始化随机数生成器
        this.initRandom();
    }
    
    destructor() {
        if (!this.isCleaned) {
            this.clean();
        }
    }
    
    // 初始化随机数生成器（浏览器版本）
    initRandom() {
        // 检查是否支持 crypto.getRandomValues
        if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
            this.cryptoRandom = window.crypto;
        } else {
            console.warn('Crypto API not available, using Math.random() (not cryptographically secure)');
            this.cryptoRandom = null;
        }
    }
    
    // 生成随机字节（浏览器版本）
    randomBytes(length) {
        const array = new Uint8Array(length);
        if (this.cryptoRandom) {
            this.cryptoRandom.getRandomValues(array);
        } else {
            // 回退到 Math.random()
            for (let i = 0; i < length; i++) {
                array[i] = Math.floor(Math.random() * 256);
            }
        }
        return array;
    }
    
    // 检查是否为素数 (Miller-Rabin 素性测试)
    isPrime(n, k = 10) {
        if (n === 2n || n === 3n) return true;
        if (n < 2n || n % 2n === 0n) return false;
        
        // 写 n-1 为 d * 2^r
        let d = n - 1n;
        let r = 0;
        while (d % 2n === 0n) {
            d /= 2n;
            r++;
        }
        
        // Miller-Rabin 测试
        for (let i = 0; i < k; i++) {
            const a = this.randomBigInt(2n, n - 2n);
            let x = this.modPow(a, d, n);
            
            if (x === 1n || x === n - 1n) continue;
            
            let composite = true;
            for (let j = 0; j < r - 1; j++) {
                x = this.modPow(x, 2n, n);
                if (x === n - 1n) {
                    composite = false;
                    break;
                }
            }
            
            if (composite) return false;
        }
        
        return true;
    }
    
    // 生成指定位数的随机素数
    getPrime(bits) {
        while (true) {
            const candidate = this.randomBigInt(2n ** BigInt(bits - 1), 2n ** BigInt(bits) - 1n);
            // 确保是奇数
            const oddCandidate = candidate | 1n;
            if (this.isPrime(oddCandidate)) {
                return oddCandidate;
            }
        }
    }
    
    // 生成安全素数 p = 2q + 1
    genSafePrime(bits) {
        while (true) {
            // 生成素数 q
            const q = this.getPrime(bits - 1);
            const p = 2n * q + 1n;
            
            // 检查 p 是否为素数
            if (this.isPrime(p)) {
                return { p, q };
            }
        }
    }
    
    // 生成指定范围内的随机大整数（修改为使用浏览器API）
    randomBigInt(min, max) {
        const range = max - min + 1n;
        const bitLength = range.toString(2).length;
        const byteLength = Math.ceil(bitLength / 8);
        
        while (true) {
            const randomBytes = this.randomBytes(byteLength);
            let randomBigInt = 0n;
            
            for (let i = 0; i < randomBytes.length; i++) {
                randomBigInt = (randomBigInt << 8n) + BigInt(randomBytes[i]);
            }
            
            randomBigInt = randomBigInt % range;
            const result = min + randomBigInt;
            
            if (result <= max) {
                return result;
            }
        }
    }
    
    // 快速模幂运算
    modPow(base, exponent, modulus) {
        if (modulus === 1n) return 0n;
        
        let result = 1n;
        base = base % modulus;
        
        while (exponent > 0n) {
            if (exponent % 2n === 1n) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1n;
            base = (base * base) % modulus;
        }
        
        return result;
    }
    
    // 扩展欧几里得算法求模逆
    modInverse(a, m) {
        if (m === 1n) return 0n;
        
        const m0 = m;
        let x0 = 0n, x1 = 1n;
        
        while (a > 1n) {
            const q = a / m;
            let t = m;
            
            m = a % m;
            a = t;
            t = x0;
            
            x0 = x1 - q * x0;
            x1 = t;
        }
        
        if (x1 < 0n) x1 += m0;
        return x1;
    }
    
    // 生成密钥对
    keygen() {
        // 1. 生成素数 p = 2q + 1
        const { p, q } = this.genSafePrime(this.bits);
        this.p = p;
        this.q = q;
        
        // 2. 选取生成元 g
        while (true) {
            // 生成随机数 h ∈ [2, p-1]
            const h = this.randomBigInt(2n, this.p - 1n);
            
            // g = h^2 mod p
            this.g = this.modPow(h, 2n, this.p);
            if (this.g > 1n) {
                break;
            }
        }
        
        // 3. 生成私钥 x ∈ [1, q-1]
        this.x = this.randomBigInt(1n, this.q - 1n);
        
        // 4. 计算公钥 y = g^x mod p
        this.y = this.modPow(this.g, this.x, this.p);
    }
    
    // 生成私钥
    generatePrivateKey() {
        this.q = (this.p - 1n) / 2n;
        
        // 生成私钥 x ∈ [1, q-1]
        this.x = this.randomBigInt(1n, this.q - 1n);
    }
    
    // 设置公钥参数
    setPKG(p, g, y) {
        this.p = BigInt(p);
        this.g = BigInt(g);
        this.y = BigInt(y);
    }
    
    // 初始化 x
    initX() {
        this.x = this.randomBigInt(1n, this.p - 1n);
    }
    
    // 获取公钥参数
    getPKG() {
        return {
            p: this.p,
            g: this.g,
            y: this.y
        };
    }
    
    // 加密消息
    encrypt(m) {
        m = BigInt(m);
        
        try {
            this.checkM(m);
        } catch (error) {
            throw error;
        }
        
        // 生成随机数 k ∈ [1, q-1]
        const k = this.randomBigInt(1n, this.q - 1n);
        
        // c1 = g^k mod p
        const c1 = this.modPow(this.g, k, this.p);
        
        // c2 = m * y^k mod p
        const c2 = (m * this.modPow(this.y, k, this.p)) % this.p;
        
        return { c1, c2 };
    }
    
    // 解密消息
    decrypt(c1, c2) {
        c1 = BigInt(c1);
        c2 = BigInt(c2);
        
        // s = c1^x mod p
        const s = this.modPow(c1, this.x, this.p);
        
        // m = c2 * s^(-1) mod p
        const sInv = this.modInverse(s, this.p);
        const m = (c2 * sInv) % this.p;
        
        return m;
    }
    
    // 清理资源
    clean() {
        this.p = null;
        this.g = null;
        this.y = null;
        this.x = null;
        this.q = null;
        this.isCleaned = true;
    }
    
    // 生成随机消息 m ∈ [2, q-1]
    getM() {
        return this.randomBigInt(2n, this.q - 1n);
    }
    
    // 检查消息是否有效
    checkM(m) {
        if (m >= this.p || m < 2n) {
            throw new Error("Invalid message: m must be in [2, p-1]");
        }
    }
}

// 浏览器环境下的全局暴露
if (typeof window !== 'undefined') {
    window.ElGamal = ElGamal;
}