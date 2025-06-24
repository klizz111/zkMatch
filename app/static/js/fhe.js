class FHE {
    constructor(name) {
        this.name = name;
        this.p = null;
        this.q = null;
        this.g = null;

        this.contact_info = '';

        this.dh_private_key = null;
        this.dh_public_key = null;

        this.shared_secret = null;
        this.shared_private_key = null;
        this.shared_y = null;

        this.choice = null;

        this.encrypted_contact = null;
        this.contact_key_ciphertext = null;

        
    }

    // setup(p, q, g) {
    setup(p, q, g) {
        this.p = BigInt(p);
        this.q = BigInt(q);
        this.g = BigInt(g);
    }

    // 从seed生成dh密钥对
    async generate_dh_key_pair(seed) {
        const derivePrivateKey = async (seed) => {
            const encoder = new TextEncoder();
            const data = encoder.encode(seed + this.p.toString() + this.g.toString() + this.q.toString());
            
            let hashBuffer = await crypto.subtle.digest('SHA-512', data);  
            
            const hashArray = new Uint8Array(hashBuffer);
            
            // 将哈希转换为大整数
            let x = 0n;
            for (let i = 0; i < hashArray.length; i++) {
                x = (x << 8n) + BigInt(hashArray[i]);
            }
            
            // 确保私钥在正确范围内 [1, q-1]
            return (x % (this.q - 1n)) + 1n;
        };
        this.dh_private_key = await derivePrivateKey(seed);
    }

    // 计算共享密钥
    async compute_shared_secret(other_public_key) {
        // k = other_public_key^my_private_key mod p
        this.shared_secret = this.modPow(BigInt(other_public_key), this.dh_private_key, this.p);
        
        // 使用哈希函数派生ElGamal私钥
        const hash_input = this.shared_secret.toString();
        const encoder = new TextEncoder();
        const data = encoder.encode(hash_input);
        
        // 使用SHA-256哈希
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);
        
        // 将哈希的前32字节转换为大整数
        let shared_private_key_int = 0n;
        for (let i = 0; i < 32 && i < hashArray.length; i++) {
            shared_private_key_int = (shared_private_key_int << 8n) + BigInt(hashArray[i]);
        }
        
        this.shared_private_key = shared_private_key_int % this.q;
        if (this.shared_private_key === 0n) {
            this.shared_private_key = 1n; // 确保私钥不为0
        }
        
        this.shared_y = this.modPow(this.g, this.shared_private_key, this.p);
        
        console.log(`${this.name} 计算共享密钥:`);
        console.log(`  派生私钥: ${this.shared_private_key.toString(16).substring(0, 20)}...`);
        
        return this.shared_secret;
    }
    
    // 辅助函数：模幂运算
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

    // 生成加密随机数
    generateSecureRandom(min, max) {
        const range = max - min;
        const bitsNeeded = range.toString(2).length;
        const bytesNeeded = Math.ceil(bitsNeeded / 8);
        
        let randomValue;
        do {
            const randomBytes = new Uint8Array(bytesNeeded);
            crypto.getRandomValues(randomBytes);
            
            randomValue = 0n;
            for (let i = 0; i < randomBytes.length; i++) {
                randomValue = (randomValue << 8n) + BigInt(randomBytes[i]);
            }
            randomValue = randomValue % range;
        } while (randomValue >= range);
        
        return min + randomValue;
    }

    // 加密联系方式
    async prepare_contact_info(contact_info) {
        this.contact_info = contact_info;
        
        // 1. 生成联系方式加密密钥（选择较小的密钥空间以适合ElGamal）
        // 使用128位密钥，确保在ElGamal参数范围内
        const maxKey = 2n ** 128n < this.q ? 2n ** 128n : this.q;
        const contact_key_int = this.generateSecureRandom(1n, maxKey);
        
        // 将密钥转换为32字节的Uint8Array
        const contact_key_bytes = new Uint8Array(32);
        let key_temp = contact_key_int;
        for (let i = 31; i >= 0; i--) {
            contact_key_bytes[i] = Number(key_temp & 0xFFn);
            key_temp = key_temp >> 8n;
        }
        
        // 2. 使用AES-ECB加密联系方式
        const key = await crypto.subtle.importKey(
            'raw',
            contact_key_bytes,
            { name: 'AES-ECB' },
            false,
            ['encrypt']
        );
        
        // PKCS7填充
        const contactBytes = new TextEncoder().encode(contact_info);
        const blockSize = 16;
        const paddingLength = blockSize - (contactBytes.length % blockSize);
        const paddedContact = new Uint8Array(contactBytes.length + paddingLength);
        paddedContact.set(contactBytes);
        for (let i = contactBytes.length; i < paddedContact.length; i++) {
            paddedContact[i] = paddingLength;
        }
        
        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: 'AES-ECB' },
            key,
            paddedContact
        );
        this.encrypted_contact = new Uint8Array(encryptedBuffer);
        
        // 3. 使用ElGamal加密联系方式密钥
        const k = this.generateSecureRandom(1n, this.q);
        const c1 = this.modPow(this.g, k, this.p);
        const c2 = (contact_key_int * this.modPow(this.shared_y, k, this.p)) % this.p;
        this.contact_key_ciphertext = [c1, c2];
        
        console.log(`${this.name} 准备联系方式:`);
        console.log(`  联系方式: ${contact_info}`);
        console.log(`  AES加密后长度: ${this.encrypted_contact.length} bytes`);
        console.log(`  密钥明文: ${contact_key_int}`);
        console.log(`  密钥ElGamal密文: (${c1.toString(16).substring(0, 15)}..., ${c2.toString(16).substring(0, 15)}...)`);
        
        return [this.encrypted_contact, this.contact_key_ciphertext];
    }

    set_choice(choice) {
        this.choice = choice;
    }
    
    async encrypt_choice() {
        /**加密匹配选择*/
        if (this.shared_private_key === null) {
            throw new Error("共享私钥未设置");
        }
        
        let message;
        if (this.choice) {
            // 接受：加密明文 1
            message = 1n;
        } else {
            // 拒绝：加密随机数
            message = this.generateSecureRandom(2n, this.q);
        }
        
        // 使用ElGamal加密
        const k = this.generateSecureRandom(1n, this.q);
        const c1 = this.modPow(this.g, k, this.p);
        const c2 = (message * this.modPow(this.shared_y, k, this.p)) % this.p;
        
        console.log(`${this.name} 加密选择:`);
        console.log(`  明文: ${message} (${this.choice ? '接受' : '拒绝'})`);
        console.log(`  密文: (${c1.toString(16).substring(0, 15)}..., ${c2.toString(16).substring(0, 15)}...)`);
        
        return [[c1, c2], message];
    }
    
    decrypt_result(ciphertext) {
        /**解密匹配结果*/
        const [c1, c2] = ciphertext;
        
        // 使用共享私钥解密
        const s = this.modPow(c1, this.shared_private_key, this.p);
        const s_inv = this.modInverse(s, this.p);
        const result = (c2 * s_inv) % this.p;
        
        // 判断结果
        const is_match = (result === 1n);
        
        console.log(`${this.name} 解密结果:`);
        console.log(`  解密值: ${result}`);
        console.log(`  匹配结果: ${is_match ? '成功' : '失败'}`);
        
        return [is_match, result];
    }
    
    modInverse(a, m) {
        /**计算模逆元 a^(-1) mod m*/
        // 扩展欧几里得算法
        const extgcd = (a, b) => {
            if (a === 0n) return [b, 0n, 1n];
            const [gcd, x1, y1] = extgcd(b % a, a);
            const x = y1 - (b / a) * x1;
            const y = x1;
            return [gcd, x, y];
        };
        
        const [gcd, x, y] = extgcd(a % m, m);
        if (gcd !== 1n) {
            throw new Error("模逆元不存在");
        }
        return (x % m + m) % m;
    }
        
    async decrypt_contact_info(contact_key_ciphertext, encrypted_contact, match_result) {
        /**解密对方的联系方式（仅在匹配成功时有效）*/
        // 首先检查匹配是否成功
        if (!match_result) {
            console.log(`  ${this.name}: 匹配失败，拒绝解密联系方式`);
            return null;
        }
        
        try {
            const [c1, c2] = contact_key_ciphertext;
            
            // 解密联系方式密钥
            const s = this.modPow(c1, this.shared_private_key, this.p);
            const s_inv = this.modInverse(s, this.p);
            const contact_key_int = (c2 * s_inv) % this.p;
            
            console.log(`  ${this.name}: 解密得到密钥数值: ${contact_key_int}`);
            
            // 将解密得到的数值转换为字节
            try {
                // 限制在128位范围内
                if (contact_key_int > 2n ** 128n) {
                    console.log(`  ${this.name}: 解密得到的密钥数值过大`);
                    return null;
                }
                
                // 将BigInt转换为32字节的Uint8Array
                const contact_key_bytes = new Uint8Array(32);
                let key_temp = contact_key_int;
                for (let i = 31; i >= 0; i--) {
                    contact_key_bytes[i] = Number(key_temp & 0xFFn);
                    key_temp = key_temp >> 8n;
                }
            } catch (e) {
                console.log(`  ${this.name}: 密钥转换失败 - ${e.message}`);
                return null;
            }
            
            // 使用解密的密钥尝试解密联系方式
            try {
                const key = await crypto.subtle.importKey(
                    'raw',
                    contact_key_bytes,
                    { name: 'AES-ECB' },
                    false,
                    ['decrypt']
                );
                
                const decryptedBuffer = await crypto.subtle.decrypt(
                    { name: 'AES-ECB' },
                    key,
                    encrypted_contact
                );
                
                // PKCS7去填充
                const paddedPlaintext = new Uint8Array(decryptedBuffer);
                const paddingLength = paddedPlaintext[paddedPlaintext.length - 1];
                
                // 验证填充是否有效
                if (paddingLength > 16 || paddingLength < 1) {
                    throw new Error("无效的填充");
                }
                
                for (let i = paddedPlaintext.length - paddingLength; i < paddedPlaintext.length; i++) {
                    if (paddedPlaintext[i] !== paddingLength) {
                        throw new Error("填充验证失败");
                    }
                }
                
                const contact_bytes = paddedPlaintext.slice(0, paddedPlaintext.length - paddingLength);
                const contact_info = new TextDecoder('utf-8').decode(contact_bytes);
                
                console.log(`  ${this.name}: 成功解密对方联系方式`);
                return contact_info;
            } catch (e) {
                console.log(`  ${this.name}: 联系方式解密失败 - ${e.message}`);
                return null;
            }
            
        } catch (e) {
            console.log(`  ${this.name}: 联系方式解密异常 - ${e.message}`);
            return null;
        }
    }
    
}