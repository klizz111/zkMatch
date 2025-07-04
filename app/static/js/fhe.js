/**
 * AES-ECB模式加密函数
 * @param {string} plaintext - 要加密的明文字符串
 * @param {bigint} contact_key_int - 用作密钥的大整数
 * @returns {string} 加密后的十六进制字符串
 */
function aes_enc_ecb(plaintext, contact_key_int) {
    // 将BigInt转换为16字节的Uint8Array (AES-128)
    const contact_key_bytes = new Uint8Array(16);
    let key_temp = contact_key_int;
    for (let i = 15; i >= 0; i--) {
        contact_key_bytes[i] = Number(key_temp & 0xFFn);
        key_temp = key_temp >> 8n;
    }
    
    // 转换为CryptoJS格式的密钥
    const keyHex = Array.from(contact_key_bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    const key = CryptoJS.enc.Hex.parse(keyHex);
    
    // 使用ECB模式加密，PKCS7填充
    const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    
    // 测试解密
    // console.log(`plaintext: ${contact_key_bytes}`);
    const decrypted = aes_dec_ecb(encrypted.ciphertext.toString(), contact_key_int);
    if (decrypted !== plaintext) {
        console.error("AES解密验证失败，可能是加密或解密过程中出现问题");
    } else {
        console.log("AES解密验证成功");
        console.log(`解密结果: ${decrypted}`);
    }
    // 返回加密后的十六进制字符串
    return encrypted.ciphertext.toString();
}

/**
 * AES-ECB模式解密函数
 * @param {string} ciphertext - 要解密的十六进制密文字符串
 * @param {bigint} contact_key_int - 用作密钥的大整数
 * @returns {string} 解密后的明文字符串
 */
function aes_dec_ecb(ciphertext, contact_key_int) {
    // 将BigInt转换为16字节的Uint8Array (AES-128)'
    console.log("call aes_dec_ecb");
    console.log(`contact_key_int: ${contact_key_int}`);
    console.log(`ciphertext: ${ciphertext}`);
    const contact_key_bytes = new Uint8Array(16);
    let key_temp = contact_key_int;
    for (let i = 15; i >= 0; i--) {
        contact_key_bytes[i] = Number(key_temp & 0xFFn);
        key_temp = key_temp >> 8n;
    }
    
    // 转换为CryptoJS格式的密钥
    const keyHex = Array.from(contact_key_bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    const key = CryptoJS.enc.Hex.parse(keyHex);
    
    // 将十六进制密文转换为CryptoJS格式
    const ciphertextObj = CryptoJS.enc.Hex.parse(ciphertext);
    
    // 解密
    const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: ciphertextObj },
        key,
        {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        }
    );
    
    // 返回解密后的明文字符串
    return decrypted.toString(CryptoJS.enc.Utf8);
}

class FHE {
    constructor(name) {
        this.name = name;
        console.log(`${this.name} call FHE constructor`);

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

    // 从localStorage加载参数
    load_params() {
        this.p = BigInt(localStorage.getItem(`system_p`));
        this.q = BigInt(localStorage.getItem(`system_q`));
        this.g = BigInt(localStorage.getItem(`system_g`));
        let seed = localStorage.getItem(`zk_login_seed_${this.name}`);
        this.generate_dh_key_pair(seed);
        console.log(`${this.name} 加载参数: p=${this.p}, q=${this.q}, g=${this.g}`);
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
        
        // 1. 生成联系方式加密密钥
        const maxKey = 2n ** 128n < this.q ? 2n ** 128n : this.q;
        const contact_key_int = this.generateSecureRandom(1n, maxKey);

        localStorage.setItem(`contact_key_${this.name}`, contact_key_int.toString());
        
        // 2. 使用独立的AES加密函数
        const encryptedHex = aes_enc_ecb(contact_info, contact_key_int);
        
        // 转换为Uint8Array
        this.encrypted_contact = new Uint8Array(
            encryptedHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
        );
        
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
    
    async encrypt_choice(choice) {
        /**加密匹配选择*/
        if (this.shared_private_key === null) {
            throw new Error("共享私钥未设置");
        }
        
        let message;
        if (choice) {
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
        
        return [c1, c2]
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
        
    async decrypt_contact_info(contact_key_ciphertext, encrypted_contact) {
        /**解密对方的联系方式（仅在匹配成功时有效）*/
        // 首先检查匹配是否成功

        try {
            const [c1, c2] = contact_key_ciphertext;
            
            // 解密联系方式密钥
            const s = this.modPow(c1, this.shared_private_key, this.p);
            const s_inv = this.modInverse(s, this.p);
            const contact_key_int = (c2 * s_inv) % this.p;
            
            console.log(`  ${this.name}: 解密得到密钥数值: ${contact_key_int}`);
            
            try {
                // 限制在128位范围内
                if (contact_key_int > 2n ** 128n) {
                    console.log(`  ${this.name}: 解密得到的密钥数值过大`);
                    return null;
                }
                
                // 将加密数据转换为十六进制字符串
                const encryptedHex = Array.from(encrypted_contact)
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
                
                // 使用独立的AES解密函数
                const contact_info = aes_dec_ecb(encryptedHex, contact_key_int);
                
                if (!contact_info) {
                    throw new Error("解密结果为空");
                }
                
                console.log(`  ${this.name}: 成功解密对方联系方式`);
                return contact_info;
                
            } catch (e) {
                console.log(`  ${this.name}: 密钥转换或解密失败 - ${e.message}`);
                return null;
            }
            
        } catch (e) {
            console.log(`  ${this.name}: 联系方式解密异常 - ${e.message}`);
            return null;
        }
    }   

    /**
     * 处理从后端返回的FHE匹配结果
     * @param {Object} responseData - 后端返回的数据
     * @returns {Object} 解密后的结果
     */
    async processFheMatchResponse(responseData) {
        try {
            const { fhe_result, contact_key, contact_info } = responseData;
            
            console.log(`${this.name} 开始处理FHE匹配响应`);
            console.log('原始contact_info:', contact_info);
            console.log('contact_info类型:', typeof contact_info);
            
            // 1. 解密匹配结果
            const fheResultCipher = [BigInt(fhe_result[0]), BigInt(fhe_result[1])];
            const [isMatch, decryptedValue] = this.decrypt_result(fheResultCipher);
            
            console.log(`匹配结果: ${isMatch ? '成功匹配' : '未匹配'}`);
            
            // 2. 如果匹配成功，解密联系方式
            let contactInfo = null;
            if (isMatch) {
                try {
                    // 解析联系方式密文密钥
                    const contactKeyCipher = [BigInt(contact_key[0]), BigInt(contact_key[1])];
                    
                    // 解析加密的联系方式数据
                    let contactInfoData;
                    
                    if (typeof contact_info === 'string') {
                        console.log('尝试解析字符串格式的contact_info');
                        
                        // 尝试多种解析方式
                        let parseSuccess = false;
                        
                        // 方式1: 直接JSON解析
                        if (!parseSuccess) {
                            try {
                                contactInfoData = JSON.parse(contact_info);
                                parseSuccess = true;
                                console.log('方式1成功: JSON.parse');
                            } catch (e1) {
                                console.log('方式1失败:', e1.message);
                            }
                        }
                        
                        // 方式2: Python字典格式转JSON
                        if (!parseSuccess) {
                            try {
                                // 处理Python字典格式 {'0': 123, '1': 456, ...}
                                let jsonStr = contact_info
                                    .replace(/'/g, '"')  // 单引号转双引号
                                    .replace(/(\d+):/g, '"$1":');  // 数字键加引号
                                contactInfoData = JSON.parse(jsonStr);
                                parseSuccess = true;
                                console.log('方式2成功: Python字典转JSON');
                            } catch (e2) {
                                console.log('方式2失败:', e2.message);
                            }
                        }
                        
                        // 方式3: 处理数组字符串格式
                        if (!parseSuccess) {
                            try {
                                // 如果是类似 "[123, 234, 156, ...]" 的格式
                                if (contact_info.startsWith('[') && contact_info.endsWith(']')) {
                                    const arrayData = JSON.parse(contact_info);
                                    contactInfoData = {};
                                    for (let i = 0; i < arrayData.length; i++) {
                                        contactInfoData[i.toString()] = arrayData[i];
                                    }
                                    parseSuccess = true;
                                    console.log('方式3成功: 数组格式转换');
                                }
                            } catch (e3) {
                                console.log('方式3失败:', e3.message);
                            }
                        }
                        
                        if (!parseSuccess) {
                            throw new Error('所有解析方式都失败了');
                        }
                        
                    } else if (typeof contact_info === 'object' && contact_info !== null) {
                        // 如果已经是对象，直接使用
                        contactInfoData = contact_info;
                        console.log('contact_info已经是对象格式');
                    } else {
                        throw new Error(`不支持的contact_info格式: ${typeof contact_info}`);
                    }
                    
                    console.log('解析后的contactInfoData:', contactInfoData);
                    console.log('contactInfoData的键:', Object.keys(contactInfoData));
                    
                    // 创建Uint8Array
                    const keys = Object.keys(contactInfoData);
                    const maxIndex = Math.max(...keys.map(k => parseInt(k)).filter(n => !isNaN(n)));
                    const encryptedContactBytes = new Uint8Array(maxIndex + 1);
                    
                    // 填充字节数组
                    for (const key of keys) {
                        const index = parseInt(key);
                        if (!isNaN(index) && index >= 0 && index < encryptedContactBytes.length) {
                            const value = contactInfoData[key];
                            if (typeof value === 'number' && value >= 0 && value <= 255) {
                                encryptedContactBytes[index] = value;
                            } else {
                                console.warn(`无效的字节值: ${key} -> ${value}`);
                            }
                        }
                    }
                    
                    console.log('转换后的字节数组长度:', encryptedContactBytes.length);
                    console.log('前10个字节:', Array.from(encryptedContactBytes.slice(0, 10)));
                    
                    // 解密联系方式
                    contactInfo = await this.decrypt_contact_info(contactKeyCipher, encryptedContactBytes, isMatch);
                    
                    if (contactInfo) {
                        console.log(`成功解密联系方式: ${contactInfo}`);
                    } else {
                        console.log(`联系方式解密失败`);
                    }
                } catch (e) {
                    console.error(`解密联系方式时出错: ${e.message}`);
                    console.error('错误堆栈:', e.stack);
                    contactInfo = null;
                }
            }
            
            return {
                isMatch: isMatch,
                decryptedValue: decryptedValue.toString(),
                contactInfo: contactInfo,
                rawResult: responseData
            };
            
        } catch (error) {
            console.error(`处理FHE匹配响应时出错: ${error.message}`);
            throw error;
        }
    }
}