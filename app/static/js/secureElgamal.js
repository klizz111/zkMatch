class SecureElGamal {
    constructor(bits) {
        this.bits = bits;
    }
    
    // 客户端生成密码/种子
    generateSeed() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    // 发送到服务端生成公钥参数
    async generatePublicParams(seed) {
        const response = await fetch('/api/elgamal/generate_public_params', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                bits: this.bits,
                seed_hash: await this.hashSeed(seed) // 只发送哈希值
            })
        });
        
        if (!response.ok) {
            throw new Error('生成公钥参数失败');
        }
        
        const data = await response.json();
        this.p = BigInt(data.p);
        this.g = BigInt(data.g);
        this.q = BigInt(data.q);
        
        // 客户端本地生成私钥
        this.x = this.derivePrivateKey(seed);
        this.y = this.modPow(this.g, this.x, this.p);
        
        return {
            p: this.p,
            g: this.g,
            y: this.y,
            // 私钥不返回给任何人
        };
    }
    
    // 使用种子派生私钥
    async derivePrivateKey(seed) {
        const encoder = new TextEncoder();
        const data = encoder.encode(seed + this.p.toString() + this.g.toString());
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);
        
        // 将哈希转换为大整数
        let x = 0n;
        for (let i = 0; i < hashArray.length; i++) {
            x = (x << 8n) + BigInt(hashArray[i]);
        }
        
        // 确保私钥在正确范围内
        return (x % (this.q - 1n)) + 1n;
    }
    
    async hashSeed(seed) {
        const encoder = new TextEncoder();
        const data = encoder.encode(seed);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);
        return Array.from(hashArray, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    // 快速模幂运算
    modPow(base, exponent, modulus) {
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
}