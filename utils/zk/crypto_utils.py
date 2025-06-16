import base64
import zlib
import json
from typing import Dict

def compress_credential(p: str, g: str, y: str, x: str) -> str:
    """
    压缩用户凭证信息为一个字符串
    格式: base64(zlib(json({p, g, y, x})))
    """
    credential_data = {
        'p': p,
        'g': g, 
        'y': y,
        'x': x
    }
    
    # 转为JSON字符串
    json_str = json.dumps(credential_data, separators=(',', ':'))
    
    # 压缩
    compressed = zlib.compress(json_str.encode('utf-8'))
    
    # Base64编码
    encoded = base64.b64encode(compressed).decode('ascii')
    
    return encoded

def decompress_credential(compressed_credential: str) -> Dict[str, str]:
    """
    解压缩用户凭证信息
    """
    try:
        # Base64解码
        compressed = base64.b64decode(compressed_credential.encode('ascii'))
        
        # 解压缩
        json_str = zlib.decompress(compressed).decode('utf-8')
        
        # 解析JSON
        credential_data = json.loads(json_str)
        
        return credential_data
    except Exception as e:
        raise ValueError(f"Invalid compressed credential: {e}")

def generate_login_token(username: str, p: str, g: str, y: str) -> str:
    """
    生成简化的登录令牌，只包含公钥信息
    用户只需要输入这个令牌和用户名就可以登录
    """
    public_data = {
        'u': username,  # 缩短字段名
        'p': p,
        'g': g,
        'y': y
    }
    
    json_str = json.dumps(public_data, separators=(',', ':'))
    compressed = zlib.compress(json_str.encode('utf-8'))
    encoded = base64.b64encode(compressed).decode('ascii')
    
    return encoded

def parse_login_token(token: str) -> Dict[str, str]:
    """
    解析登录令牌
    """
    try:
        compressed = base64.b64decode(token.encode('ascii'))
        json_str = zlib.decompress(compressed).decode('utf-8')
        public_data = json.loads(json_str)
        
        return {
            'username': public_data['u'],
            'p': public_data['p'],
            'g': public_data['g'],
            'y': public_data['y']
        }
    except Exception as e:
        raise ValueError(f"Invalid login token: {e}")