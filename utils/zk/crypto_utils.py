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