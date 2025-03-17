#!/usr/bin/env python3
import sys
import json
import base64
import argparse
import cbor2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.exceptions import InvalidSignature

def parse_attestation_doc(file_path):
    """解析 AWS Nitro 证明文档"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # 解析 CBOR 格式的 COSE_Sign1 结构
        try:
            cose_sign1 = cbor2.loads(content)
            
            if not isinstance(cose_sign1, list) or len(cose_sign1) != 4:
                print("错误: 不是有效的 COSE_Sign1 结构")
                return None
            
            # COSE_Sign1 结构: [protected_header, unprotected_header, payload, signature]
            protected_header_bytes = cose_sign1[0]
            unprotected_header = cose_sign1[1]
            payload = cose_sign1[2]
            signature = cose_sign1[3]
            
            # 解析受保护的头部
            protected_header = cbor2.loads(protected_header_bytes)
            
            # 解析载荷 (attestation document)
            attestation_doc = cbor2.loads(payload)
            
            return {
                "cose_sign1": {
                    "protected_header": protected_header,
                    "unprotected_header": unprotected_header,
                    "payload": attestation_doc,
                    "signature": signature
                },
                "raw_payload": payload
            }
        except Exception as e:
            print(f"CBOR 解析失败: {e}")
            return None
            
    except Exception as e:
        print(f"读取文件失败: {e}")
        return None

def print_debug_info(obj, prefix=""):
    """打印对象的调试信息"""
    if isinstance(obj, dict):
        print(f"{prefix}字典，包含 {len(obj)} 个键:")
        for key, value in obj.items():
            key_str = str(key)
            if isinstance(key, bytes):
                key_str = f"bytes({len(key)}): {key.hex()}"
            print(f"{prefix}  键: {key_str}")
            print_debug_info(value, prefix + "    ")
    elif isinstance(obj, list):
        print(f"{prefix}列表，包含 {len(obj)} 个元素:")
        for i, item in enumerate(obj):
            print(f"{prefix}  元素 {i}:")
            print_debug_info(item, prefix + "    ")
    elif isinstance(obj, bytes):
        print(f"{prefix}二进制数据，长度: {len(obj)} 字节")
        if len(obj) <= 32:
            print(f"{prefix}  值: {obj.hex()}")
    else:
        print(f"{prefix}值: {obj} (类型: {type(obj)})")

def try_decode_hex_to_string(hex_str):
    """尝试将十六进制字符串解码为可读字符串"""
    try:
        # 将十六进制字符串转换为字节
        bytes_data = bytes.fromhex(hex_str)
        # 尝试将字节解码为 UTF-8 字符串
        return bytes_data.decode('utf-8')
    except Exception:
        # 如果解码失败，返回原始十六进制字符串
        return None

def extract_fields(attestation_doc):
    """从证明文档中提取字段"""
    if not attestation_doc or "cose_sign1" not in attestation_doc:
        return {}
    
    payload = attestation_doc["cose_sign1"]["payload"]
    result = {}
    
    # 提取关键字段
    fields_to_extract = [
        "module_id", "timestamp", "digest", "pcrs", 
        "certificate", "cabundle", "public_key", "user_data", "nonce"
    ]
    
    for field in fields_to_extract:
        if field in payload:
            value = payload[field]
            
            # 处理 PCR 值 - 现在我们知道它是一个字典
            if field == "pcrs" and isinstance(value, dict):
                pcrs_info = []
                for index, pcr_value in value.items():
                    pcr_entry = {
                        "index": index,
                        "value": pcr_value.hex() if isinstance(pcr_value, bytes) else str(pcr_value),
                        "hash_algorithm": "SHA384"  # 默认值
                    }
                    pcrs_info.append(pcr_entry)
                result[field] = pcrs_info
            elif field == "cabundle" and isinstance(value, list):
                result[field] = [cert.hex() if isinstance(cert, bytes) else str(cert) for cert in value]
            elif field == "certificate" and isinstance(value, bytes):
                result[field] = value.hex()
            elif field == "public_key" and isinstance(value, bytes):
                result[field] = value.hex()
            elif field == "user_data" and isinstance(value, bytes):
                hex_value = value.hex()
                result[field] = hex_value
                # 尝试解码为字符串
                decoded = try_decode_hex_to_string(hex_value)
                if decoded:
                    result[f"{field}_decoded"] = decoded
            elif field == "nonce" and isinstance(value, bytes):
                hex_value = value.hex()
                result[field] = hex_value
                # 尝试解码为字符串
                decoded = try_decode_hex_to_string(hex_value)
                if decoded:
                    result[f"{field}_decoded"] = decoded
            elif value is not None:  # 只添加非空值
                result[field] = value
    
    return result

def main():
    parser = argparse.ArgumentParser(description='解析 AWS Nitro Enclave 证明文档')
    parser.add_argument('file', help='证明文档文件路径')
    parser.add_argument('--raw', action='store_true', help='显示原始 CBOR 数据')
    parser.add_argument('--debug', action='store_true', help='显示调试信息')
    args = parser.parse_args()
    
    attestation_doc = parse_attestation_doc(args.file)
    if not attestation_doc:
        sys.exit(1)
    
    if args.debug:
        print("原始文档结构:")
        print_debug_info(attestation_doc)
        sys.exit(0)
    
    if args.raw:
        print("原始 COSE_Sign1 结构:")
        print(json.dumps({
            "protected_header": str(attestation_doc["cose_sign1"]["protected_header"]),
            "unprotected_header": str(attestation_doc["cose_sign1"]["unprotected_header"]),
            "payload": "二进制数据，长度: " + str(len(attestation_doc["raw_payload"])) + " 字节",
            "signature": attestation_doc["cose_sign1"]["signature"].hex() if isinstance(attestation_doc["cose_sign1"]["signature"], bytes) else str(attestation_doc["cose_sign1"]["signature"])
        }, indent=2, ensure_ascii=False))
        sys.exit(0)
    
    # 提取字段
    fields = extract_fields(attestation_doc)
    
    # 打印提取的字段
    print("证明文档分析:")
    print("-" * 50)
    
    for field, value in fields.items():
        if field == "pcrs":
            print("\nPCR 值:")
            # 按 PCR 索引排序
            sorted_pcrs = sorted(value, key=lambda x: int(x["index"]) if isinstance(x["index"], (int, str)) else x["index"])
            for pcr in sorted_pcrs:
                print(f"  PCR[{pcr['index']}]: {pcr['value']} (算法: {pcr['hash_algorithm']})")
        elif field == "cabundle":
            print("\n证书链:")
            for i, cert in enumerate(value):
                print(f"  证书 {i}: {cert[:64]}...")
        elif field == "certificate":
            print(f"\n证书: {value[:64]}...")
        elif field == "public_key" and value:
            print(f"\n公钥: {value[:64]}...")
        elif field == "user_data" and value:
            print(f"\n用户数据 (十六进制): {value}")
        elif field == "user_data_decoded" and value:
            print(f"用户数据 (解码): {value}")
        elif field == "nonce" and value:
            print(f"\nNonce (十六进制): {value}")
        elif field == "nonce_decoded" and value:
            print(f"Nonce (解码): {value}")
        else:
            if not field.endswith("_decoded"):  # 避免重复打印解码字段
                print(f"{field}: {value}")

if __name__ == "__main__":
    main()