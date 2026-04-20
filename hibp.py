import hashlib
import requests

def check_hibp(password):
    # 第1步：SHA1哈希密码
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # 第2步：只发送前5位（保护隐私）
    prefix = sha1[:5]
    suffix = sha1[5:]
    
    # 第3步：查询API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"Add-Padding": "true"}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        return {"error": str(e), "pwned": None, "count": 0}
    
    # 第4步：在返回结果里找我们的suffix
    for line in response.text.splitlines():
        returned_suffix, count = line.split(":")
        if returned_suffix == suffix:
            return {"pwned": True, "count": int(count), "error": None}
    
    return {"pwned": False, "count": 0, "error": None}