from zxcvbn import zxcvbn
from patterns import detect_all_patterns
from hibp import check_hibp

def analyze_password(password):
    # 1. zxcvbn分析
    zx = zxcvbn(password)
    
    # 2. 模式检测
    patterns = detect_all_patterns(password)
    
    # 3. HIBP检查
    hibp = check_hibp(password)
    
    # 4. 综合评分
    score = zx["score"]
    if hibp.get("pwned"):
        score = 0
    if patterns["keyboard_walk"]["detected"]:
        score = max(0, score - 1)
    
    # 5. 统一输出
    return {
        "password_length": len(password),
        "final_score": score,
        "score_label": ["very weak","weak","fair","strong","very strong"][score],
        "crack_time": zx["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "patterns": patterns,
        "hibp": hibp,
        "feedback": zx["feedback"],
    }