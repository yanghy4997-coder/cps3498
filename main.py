from analyzer import analyze_password

test_passwords = [
    "password",
    "P@ssw0rd",
    "qwerty123",
    "19901201",
    "Tr0ub4dor&3",
]

for pwd in test_passwords:
    print(f"\n{'='*40}")
    print(f"密码: {pwd}")
    result = analyze_password(pwd)
    print(f"评分: {result['final_score']} / 4 ({result['score_label']})")
    print(f"破解时间: {result['crack_time']}")
    print(f"键盘走位: {result['patterns']['keyboard_walk']}")
    print(f"日期格式: {result['patterns']['date_pattern']}")
    print(f"L33t: {result['patterns']['leet_speak']}")
    print(f"HIBP泄露: {result['hibp']}")
    if result['feedback']['suggestions']:
        print(f"建议: {result['feedback']['suggestions']}")