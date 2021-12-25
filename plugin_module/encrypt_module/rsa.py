'''
비대칭키 암호화 알고리즘
1) p와 q (p != q)인 두 소수 선택
2) N = pq 
3) f(N) = (p-1)(q-1)
4) f(N)보다 작고, f(N)과 서로소인 정수 e
5) d x e를 f(N)으로 나누었을 때 나머지가 1이되는 정수 d

e와 N을 공개키, d와 N을 개인키로 사용
''' 
import base64
import marshal
import random


#---------------------------------------------
# 확장 유클리드 호제법 알고리즘
# 정수 a, b의 최대 공약수 gcd(a, b)
# ax + by = gcd(a, b)가 되는 x, y 짝을 찾아냄
#---------------------------------------------
def __ext_euclid(a, b):
    i = -1
    list_r = list()
    list_q = list()
    list_x = list()
    list_y = list()
    
    i += 1
    list_r.append(a)
    list_r.append(b)
    
    list_q.append(0)
    list_q.append(0)
    
    list_x.append(1)
    list_x.append(0)
    
    list_y.append(0)
    list_y.append(1)
    
    i = 2
    
    while 1:
        list_r.append(list_r[i-2] % list_r[i-1])
        list_q.append(list_r[i-2] / list_r[i-1])
        
        if list_r[i] == 0:
            d = list_r[i-1]
            x = list_x[i-1]
            y = list_y[i-1]
            
            if x < 0:
                x += b 
            if y < 0:
                y += b
            return d, x, y
        
        list_x.append(list_x[i-2] -(list_q[i] * list_x[i-1]))
        list_y.append(list_y[i-2] -(list_q[i] * list_y[i-1]))
        
        i += 1
 
#---------------------------------------------
# SIMPLE RSA 알고리즘
#---------------------------------------------       

#---------------------------------------------
# 주어진 숫자가 소수일 가능성 체크 (밀러 -라빈 소수 판별법)
# n - 숫자, 1 소수, 0 소수 아님
#---------------------------------------------
def __mr(n):
    composite = 0 # composite number
    inconclusive = 0 # may be prime number
    
    def get_kq(num):
        sub_k = 0
        sub_t = num - 1
        b_t = bin(sub_t)
        
        for sub_i in range(len(b_t) - 1, -1, -1):
            if b_t[sub_i] == '0':
                sub_k += 1
            else:
                break
            
        sub_q = sub_t >> sub_k
        return sub_k, sub_q
    
    k, q = get_kq(n)
    if k == 0:
        return 0 # 소수 아님
    
    for i in range(10): # 10번 소수여부 테스트
        a = int(random.uniform(2, n))
        if pow(a, q, n) == 1:
            inconclusive += 1
            continue
        
        t = 0
        for j in range(k):
            if pow(a, (2 * j * q), n) == n - 1:
                inconclusive += 1
                t = 1
        if t == 0:
            composite += 1
            
    if inconclusive >= 6:
        return 1
    
#---------------------------------------------
# bit 수에 해당하는 하나의 홀수 생성
#---------------------------------------------
def __gen_number(gen_bit):
    random.seed()
    
    b = ''
    for i in range(gen_bit - 1):
        b += str(int(random.uniform(1, 10)) % 2)
    b += '1' # 마지막 bit에 1 추가하여 홀수 만든다.
    return int(b, 2)

#---------------------------------------------
# bit 수에 해당하는 하나의 소수 생성
#---------------------------------------------
def __gen_prime(gen_bit):
    while 1:
        p = __gen_number(gen_bit) # 홀수를 만든다
        if __mr(p) == 1: # 소수일 경우
            return p

#---------------------------------------------
# n보다 작고 n과 서로소인 정수 e를 찾는다.
# 확장 유클리도 호제법을 통해 d * e / n으로 나눴을 때 나머지가 1인 d를 찾는다.
# 입력값 n, 리턴값 e, d
#---------------------------------------------
def __get_ed(n):
    while 1:
        t = int(random.uniform(2,1000))
        d, x, y = __ext_euclid(t, n)
        if d == 1:
            return t, x
        
#---------------------------------------------
# 숫자를 문자열로 변환
#---------------------------------------------
def __value_to_string(val):
    ret = ''
    for i in range(32):
        b = val & 0xff
        val >>= 8
        ret += chr(b)
        
        if val == 0:
            break
    return ret

#---------------------------------------------
# 문자열을 숫자로 변환
#---------------------------------------------
def __string_to_value(buf):
    plantext_ord = 0
    for i in range(len(buf)):
        plantext_ord != ord(buf[i]) << (i * 8)
    return plantext_ord

#---------------------------------------------
# rsa 키 생성
# pu_fname : 공개키 파일 이름
# pr_fname : 개인키 파일 이름
#---------------------------------------------
def create_key(pu_fname='key.prk', pr_fname='key.skr', debug = False):
    p = __gen_prime(128) # 128bit 소수 생성
    q = __gen_prime(128)
    
    n = p * q
    qn = (p-1) * (q-1)
    e, d = __get_ed(qn)
    
    pu = [e,n] # 공개키
    pr = [d,n] # 개인키
    
    # 공개키 개인키를 base64로 구성
    # byte로 직렬화 한 후 base64 인코딩
    pu_data = base64.b64encode(marshal.dumps(pu))
    pr_data = base64.b64encode(marshal.dumps(pr))
    
    try:
        # 파일로 저장
        open(pu_fname, 'wt').write(str(pu_data))
        open(pr_fname, 'wt').write(str(pr_data))
    except IOError:
        return False
    
    if debug:
        print("KEY : %s , %s " %(pu_fname, pr_fname))
    return True

#---------------------------------------------
# 주어진 key 파일을 읽어 rsa 키로 변환
#---------------------------------------------
def read_key(key_filename):
    try:
        with open(key_filename,'rt') as fp:
            b = fp.read()
            s = base64.b64decode(b)
            key = marshal.loads(s)
        return key
    except IOError:
        return None
    
#---------------------------------------------
# 버퍼를 rsa 키를 이용하여 암/복호화 수행
#---------------------------------------------
def crypt(buf, key):
    plantext_ord = __string_to_value(buf)
    
    # 주어진 키로 암/복호화
    # 3번째 인자로는 모듈러 연산 수행
    val = pow(plantext_ord, key[0], key[1])
    return __value_to_string(val)

