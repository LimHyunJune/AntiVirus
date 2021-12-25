import hashlib
import posixpath
import py_compile
import shutil
import struct
import sys
import zlib
import rc4
import rsa
import timelib

'''
암호화된 플러그인 엔진
Header : KAVM + 예약 영역 (날짜, 시간 값 포함)
Body : 개인키로 암호화된 RC4 키 + RC4로 암호화한 압축된 코드 이미지
        rsa는 RC4 키를 암호화하는데 사용, 코드를 암호화하기에는 너무 느림
Tailer : 개인키로 암호화한 Header와 Body 전체에 대해 MD5를 3번 연산한 결과

헤더에 날짜와 시간 값을 저장한 이유는 앞으로 생성된 수 많은 플러그인 엔진 중 하나만 교체되어도 
백신은 그 플러그인 엔진의 생성 날짜와 시간을 통해 최종적으로 언제 빌드(업데이트) 되었는지 표시 가능

RC4 키는 32bit
'''



#------------------------------
# rsa 개인키를 이용하여 주어진 파일 암호화하여 KMD 파일 생성.
#------------------------------
def make(src_fname, debug=False):
    fname = src_fname # 암호화 대상 파일 복사
    
    if fname.split('.') == 'py': # python 파일인 경우 컴파일
        py_compile.compile(fname)
    else: # 파이썬 파일이 아닐 경우 확장자를 pyc로 하여 복사
        pyc_name = faname.split('.')[0] + '.pyc'
        shutil.copy(fname, pyc_name)
        
    # 공개키 개인키를 로딩
    # 미리 make_key 모듈을 통해 키 생성해야 함
    rsa_pu = rsa.read_key('key.pkr')
    rsa_pr = rsa.read_key('key.skr')
    
    if not (rsa_pr and rsa_pu) :
        if debug:
            print("ERROR : Cannot find the key files !")
        return False
    
    # KMD 파일 생성
    # 헤더 : 시그니처 (KAVM) + 예약 영역 : [[KAVM][[날짜][시간]....]
    
    kmd_data = 'KAVM'
    
    # 현재 날짜와 시간 구한다.
    ret_data = timelib.get_now_date()
    ret_time = timelib.get_now_time()
    
    # 날짜와 시간 값을 2Byte로 변경
    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)
    # 예약 영역
    reserved_buf = val_date + val_time + (chr(0) * 28)
    # 예약 영역 추가
    kmd_data += reserved_buf
    
    # 본문 생성
    # [개인키로 암호화한 RC4 키][RC4로 암호화한 파일]
    random.seed()
    while 1:
        tmp_kmd_ata = '' # 임시 본문 데이터
        
        # RC4 알고리즘에 사용할 128bit 랜덤키 생성
        for i in range(16):
            key += chr(random.randinit(0, 0xff))
            
        # 생성된 RC4 키를 암호화
        e_key = rsa.crypt(key, rsa_pr) # 개인키로 암호화
        if len(e_key) != 32: # 암호화에 오류 발생 시 다시 생성
            continue
        
        # 암호화된 RC4 키 복호화
        d_key = rsa.crypt(e_key, rsa_pu)
        
        # 생성된 RC4 키의 문제 없음 확인
        if key == d_key and len(key) == len(d_key):
            # 암호화된 RC4 키 임시 버퍼에 추가
            tmp_kmd_ata += e_key
            
            # 생성된 pyc 파일 압축
            buf1 = open(pyc_name, 'rb').read()
            buf2 = zlib.compress(buf1)
            
            e_rc4 = rc4.RC4() # RC4 알고리즘 사용
            e_rc4.set_key(key) # RC4에 key 적용
            
            # 압축된 pyc 파일 이미지를 RC4로 암호화
            buf3 = e_rc4.crypt(buf2)
            
            e_rc4 = rc4.RC4() # RC4 알고리즘 사용
            e_rc4.set_key(key) # RC4에 key 적용
            # 암호화한 pyc 파일 이미지와 복호화된 이미지의 일치 확인
            if e_rc4.crypt(buf3) != buf2:
                continue
                
            # 개인키로 암호화한 압축 파일 이미지를 임시 파일에 추가
            tmp_kmd_ata += buf3
            
            # 꼬리 : ["개인키로 암호화"한  MD5 * 3]
            md5 = hashlib.md5()
            md5hash = kmd_data + tmp_kmd_ata # 헤더와 본문 합침
            for i in range(3):
                md5.update(md5hash)
                md5hash = md5.hexdigest()
            m = md5hash.decode('hex')
            
            e_md5 = rsa.crypt(m, rsa_pr) # 개인키로 암호화
            if len(e_md5) != 32: # 암호화에 오류 존재 시 다시 생성
                continue
            
            d_md5 = rsa.crypt(e_md5, rsa_pu) # 암호화된 MD5 공개키로 복호화
            
            if m == d_md5 : # 복호화 결과가 같다면?
                kmd_data += tmp_kmd_data + emd_5 # 헤더, 본문, 꼬리 합침
                break # 무힌루프 탈출
    # KMD 파일 생성.
    ext = fname.find('.')
    kmd_name = fname[0:ext] + '.kmd'
    
    try:
        if kmd_data:
            open(kmd_name, 'wb').write(kmd_data)
            
            # pyc 파일은 삭제 
            os.remove(pyc_name) 
            
            if debug:
                print("SUCCESS : %-13s -> %s" % (fname, kmd_name))
            return True
        else:
            raise IOError
    except IOError:
        if debug:
            print("FAIL")
        return False
    
            
            
            
            
        
    
    
    
    
    
    