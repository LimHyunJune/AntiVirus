import sys
import os
import hashlib
import zlib


'''
Virus 패턴 파일은 누구나 수정 가능함으로 공격자가 수정하여 배포시 문제.
백신 업체에서만 수정 가능하도록 하여야 함.
패턴 파일에 대한 암호화 수행.
'''


'''
아래 메소드는 해쉬(md5)를 통한 암호화 및 복호화 과정 : key를 사용하지 않으므로 알고리즘 유출 시 전부 노출됨
AES와 개인키, 공개키를 통해 암호화 해서 배포하는 것도 안전할 것 같음
1) 개인키와 AES를 통해 DB 내용 암호화
2) 모듈에서 공개키 오픈, 공개키를 통한 복호화 로직 
3) DB에서 내용을 수정하고 싶어도 개인키를 모르기 때문에 적절히 암호화 불가
4) 복호화 과정에서 충돌 발생
'''

def encrypt():
    fp = open('../data/virus.db','rb')
    buf = fp.read()
    fp.close()
    
    # 1.압축
    compressed_buf = zlib.compress(buf)
    # 2.XOR
    xor_compressed_buf = ''
    for character in compressed_buf:
        xor_compressed_buf += chr((character) ^ 0xFF)
    
    # 3.헤더 추가 
    header_added_buf = 'KAVM' + xor_compressed_buf
    hashed_buf = header_added_buf
    
    # 4.해싱 x 3
    for i in range(3):
        md5 = hashlib.md5()
        md5.update(hashed_buf.encode('utf-8'))
        hashed_buf = md5.hexdigest()
    
    # 5. 헤더부와 해싱부 결합
    encrypted_buf = header_added_buf + hashed_buf
    
    kmd_name = '../data/virus' + '.kmd' # kmd 암호 파일 생성
    fp = open(kmd_name,'wb')
    fp.write(encrypted_buf.encode('utf-8'))
    fp.close()


def decrypt():
    fp = open('../data/virus.kmd','rb')
    buf = fp.read()
    fp.close()
    
    encrypted_part = buf[:-32] #암호화 내용 분리
    fmd5 = buf[-32:] # MD5 분리 , MD5는 32 characters로 해싱
    temp_encrypted_part = encrypted_part
    for i in range(3):
        md5 = hashlib.md5()
        md5.update(temp_encrypted_part.encode('utf-8'))
        temp_encrypted_part = md5.hexdigest()
    if temp_encrypted_part != fmd5 :
        print('error')
        raise SystemError
    
    xor_buf = ''
    for character in encrypted_part[4:] :
        xor_buf += chr((character) ^ 0xFF)
        
    decompressed_buf = zlib.decompress(xor_buf)
    return decompressed_buf
    
