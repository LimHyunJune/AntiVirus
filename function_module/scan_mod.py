import sys
import os
import hashlib

"""
scan 모듈 분리
"""
    
def SearchVDB(vdb,fmd5):
    for t in vdb:
        if t[0] == fmd5:
            return True, t[1]
    return False, ''

# md5를 통해 악성코드 검사
def ScanMD5(vdb,vsize,fname):
    size = os.path.getsize(fname)
    if vsize.count(size):
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()
        
        m = hashlib.md5()
        m.update(buf)
        fmd5 = bytes(m.hexdigest(), 'UTF-8') # DB : byte -> hash -> 다시 byte로 읽음, 따라서 파일 hash 값에 byte 인코딩

        return SearchVDB(vdb, fmd5)
    return False, ''
    
