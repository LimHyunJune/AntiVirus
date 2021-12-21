import sys
import os
import hashlib

"""
scan 모듈 분리
md5 해시를 이용한 검사 
특정 위치 문자열 매칭 검사 
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
    
# 특정 위치 검색을 통한 검사 
def ScanStr(fp, offset, mal_str):
    size = len(mal_str)
    fp.seek(offset) # offset 위치로 이동
    buf = fp.read(size) # size만큼 읽음
    
    if buf == mal_str:
        return True
    else:
        return False
    
    
def ScanVirus(vdb, vsize, sdb, fname):
    # MD5 해시를 이용하여 검사
    ret, vname = ScanMD5(vdb, vsize, fname)
    if ret:
        return ret, vname
    
    # str 특정 위치 검색을 이용해서 검사
    fp = open(fname,'rb')
    for t in sdb:
        if ScanStr(fp, t[0], t[1]):
            ret = True
            vname = t[2]
            break
    fp.close()
    
    return ret, vname

        