import sys
import os
import hashlib

VirusDB =[] # virus raw data
vdb = [] # 가공된 악성코드 : 해쉬, 악성코드명 
vsize = [] # 악성코드 사이즈 모음 , set 자료구조 

'''
악성코드 패턴
https://github.com/vrtadmin/clamav-devel

size:hash:name
':' 로 구분 
'''

# 파일에서 Load
def LoadVirusDB():
    fp = open('../data/virus.db','rb')
    while True:
        line = fp.readline()
        if not line : break
        
        line = line.strip() 
        VirusDB.append(line)
    fp.close()

# 가공하여 저장    
def MakeVirusDB():
    for pattern in VirusDB:
        t = []
        v = pattern.split(':'.encode('utf-8')) # : 을 binary 형태로 인코딩
        t.append(v[1])
        t.append(v[2])
        vdb.append(t)
        
        size = int(v[0])
        if vsize.count(size) == 0:
            vsize.append(size)
    
def SearchVDB(fmd5):
    for t in vdb:
        if t[0] == fmd5:
            return True, t[1]
    return False, ''

if __name__ == '__main__' :
    LoadVirusDB()
    MakeVirusDB()
    
    print(vdb)
    
    if len(sys.argv) != 2:
        print("Usage : by_file [file]")
        exit(0)
        
    fname = sys.argv[1]
    size = os.path.getsize(fname)
    if vsize.count(size) :
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()
        
        m = hashlib.md5()
        m.update(buf)
        fmd5 = bytes(m.hexdigest(), 'UTF-8') # DB : byte -> hash -> 다시 byte로 읽음, 따라서 파일 hash 값에 byte 인코딩
        ret, vname = SearchVDB(fmd5)
        if ret :
            print ("%s : %s" % (fname, vname))
            os.remove(fname)
        else :
            print('%s : ok' % (fname))
    else:
        print('%s : ok' % (fname))