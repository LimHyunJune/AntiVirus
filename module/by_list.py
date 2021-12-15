import sys
import os
import hashlib

VirusDB = ['64:a9030c45a2361e8565559eee400eca24:dummy_test']

#가공 악성코드 적용
vdb = []
#악성코드 사이즈 기록
vsize = []


def MakeVirusDB():
    for pattern in VirusDB:
        t = []
        v = pattern.split(':')
        t.append(v[1])
        t.append(v[2])
        vdb.append(t)
        
        size = int(v[0])
        #이미 등록된 사이즈?
        if vsize.count(size) == 0:
            vsize.append(size)
            
def SearchVDB(fmd5):
    for t in vdb :
        if t[0] == fmd5 : 
            return True, t[1]
        
if __name__ == '__main__' :
    MakeVirusDB()
    
    if len(sys.argv) != 2 :
        print('Usage : antiviru.py [file]')
        exit(0)
        
    fname = sys.argv[1]
    size = os.path.getsize(fname)
    if vsize.count(size) : # size가 존재하는 파일만 의심의 대상 
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()
        
        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()
        
        ret, vname = SearchVDB(fmd5)
        if ret == True:
            print('%s : %s ' % (fname, vname))
            os.remove(fname)
        else : # size는 일치하지만 hash가 다름
            print('OK')
    else: # VirusDB에 size가 일치하는 파일이 없음
        print('OK')
        
        