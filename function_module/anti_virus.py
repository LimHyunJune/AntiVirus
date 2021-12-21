import sys
import os
import hashlib
import scan_mod

VirusDB =[] # virus raw data
vdb = [] # 가공된 악성코드 : 해쉬, 악성코드명 
vsize = [] # 악성코드 사이즈 모음 , set 자료구조 


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
    

if __name__ == '__main__' :
    LoadVirusDB()
    MakeVirusDB()
    
    print(vdb)
    
    if len(sys.argv) != 2:
        print("Usage : by_file [file]")
        exit(0)
        
    fname = sys.argv[1]
    ret, vname = scan_mod.ScanMD5
    
    if ret :
        print ("%s : %s" % (fname, vname))
        os.remove(fname)
    else:
        print('%s : ok' % (fname))