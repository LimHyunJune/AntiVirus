import sys
import os
import hashlib
import scan_mod
import cure_mod

VirusDB =[] # virus raw data
vdb = [] # md5 해시 검색 기반 가공 악성코드 
vsize = [] # 악성코드 사이즈 모음 , set 자료구조 , 모든 검사 함수에서 공통으로 사용 
sdb = [] # 위치 검색 기반 가공 악성코드

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
        
        scan_func = v[0] # 악성코드 검사 함수
        cure_func = v[1] # 악성코드 치료 함수 
        
        if scan_func == 'ScanMD5':
            t.append(v[3]) # MD5 해시 값 
            t.append(v[4]) # 악성 코드 명
            vdb.append(t)
        
            size = int(v[2])
            if vsize.count(size) == 0:
                vsize.append(size)
        elif scan_func == 'ScanStr':
            t.append(int(v[2])) # offset
            t.append(v[3]) # 진단 문자열 패턴
            t.append(v[4]) # 악성코드 명
            sdb.append(t)
ㅣ
if __name__ == '__main__' :
    LoadVirusDB()
    MakeVirusDB()
    
    print(vdb)
    
    if len(sys.argv) != 2:
        print("Usage : by_file [file]")
        exit(0)
        
    fname = sys.argv[1]
    ret, vname = scan_mod.ScanVirus(vdb, vsize, sdb, fname)
    
    if ret :
        print ("%s : %s" % (fname, vname))
        cure_mod.CureDelete(fname)
    else:
        print('%s : ok' % (fname))