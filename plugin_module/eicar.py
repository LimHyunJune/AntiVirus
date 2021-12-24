import os
import hashlib

class KavMain:
    # eicar는 hash를 통해 검출
    def init(self, plugints_path):
        self.virus_name = 'Eicar-Test-File (not a virus)'
        self.eicar_hash = '44das87asd8zxc9asd89zv6z7xv'
        return 0
    
    def uninit(self):
        del self.virus_name
        del self.dummy_pattern
        return 0

    def scan(self, filehandle, filename):
        try:
            size = os.path.getsize(filename)
            # eicar size와 일치하는 파일 대상으로만 해시를 구함
            if size == 68:
                m = hashlib.md5()
                '''
                fp는 read한 만큼 offset이 이동
                따라서 다음 플러그인에서 fp.seek(0)으로 매번 초기화 해야함
                해결책 filehandle은 fp대신 mmap 사용
                '''
                '''
                import mmap
                fp = open('dummy.txt','rb')
                mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
                
                mm[시작위치:시작위치 + 읽을크기]
                mm[:68] 사직위치 생략 시 0으로 취급
                '''
                m.update(filehandle[:68])
                fmd5 = m.hexidigest()
                if fmd5 == self.eicar_hash:
                    return True, self.virus_name, 0
        except IOError:
            pass
        return False, '', -1
    
    def disinfect(self, filename, malware_id):
        try:
            if malware_id == 0 :
                os.remove(filename)
                return True
            # id 값에 따라 치료법 분리 가능
        except IOError:
            pass
        return False    
        
    def list_virus(self):
        vlist = list()
        vlist.append(self.virus_name)
        return vlist
    
    def get_info(self):
        info = dict()
        info['author'] = "HJ LIM"
        info['version'] = '1.0'
        info['title'] = 'Eicar Test Engine'
        