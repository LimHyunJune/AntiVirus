import os
'''
키콤 백신 엔진 모듈임을 나타내는 클래스
이 클래스가 없으면 백신 엔진 커널 모듈에서 로딩하지 않음.
'''
class KavMain:
    # ------------------------------------------------
    # 플러그인 엔진 초기화
    # plugints_path : 악성코드 패턴 파일 위치를 커널로 부터 전달 받음
    # return 0 정상 종료
    # ------------------------------------------------
    def init(self, plugints_path):
        # 진단/치료하는 악성코드 이름
        self.virus_name = 'Dummy-Test-File (not a virus)'
        '''
        악성코드 패턴
        dummy 테스트 파일이므로 패턴이 따로 없음
        패턴 파일이 필요하면 로드해서 사용 가능
        '''
        self.dummy_pattern = 'Dummy Engine test file -KIKOM Anti-Virus Project!!'
        return 0
    
    # 메모리 해제 
    def uninit(self):
        del self.virus_name
        del self.dummy_pattern
        return 0
    
    #-------------------------------------------------
    # 악성코드 검사
    # 플러그인 A에서 악성코드 검색을 위해 파일 열고 검출 못한 경우 플러그인 B에서 다시 열어야 됨.
    # 백신 검사속도를 위해 파일(악성코드) 열고 닫기 최소화 방법 모색
    # 백신 커널이 파일을 한번만 열고 file handle (fp) 을 전달
    #-------------------------------------------------
    def scan(self, filehandle, filename):
        try:
            # 파일을 열어서 악성코드 패턴만큼 파일에서 읽음
            fp = open(filename)
            buf = fp.read(len(self.dummy_pattern))
            fp.close()
            
            if buf == self.dummy_pattern:
                # 반환 값중 인덱스는 악성코드 ID
                # 하나의 플러그인에서 다루는 악성코드가 여러개인 경우 ID로 구분
                # 악성코드 ID 마다 치료방법이 다를 수 있다.
                return True, self.virus_name, 0
            # 다른 패턴들에 대해서 다른 ID로 리턴하는 elif 추가 가능 
        except IOError:
            pass
        # 발견 못했을 경우 ID -1 리턴
        return False, '', -1
    
    #-------------------------------------------------
    # 악성코드 치료
    # filename : 치료를 위해 필요
    # malware_id : id에 따라 치료방법 달라짐
    #-------------------------------------------------
    '''
    악성코드가 실행중인 프로세스라면 파일제거 불가능
    프로세스를 졸료하는 로직 추가 ?
    백신 엔진은 모든 플랫폼에서 동작해야함 (리눅스, 윈도우, 맥 ...)
    프로세스 종료는 플랫폼마다 방식이 다름
    따라서 프로세스 종료 로직은 GUI 프로그램에서 따로 처리 
    '''
    def disinfect(self, filename, malware_id):
        try:
            if malware_id == 0 :
                os.remove(filename)
                return True
            # id 값에 따라 치료법 분리 가능
        except IOError:
            pass
        return False    
        
    #-------------------------------------------------
    # 진단/치료 가능한 악성코드 리스트
    #-------------------------------------------------
    def list_virus(self):
        vlist = list()
        vlist.append(self.virus_name)
        return vlist
    
    #-------------------------------------------------
    # 플러그인 엔진 정보 리턴
    #-------------------------------------------------
    def get_info(self):
        info = dict()
        info['author'] = "HJ LIM"
        info['version'] = '1.0'
        info['title'] = 'Dummy Test Engine'
        