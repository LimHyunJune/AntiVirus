import hashlib
import os

fp = open('../data/dummy_test', 'rb') # byte로 읽어야 함 
fbuf = fp.read()
fp.close()

m = hashlib.md5()
m.update(fbuf)
fmd5 = m.hexdigest()
#a9030c45a2361e8565559eee400eca24

if fmd5 == 'a9030c45a2361e8565559eee400eca24':
    print('Dummy Test Virus')