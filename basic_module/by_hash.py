import hashlib
import os

fp = open('../data/dummy', 'rb') # byte로 읽어야 함 
fbuf = fp.read()
fp.close()

m = hashlib.md5()
m.update(fbuf)
fmd5 = m.hexdigest()
print(fmd5)
#30742978c615036eba5c1f4e97281dc7

if fmd5 == 'a9030c45a2361e8565559eee400eca24':
    print('Dummy Test Virus')
    print(len(fbuf))