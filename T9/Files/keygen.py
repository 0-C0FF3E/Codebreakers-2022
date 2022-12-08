#!/bin/python

from Crypto.Cipher import AES
import sys

t1 = "b185a200-8e22-11ec-b176-12edfd570000"
t2 = "5de47a00-8e5d-11ec-b176-12edfd570000"
iv = b'\xfa\x0b\x3b\x71\xc4\x85\x37\x06\x04\xd4\xf6\xbf\xea\x6e\x39\x92'
p1 = "-11ec-b176-12edfd570000"
mb = b'\x25\x50\x44\x46'

data = open("important_data.pdf.enc","rb").read()
data = data[32:]

start = t1.split('-')[1] + t1.split('-')[0]
finish = t2.split('-')[1] + t2.split('-')[0]

a = int(start,16)
b = int(finish,16)
cnt = b - a
cur = 1

def decrypt(key, file):
    cipher = AES.new(key,AES.MODE_CBC, iv)
    output = cipher.decrypt(file)
    if mb in output[0:5]:
        print(f'FOUND PDF HEADER\n{key}')
        input()
        print(output)
    
for x in range(a,b+1):
    x = str(hex(x)[2:])
    temp = x[4:] + '-' + x[0:4] + p1
    temp = bytes(temp[:32], 'utf-8')
    decrypt(temp, data)
    cur += 1
    if cur % 100000 == 0:
        print('\b'*13 + f'{(cur/cnt)/100:.10f}%', end='')
        sys.stdout.flush()