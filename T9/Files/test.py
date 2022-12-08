#!/bin/python

#read -p "Enter encryption key: " key
#hexkey=`echo -n $key | ./busybox xxd -p | ./busybox head -c 32`
#export hexkey
#./busybox find $1 -regex '.*\.\(pdf\|doc\|docx\|xls\|xlsx\|ppt\|pptx\)' -print -exec sh -c 'iv=`./openssl rand -hex 16`; echo -n $iv > $0.enc; ./openssl enc -e -aes-128-cbc -K $hexkey -iv $iv -in $0 >> $0.enc; rm $0' \{\} \; 2>/dev/null

# AES-128-CBC
# KEY = First 16 Chars of UUID in HEX
# IV = First 16 Bytes (32 Chars)

from Crypto.Cipher import AES
import time
import sys

#-------------------
#  Times Tested
# 2022-02-15 09:55:00.000000.0 UTC      -->    2022-02-15 09:57:00.000000.0 UTC (2 Mins)
#
# ----- NOTES --- 
# * Triple Check how UUID is generated (Local [-0500] or UTC Time?)   Seems to be UTC Time
#
#	2022-02-15 10:04:54.000000.0        -->    2022-02-15 10:04:56.000000.0
#   2022-02-15 14:56:00.000000.0        -->    2022-02-15 14:57:00.000000.0
#   0x1ed65bec87a4000


t1 = "e0d71bc0-65f0"  # Start Time from UUID
t2 = "e0d71bd0-65f0"  # End Time from UUID
iv = b'\x58\x57\x5c\x24\x2c\x95\x6a\x02\x86\x2d\x27\xbd\xb4\x1e\xd8\x9b'
p1 = "-11"
mb = b'\x25\x50\x44\x46'

data = open("test.pdf.enc","rb").read()
data = data[32:]

start = t1.split('-')[1] + t1.split('-')[0]
finish = t2.split('-')[1] + t2.split('-')[0]

a = int(start,16)
b = int(finish,16)
cnt = b - a
cur = 1

ticks = cnt / 100000
secs = ticks * 2.05
mins = secs / 60
hours = mins / 60
days = hours / 24

print(f'Total Guesses: {cnt}\nDays: {int(days%365)}, Hours: {int(hours%24)}, Mins: {int(mins%60)}, Seconds: {int(secs%60)}')

def decrypt(key, file):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    output = cipher.decrypt(file)
    #print(output[0:48])
    if mb in output[0:8]:
        print(f'FOUND PDF HEADER\n{key}')
        fname = str(key[2:len(key)-1]) + '.pdf'
        with open(fname, "wb") as f:
            f.write(output)

for x in range(a,b+1):
    x = str(hex(x)[2:])
    temp = x[4:] + '-' + x[0:4] + p1
    temp = bytes(temp[:32], 'utf-8')
    decrypt(temp, data)
    cur += 1
    if cur % 100000 == 0:
        print('\b'*8 + f'{(cur/cnt)*100:.4f}%', end='')
        sys.stdout.flush()