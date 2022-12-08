#!/bin/sh
read -p "Enter encryption key: " key
echo $key
hexkey=`echo -n $key | xxd -p | head -c 32`
echo $hexkey
export hexkey
find $1 -regex '.*\.\(pdf\|doc\|docx\|xls\|xlsx\|ppt\|pptx\)' -print -exec sh -c 'iv=`openssl rand -hex 16`; echo -n $iv > $0.enc; openssl enc -e -aes-128-cbc -K $hexkey -iv $iv -in $0 >> $0.enc' \{\} \; 2>/dev/null


# e0d71bc8-65f0-11ed-9061-0800273b