Unfortunately, looks like the ransomware site suffered some data loss, and doesn't have the victim's key to give back! I guess they weren't planning on returning the victims' files, even if they paid up.

There's one last shred of hope: your cryptanalysis skills. We've given you one of the encrypted files from the victim's system, which contains an important message. Find the encryption key, and recover the message.

Prompt:

Enter the value recovered from the file

---

This one stumped me for a good while.  It took lots of repeated stepping through the program to figure out what was happening.  The first step was to figure out just how the encryption key was being generated.

Using the notes from the previous task (See bonus info at end of task 8), we can see that each time the LOCK command was issued into the program, a UUID value was generated.  Since each UUID value is technically unique, there should be no duplicate key values.

This seemed to be a critical discovery as it was most likely going to be how unique encryption keys were derived.  The ransom amount, hackername, and cid values all had the potential to be the same as before, so it did not logically make sense that these values would be used in the key generation.

To avoid going into all the rabbit holes I had to discover, I am going to go only through the process that lead to the key discovery.

In order to test some of my theories, I manually added credits to ProfuseHunter (You needed at least 1 credit listed in the database to generate a lock code) so that I could follow the process of requesting a new key all the way through.

While going through that, we see that the UUIDv1 is generated and used for the key generation.

1 - Generate UUID at runtime:
```
UUID:
14e7390b-61ed-11ed-93b1-0800273b6e7b
14e7390b-61ed-11ed-93b1-0800273b6e7b
	Contents - Time	2022-11-11 18:17:20.419457.1 UTC
	Contents - Clock	5041 (usually random)
	Contents - Node	08:00:27:3b:6e:7b (global unicast)
		VER: 1
		VAR: DCE 1.1, ISO/IEC 11578:1996
```
2 - The time-value is then modified for storage into the logs/database:
```
Time
2006-01-02T15:04:05Z07:00 Fmt String
2022-11-11T11:09:58-08:00 Result
```
3 - Then the HEX values of the ASCII UUID value are picked out:
```
Size: 0x10 (16)
	0x315431313a30393a35382d30383a3030
```
4 - These bytes are then base64 encoded as the encryption key value
```
Base64 String
	0MJ7bUsqs5Yb65fgfQojSYudPhz+mX9632kc2m6JIeI=
```
5 - This is then finally encrypted with the key-encrypting-key for storage in the database.

Looking back, there were some major clues here:

* First, we can see that the decryption key is the UUID value.  This means we will need to find an associated timestamp for WHEN the file was encrypted to be able to generate the key.
* Second, only certain parts of the UUID are relevant (though this was not obvious to me at first -- More on this later)
* Third, based on the AES Cipher, we also need to find a IV value which is usually a random 16 byte value.

My first assumption that cost me quite a bit of time was that the encryption algorithm was the same as the key-encrypting-key: AES-256-CBC

However, this was wrong.  I spent a few days trying to calculate random values before it occoured to me that I should go back and look at how exactly the key was being used.  Up to this point, we have only seen the parts on how the key was generated... But nothing on WHERE the key was used.

I ended up going all the way back to task A2 - Where we were able to obtain a copy of the tools that were used during the ransomware attack -- Here is where the first major discovery was made.  The ransom.sh file from tools.rar contains lots of the data we need:

```sh
#!/bin/sh
read -p "Enter encryption key: " key
hexkey=`echo -n $key | ./busybox xxd -p | ./busybox head -c 32`
export hexkey
./busybox find $1 -regex '.*\.\(pdf\|doc\|docx\|xls\|xlsx\|ppt\|pptx\)' -print -exec sh -c 'iv=`./openssl rand -hex 16`; echo -n $iv > $0.enc; ./openssl enc -e -aes-128-cbc -K $hexkey -iv $iv -in $0 >> $0.enc; rm $0' \{\} \; 2>/dev/null
```

* First: We see that openssl is used in AES-128-CBC mode... Not AES-256-CBC.  This is different than what I expected because I just assumed that it used the same cipher as the key-encrypting-key!  So now we know the correct cipher to use when attempting to decrypt.  This also explains why in the UUID breakdown, I only saw 16 bytes of the UUID being used, and not the full UUID value.

* Second: Next we know that an IV is required when encrypting and it is actually generated here in this file!  It uses openssl to generate a 16-byte random value and is stored in the $iv variable in the script!  This IV is then fed INTO the encrypted file and then the encrypted contents are appended to that file.  This means if we look at the the file, we should be able to find the IV value that was used!

* Third: The start of this script REQUESTS the user enter the encryption key.  This implies that the process is not fully-automated.  The hacker needs to request the key from the server, and then input that key into the script before the ransomware can actually get started -- This means that we can actually test our decryption routine fairly easily.

* Fourth (less-important): We also see that this script only runs on documents!  Not every file on the system (or even outside the current folder).  Thankfully this means the systems are not locked out -- this was very nice of the ransomware group! (and has absolutely not bearing on the solution)!

Starting with the IV value, if we open the encrypted PDF file, we can see that indeed the IV is included at the start of the file:

![](/T9/Files/Pasted%20image%2020221207134901.png)

```
First piece of the puzzle (IV): fa0b3b71c485370604d4f6bfea6e3992
```

Now that we have the IV and we know the cipher mode, the last piece that we need to derive is the actual Key used in the encryption of the file.  This proved to be the most difficult part of this task.  We need the EXACT time that the file was encrypted to be able to derive the key...

I started by looking at the website that the ransom note was sitting on.  It had a timer value that was likely associated to the time of when the files were encrypted

![](/T9/Files/Pasted%20image%2020221207135545.png)

First, the time appears to be in the negative.  This means that the window of time to decrypt the files had already passed.  However, if we subtracted that time from the current date, we come to a day in March.

This didn't seem correct through, as looking back at A1, when the malicious activity was originally detected, we see the date was actually February 15.  If we subtracted the March date from the February date, we come to find out that there is a 30 day difference.

This means that the victims have 30 days from the time the ransomware was run to pay the ransom or the key is 'destroyed'.  Perhaps this is why the key is not listed in the keyMaster.db file.

I tried using this as initial basis for deriving the key.  Yet, this was not enough.  Since UUIDs are generated down to the microsecond, trying to brute-force decrypt a single hours worth of UUIDs would take days... So a single day would take weeks.

I was on the right track, but obviously not close enough.  I was stumped here for another good chunk of time.  I knew there had to be a clue I was missing so that I could derive a more precise window of time.

I spent some time looking into how the UUID was generated and how each bit of data was used to generate the actual values.  Maybe I didn't need to be as precise as I thought?  Below is a breakdown of a UUID value and how each section contains information about the timestamp.
```
The time_low (the first 32 bits of data) contains the seconds values
The time_mid (next 16 bits) contained the value for minutes/hours
The time_high (next 12 bits) contained the value for days and years
The ver (next 4 bits) specifies the version (v1/2/3/4)
The clq sq hi/res/low (next 2 bytes) contains data on random values
The node (last 4 bytes) contains the MAC Address of the device it was generated on

   x   x    x   x    x   x    x   x-   
   00000111 01011110 10010011 00110000
   time_low   
   
   8   e    x   x-
   10001110 11001100
   time_mid
   
   1   1    e   c-
   00010001 11101100 
   time_high + ver
   
   b   1    7   6-
   10110001 01110110 
   clk sq hi/res/low
   
   1   2    e   d    f   d    5   7
   00010010 11101101 11111101 01010111
   node
```
The sections marked with X are things that needed to be generated, the actual hex values are things that could be derived from looking at all the other keys that were stored in the database after decrypting them.  This significantly reduces the keyspace we need to look into, however, the hardest part (microseconds) does not get any easier.

At this point, I decided to try doing a test-run in a controlled environment to see just how everything was being utilized again...  I started by generating a key using the binary from Task 8:

```
┌──(kali㉿kali)-[/ctf/NSA Codebreakers/T8/Files]
└─$ ./keyMaster lock 99999 9.9999 ProfuseHunter
{"plainKey":"e30227a7-767c-11ed-95a0-0800273b","result":"ok"}
```

Okay... So the value returned back from the web server uses the full UUID value...
Now, let's see how the key was used in the ransom.sh file again...

```sh
read -p "Enter encryption key: " key
hexkey=`echo -n $key | ./busybox xxd -p | ./busybox head -c 32`
```

Wait a minute.... We see that the key is echo'd into xxd and only part of the value appears to be used as the hexkey after the head command:
```
┌──(kali㉿kali)-[/ctf/NSA Codebreakers/T8/Files]
└─$ echo -n e30227a7-767c-11ed-95a0-0800273b | xxd -p | head -c 32                                              
65333032323761372d373637632d3131  
```
If we take this value and convert it back to ASCII, we get:
```
e30227a7-767c-11
^low    ^mid ^high
```
So this means that only the time value from the UUID is actually used in the key.  The rest of the UUID is essentially cut out and not even considered!  We are definitely getting closer now.... Yet, we still need to find the exact time of when the key was generated in order to figure out the time.

Before I let a brute-force script run, I wanted to sanity check my process.  I went ahead and created a temp folder and ran the ransomware tools against a single PDF with the text "TEST" inside.

![](/T9/Files/Pasted%20image%2020221207144503.png)

I then created a python script that used the IV and UUID to try and decrypt the file.  I wanted it to brute-force, so I ever-so-slightly modified the UUID values by a couple hundred micro-seconds to create a range of UUID's to test.

After running the script, I was able to decrypt the file.  I used the magic bytes (%PDF) to test to see if the file was decrypted.  After opening the decrypted file, I was presented with the "Test" in a PDF.  This confirmed to me that my script was going to work, provided I had given the correct range for the UUIDs on the task file.

Once again, I come back to the part where I am missing that one last piece though - I needed a precise window of time to run the script against the encrypted file.  After spending a couple of days reviewing the site again and all the files associated with the challenge.... I finally found it.

In fact, I had actually found it back in Task 8 and didn't even realize I did!

When I was looking back through the server-side code for the lock requests.... Right after the UUID/Key is generated, the transaction is LOGGED in keygeneration.log file!  It was right in front of me the whole time... 

```python
with open("/opt/ransommethis/log/keygeneration.log", 'a') as logfile:
	print(f"{datetime.now().replace(tzinfo=None,
	microsecond=0).isoformat()}\t
	{util.get_username()}\t
	{cid}\t
	{request.args.get('demand')}", file=logfile)
	return jsonify({'key': jsonresult['plainKey'], 'cid': cid})
```

Here we see that the microseconds value is stripped off the timestamp, but the exact Day/Hour/Minute/Second value IS stored.  This was the missing piece of the puzzle.
```
2022-02-15T09:59:42-05:00	WiseGeneration	95876	4.718
```
Here we see the timestamp that matches February 15, which we should expect
We see the same CID value that is used in the demand endpoint back on the webserver
We also see the exact ransom that was requested which was shown on the website

This was it... We had the Timestamp down to the second!
Using some online UUID Generation Tools, we can re-create the UUID values for this timestamp within a range.

Since UUIDs are in UTC, we need to add +0500 to the time:
```
2022-02-15T14:59:42
```
Then we need to create a starting and ending point for a range of microseconds
```
(START) ce949200-8e6f-11xx-xxxx-xxxxxxxxxxxx       2022-02-15 14:59:00.000000.0 UTC
( END ) f257d800-8e6f-11xx-xxxx-xxxxxxxxxxxx       2022-02-15 15:00:00.000000.0 UTC
```
SIDE NOTE: I originally limited myself to just the couple second around the timestamp, but this was not successful.  I figured there was probably some margin of error between system times, so I expanded this out to one minute.

Finally.... I have all the pieces I need: We have the IV, a range of values for the UUID based on a precise timestamp, and the algorithm AES-128-CBC.

Below is the full script I used with comments.  At a high level, I used the UUID, converted that into an INT value for the timestamp START and END, loop through the difference between those two values, converting that INT back into the UUID format where I would append the trailer of '-11'.

The IV used was from the provided IV at the start of the encrypted file.

Each decryption was then checked to see if the first few bytes contained the PDF header (magic bytes) of 0x25504446 (%PDF).  If that value was found, the key was printed to the screen and the decrypted file was written out.
NOTE: I should only be checking the first 4 bytes of the file, but I wanted to catch the possibility that the header was off by a few bytes, so I checked the first 8.

```python
#!/bin/python

from Crypto.Cipher import AES
import time
import sys

t1 = "ce949200-8e6f"  #start time
t2 = "f257d800-8e6f"  #end time
p1 = "-11"            #trailer of key/UUID

# IV Value from File
iv = b'\xfa\x0b\x3b\x71\xc4\x85\x37\x06\x04\xd4\xf6\xbf\xea\x6e\x39\x92'

# PDF Magic Bytes
mb = b'\x25\x50\x44\x46'

# open and read the file
data = open("important_data.pdf.enc","rb").read()

# trim out the IV (not part of encrypted data)
data = data[32:]

# Split and join the hex values to generate a string of hex that represents
# the timestamps in the correct order (MM/DD/YYYY HH:MM:SS.MMMMMM.M)
start = t1.split('-')[1] + t1.split('-')[0]
finish = t2.split('-')[1] + t2.split('-')[0]

# convert the hex into INT values
a = int(start,16)
b = int(finish,16)

# Find the difference between the two times (in microseconds)
cnt = b - a
cur = 1

# Estimated Completion Time Calculation (VERY ROUGH)
ticks = cnt / 100000  # Define ticks as possibilities/100000
secs = ticks * 2.0496 # Roughly 204,960 iterations a second
mins = secs / 60      # Standard calculations on secs/hours/mins/days
hours = mins / 60
days = hours / 24

print(f'Total Guesses: {cnt}\nDays: {int(days%365)}, Hours: {int(hours%24)}, Mins: {int(mins%60)}, Seconds: {int(secs%60)}')

# decryption routine
def decrypt(key, file):
    cipher = AES.new(key, AES.MODE_CBC, iv)  #create new cipher
    output = cipher.decrypt(file)            # decrypt
    if mb in output[0:8]:                    # check first 8 bytes for %PDF
        print(f'FOUND PDF HEADER\n{key}')    # if found, print key
        with open("imortant_data.pdf", "wb") as f:
            f.write(output)                  # save decrypted file
            input("Press [ENTER] to keep going...")  # prompt to keep going

# loop through every microsecond between the two timestamps
for x in range(a,b+1): 
    x = str(hex(x)[2:])              #strip 0x from new hex number
    temp = x[4:] + '-' + x[0:4] + p1 #recreate the UUID format
    temp = bytes(temp[:32], 'utf-8') #Convert to bytes
    decrypt(temp, data)              #Attempt Decrypt
    cur += 1                         
    if cur % 100000 == 0:            #update the time remaining every 100k attempts
        print('\b'*8 + f'{(cur/cnt)*100:.4f}%', end='')
        sys.stdout.flush()
```

```
┌──(kali㉿kali)-[/ctf/NSA Codebreakers/T9/Files]
└─$ ./final.py
Total Guesses: 600000000
Days: 0, Hours: 1, Mins: 4, Seconds: 59
53.7183% FOUND PDF HEADER
b'e1cac6c7-8e6f-11' 
```
Let's try opening this decrypted file that the brute-forcer found...

![](/T9/Files/Pasted%20image%2020221116180707.png)

SUCCESS!  ALL TASKS COMPLETED!

![](/T9/Files/badge9.png)

#### *Bonus Section*
```
The encryption key was:
   e1cac6c7-8e6f-11

The timestamp associated with the key was:
   2022-02-15 14:59:32.231955.9 UTC
```
Based on the format of all other UUIDs in the victims.db file (which can be decrypted from the encryptionKey column using the key-encrypting-key), the FULL UUID Value in the database for this specific victim would have been:
```
e1cac6c7-8e6f-11ec-b176-12edfd570000
```
