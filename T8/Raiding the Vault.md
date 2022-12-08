You're an administrator! Congratulations!

It still doesn't look like we're able to find the key to recover the victim's files, though. Time to look at how the site stores the keys used to encrypt victim's files. You'll find that their database uses a "key-encrypting-key" to protect the keys that encrypt the victim files. Investigate the site and recover the key-encrypting key.

Prompt:
-   Enter the base64-encoded value of the key-encrypting-key

---

Looks like we need to investigate the source code more thoroughly again and see how the database is being interacted with.

Within the server.py file we see that logs are created in lock() :

```python
def lock():
	if request.args.get('demand') == None:
		return render_template('lock.html')
	else:
		cid = random.randrange(10000, 100000)
		result = subprocess.run(["/opt/keyMaster/keyMaster", 
								 'lock',
								 str(cid),
								 request.args.get('demand'),
								 util.get_username()],
								 capture_output=True, check=True, text=True, cwd="/opt/keyMaster/")
		jsonresult = json.loads(result.stdout)
		if 'error' in jsonresult:
			response = make_response(result.stdout)
			response.mimetype = 'application/json'
			return response
		
		with open("/opt/ransommethis/log/keygeneration.log", 'a') as logfile:
			print(f"{datetime.now().replace(tzinfo=None, microsecond=0).isoformat()}\t{util.get_username()}\t{cid}\t{request.args.get('demand')}", file=logfile)
		return jsonify({'key': jsonresult['plainKey'], 'cid': cid})
```

So, anytime ransom is demanded, the logs for that transaction are stored in a file /opt/ransommethis/log/keygeneration.log

There is also an endpoint that on the site called fetchlog() -- If we look at the function we can request access to this log using the ?log= parameter:

```python
def fetchlog():
	log = request.args.get('log')
	return send_file("/opt/ransommethis/log/" + log)
```

```
https://ukzcouspczgmbzmx.ransommethis.net/etvdmxhpgpvdweyg/fetchlog?log=keygeneration.log

       Time                    User             RNG     Demand
2021-01-05T22:05:35-05:00	LopsidedGoodness	35209	9.809
2021-01-06T23:57:29-05:00	ProfuseHunter	    43561	3.432
2021-01-13T10:08:54-05:00	SoftPopcorn	        29547	1.414
2021-01-19T00:40:00-05:00	EfficientSorghum	30407	3.055
... Trimmed ...
2022-04-22T17:09:47-05:00	BrawnyDimple	    26742	6.296
2022-05-02T16:38:55-05:00	DisillusionedMailer	19479	0.575
2022-05-07T11:41:48-05:00	DomineeringStool	36302	6.341
2022-05-29T14:53:56-05:00	SuperLogistics	    17962	5.711
```

Since it appears that there is no sanitation on what is gathered from this endpoint, we can also do some directory traversal to obtain a copy of what appears to be the binary file that is used in the lock()/unlock() endpoints.

We see the following path for the key generating tool:

/opt/keyMaster/keyMaster

And the default log path is:

/opt/ransommethis/log/

So we need to go up 2 folders and then down to keyMaster:

?log=../../keyMaster/keyMaster

...and now we have the binary file associated with this servers key generation!

![keyMaster](/T8/Files/keyMaster)


Fun side note:  If you just go up to /opt/  (?log=../../) You get a fun little message:

![](/T8/Files/Pasted%20image%2020221109144930.png)

We can also pull down full copies of the databases (/opt/ransommethis/db/user.db and /opt/ransommethis/db/victims.db).  Both of these file paths are found in the util.py file

Let's start by peeking through the databases and see what we find.  While perhaps not useful right away, we can finally see the pwhash of the users now.  We can also verify that we had the correct information from the output of sqlmap (see bonus info at end of Task 8)

![](/T8/Files/Pasted%20image%2020221117220647.png)

The victims DB only has one table: cid, dueDate, Baddress, pAmount -- Without further information about how the data in this table is used, we will likely need to look into the binary file.  Nothing from these databases is giving us a clue about how keys are generated.

![](/T8/Files/Pasted%20image%2020221109150349.png)

Just based on the server.py file we can tell what some of the arguments are in binary program:
```
$ keyMaster lock RNG DEMAND HACKERNAME
$ keyMaster unlock RECEIPT
$ keyMaster credit HACKERNAME CREDIT RECEIPT

RNG = Random Number [10000-99999] (INT)
HACKER = Hacker Username (STR)
CREDIT = Amount (FLOAT)
DEMAND = Amount (FLOAT)
RECEIPT = ?
```
Since the website doesn't seem to report or respond with anything relating to the receipt or the key-encrypting-keys, it's time to do some reverse engineering....

Running strings, we find some things of interest:

First is the presence of several .go files which means this was likely programmed with GoLang:

```
One Line from Strings Output:
/generator/cmd/keyMaster/main.go
```
Next is that we see several hard-coded strings for SQL:
```sql
INSERT INTO customers (customerId, encryptedKey, expectedPayment, hackerName, creationDate) VALUES (?, ?, ?, ?, ?)
SELECT encryptedKey, expectedPayment FROM customers WHERE customerId = ?
```
We can see that there is another customers table.  If we hunt through the strings more we also find a few instances of keyMaster --- Taking this and using grep we see one particular string of interest:

./keyMaster.db

If we go back to the fetchlog() function in the website, we can try and request this database... and it works (and maps to the INSERT query from above)

![](/T8/Files/Pasted%20image%2020221207124135.png)

```
customerID: INT
encryptedKey: BASE64 Encoded String
expectedPayment: FLOAT
hackerName: STR
creationDate: STR
```
Decoding the encryptedKey gives us gibberish -- Based on the prompt, it sounds like this is the decryption key, but its been encryped with the key-encrypting-key and base64 encoded.

When reversing go binaries, we need to located the main.main() function as this is the actual start point of the program data.  If we follow the instruction flow, we see that the command line argument is parsed in pieces that lead to the functions associated with LOCK, UNLOCK, CREDIT, etc..

![](/T8/Files/Pasted%20image%2020221207124547.png)

After verifying the remaining command line arguments, we see that a function is called to generate a UUID value.  UUID values are based on the current time, down to the microsend.

![](/T8/Files/Pasted%20image%2020221207124734.png)

We then see that the values are all saved, presumably as input values for the encryption key that is actually used.  Then this information is passed into another function which I have named "encrypt_1":

![](/T8/Files/Pasted%20image%2020221207124924.png)

![](/T8/Files/Pasted%20image%2020221207124959.png)

After stepping through "encrypt_1", I was able to derive the key.  It appears to be derived from a hard-coded value in the binary.  The magic happens around here:

![](/T8/Files/Pasted%20image%2020221113123258.png)

The gen_new_sha256_key() generates the key at runtime.  It takes a hardcoded base64 string from the program, decodes that into bytes:
```
Base64: 0MJ7bUsqs5Yb65fgfQojSYudPhz+mX9632kc2m6JIeI=
Bytes:  d0c27b6d4b2ab3961beb97e07d0a23498b9d3e1cfe997f7adf691cda6e8921e2
```

![](/T8/Files/Pasted%20image%2020221113125333.png)

Another hard-coded chunk of data is then built out (88 Bytes in Size):
```
0xc00007e0c0:   0x32    0xfb    0xfc    0x2b    0x08    0x1e    0xe5    0xc9
0xc00007e0c8:   0x32    0x0e    0xb1    0x71    0x85    0x96    0xa7    0x1d
0xc00007e0d0:   0xfc    0xd4    0x4b    0x1e    0x28    0xeb    0xef    0x02
0xc00007e0d8:   0x2e    0xb3    0x69    0xbf    0x93    0xba    0x2f    0xcd
0xc00007e0e0:   0xfe    0x4b    0x31    0x70    0x93    0xaf    0x53    0x17
0xc00007e0e8:   0xba    0x67    0xf8    0x8a    0xc3    0x2d    0xf6    0xe1
0xc00007e0f0:   0x74    0x0b    0x2c    0x92    0xd1    0x59    0x26    0xb2
0xc00007e0f8:   0x64    0xba    0xa0    0xbc    0x01    0xce    0xfd    0x5e
0xc00007e100:   0x3e    0x12    0xe4    0xdb    0x4e    0x25    0x84    0x70
0xc00007e108:   0xac    0xbe    0xdd    0x2a    0xc3    0xaa    0x25    0x73
0xc00007e110:   0x68    0x91    0xe9    0x59    0x2c    0xb0    0x20    0xf5

32fbfc081ee5c9320eb18596a71dfcd44b28ebef022eb36993ba2fcdfe4b3193af5317ba67f8c32df6e1740b2cd15926b264baa001cefd5e3e12e44e258470acbeddc3aa25736891e92cb020f5
```
Again another smaller block of data is then pulled from the stack
```
0x85d660:       0x64    0x8f    0x98    0x13    0x44    0x5f    0xa6    0x98
0x85d668:       0x61    0x5f    0xd7    0x1d    0xc8    0xe7    0x8c    0x00

64af8f9813445fa698615fd71dc8e78c
```
Each byte of the smaller version is then XOR'd with each byte of the longer version.

![](/T8/Files/Pasted%20image%2020221113125412.png)

This repeats until the full block is decoded into this Base64 string:

```
Vtd8LACQSQflMq+ysLXZwMwcqdtwt6KBfXu/572Hmz0mOIyygOs4I8yeyrG0eAeMzMBC/zSmdYQNL26777q8sg==
```

This is then used as the password into the AES Key generating algorithm:

![](/T8/Files/Pasted%20image%2020221113125658.png)

```
	pbkdf2.Key(password,salt,4096,32,sha256.New)
	Password = Vtd8LACQSQflMq+ysLXZwMwcqdtwt6KBfXu/572Hmz0mOIyygOs4I8yeyrG0eAeMzMBC/zSmdYQNL26777q8sg==
	Salt = 96b32a4b6d7bc2d0
	Iter = 4096
	KeyLen = 32
	Hash = SHA256
```
This then puts out the value in RAX of:
```
2aa91ae6a1669eeeb3cc71fb4f60990ffd7d70de172b68f7269ef3a776911ec1
```
This is then used as input into crypto_aes_NewCipher.  From the documentation for this function we see that one of the arguments is the encrypting key:

```
func NewCipher(key []byte) (cipher.Block, error)

NewCipher creates and returns a new cipher.Block. 
The key argument should be the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
```

Following this is the gold (hence the yellow background!) where the randomly generated encryption keys are created and then encrypted.

![](/T8/Files/Pasted%20image%2020221207130112.png)

This confirms that the above value returned in RAX from the XOR'd key value is indeed the key-encrypting-key!  That key is used to create a new cipher block where the client's encryption key is generated and encrypted again to be stored in the database.

We then need to take the byte-data of that key-encrypting-key and Base64 encode that.  When done we end up with:

```
Kqka5qFmnu6zzHH7T2CZD/19cN4XK2j3Jp7zp3aRHsE=
```

When submitting this value, we find that we were indeed correct!

![](/T8/Files/badge8.png)

#### *BONUS: Random Bits of Info*

Additional Scratch-Paper Notes below on how input data is being used -- I kept these notes and am glad that I did as this came into play during the last task!  I'll leave them here since this was part of the work that I did during this task.

Namely, this follows HOW the client encryption key is being generated from the UUID value when requesting a new encryption key from the server and then stored in the databases.

```
UUID:
14e7390b-61ed-11ed-93b1-0800273b6e7b
14e7390b-61ed-11ed-93b1-0800273b6e7b
	Contents - Time	2022-11-11 18:17:20.419457.1 UTC
	Contents - Clock	5041 (usually random)
	Contents - Node	08:00:27:3b:6e:7b (global unicast)
		VER: 1
		VAR: DCE 1.1, ISO/IEC 11578:1996

Time
2006-01-02T15:04:05Z07:00 Fmt String
2022-11-11T11:09:58-08:00 Result

Rand Size: 0x10
	0x315431313a30393a35382d30383a3030

Base64 String
	0MJ7bUsqs5Yb65fgfQojSYudPhz+mX9632kc2m6JIeI=

	ASCII: ÐÂ{mK*³..ë.à}
		   #I..>.þ..zßi.Ún.!â
	Hex: d0c27b6d4b2ab3961beb97e07d0a23498b9d3e1cfe997f7adf691cda6e8921e2

	RSI - 648f9813445fa698615fd71dc8e78c00 << XOR KEY
	RDI - 32fbfc2b081ee5c9320eb1718596a71d fcd44b1e28ebef022eb369bf93ba2fcd  32
          fe4b317093af5317ba67f88ac32df6e1 740b2c92d15926b264baa0bc01cefd5e  64
		  3e12e4db4e258470acbedd2ac3aa2573 6891e9592cb020f5                  88 
	RSI ^ RDI = Password
	
	See Below:
		pbkdf2.Key(password,salt,4096,32,sha256.New)
		Password = Vtd8LACQSQflMq+ysLXZwMwcqdtwt6KBfXu/572Hmz0mOIyygOs4I8yeyrG0eAeMzMBC/zSmdYQNL26777q8sg==
		Salt = 96b32a4b6d7bc2d0
		Iter = 4096
		KeyLen = 32
		Hash = SHA256

			2aa91ae6a1669eeeb3cc71fb4f60990ffd7d70de172b68f7269ef3a776911ec1


0xc000138338 = 0x10101010101010101010101010101010
0xc00012a210 = UUID

14e7390b-61ed-11ed-93b1-0800273b6e7b
Changed to:
14e7390b-61ed-11ed-93b1-0800273b + 0x10101010101010101010101010101010

8e8e408a38cf794bab3d3c278e203d2d4d9f1c1d0068948184d2f6786adba001
2aa91ae6a1669eeeb3cc71fb4f60990ffd7d70de172b68f7269ef3a776911ec1

14e7390b-61ed-11ed-93b1-0800273b6e7b (36 Len - 0x24 [w/o '-' 32 Len - 0x20])

RAX = BLOCK SIZE?   = 0x10
RBX = KEY           = 2aa91ae6a1669eeeb3cc71fb4f60990ffd7d70de172b68f7269ef3a776911ec1
RCX = IV?           = 30b401d6289387baee42edb85cbf6f82

$R11
    4a515862787a7c7e    95a9aab2cbd8d9dc    16
    dde5ff0140030409    9211011102134e16    32
    032504251128012b    032c0138313b1841    48
    0249024912493155    0155055515555565    64
    
    e30f9861446b4462    7852fd357e92093d
   
    < Result > ??
    30b401d6289387baee42edb85cbf6f82    1976c24b35068fbf0c5395c881703010    02b779bde01db1d0fb941fe7fb737dfe    62446b4461980fe33d09927e35fd5278
    30b401d6289387baee42edb85cbf6f821976c24b35068fbf0c5395c88170301002b779bde01db1d0fb941fe7fb737dfe62446b4461980fe33d09927e35fd5278
    
    1976c24b35068fbf0c5395c881703010    02b779bde01db1d0fb941fe7fb737dfe    62446b4461980fe33d09927e35fd5278
    
    
    FN(EncKey, CID, HackerName, len(HackerName), Timestamp, len(Timestamp))
            
    EncKey  30b401d6289387baee42edb85cbf6f821976c24b35068fbf0c5395c88170301002b779bde01db1d0fb941fe7fb737dfe62446b4461980fe33d09927e35fd5278
    CID     54321
    Ransom  9.8765
    Hacker  ProfuseHunter
    len(^)  13
    Time    2022-11-11T11:09:58-08:00
    len(^)  25
```
