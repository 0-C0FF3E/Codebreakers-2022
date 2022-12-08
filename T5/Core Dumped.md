The FBI knew who that was, and got a warrant to seize their laptop. It looks like they had an encrypted file, which may be of use to your investigation.

We believe that the attacker may have been clever and used the same RSA key that they use for SSH to encrypt the file. We asked the FBI to take a core dump of `ssh-agent` that was running on the attacker's computer.

Extract the attacker's private key from the core dump, and use it to decrypt the file.

_Hint: if you have the private key in PEM format, you should be able to decrypt the file with the command `openssl pkeyutl -decrypt -inkey privatekey.pem -in data.enc`_

Prompt:
-   Enter the token value extracted from the decrypted file.

---

![core](/T5/Files/core)
![data.enc](/T5/Files/data.enc)

Using this blog (https://vnhacker.blogspot.com/2009/09/sapheads-hackjam-2009-challenge-6-or.html) as a point of reference, we need first we need to find the pointers to the private key structure.

Based on what we see, we should be able to find a listing of /tmp/ssh-RANDOM/agent.ID

Right before the temp name of the key are some pointers that we can use to follow that will lead us to the actual key data.

The image below shows what it looks like from the blog post

![](/T5/Files/Pasted%20image%2020221108112231.png)

When looking through the core file in a hex editor, we can find this same structure of data by searching for the /tmp/ssh value -- This is the beginning of the breadcrumbs that we need to go backwards to the key itself.

![](/T5/Files/Pasted%20image%2020221108112358.png)

We will start with using objdump -s (displays raw content of all sections found) on the core file to spit out the data in memory.

NOTE: This is in memory though, so the byte-order is little-endian which means we need to convert to big-endian when working with data (unless its a char data or similar)

![objdump.txt](/T5/Files/objdump.txt)

Since we only have one pointer, it makes it easier to follow.  It points to an IDTABLE structure which we can find the definition of inside of  sshkey.c  from the source code for openssh:

```c
struct idtable {
	int nentries;           
	TAILQ_HEAD(idqueue, identity) idlist;
};
```

We can then go to the idtable pointer using the address we found.
 and then follow that address:
```
 c0 f3 61 f2 0b 56  --> 560bf261f3c0
```
At that address we find the following information:
```
 Address    | nentries        | idlist
560bf261f3c0|01000000 00000000|904b62f2 0b560000  .........Kb..V..
            |                 |
```
The idlist value holds a pointer to an IDENTITY structure (identity) which we can also find defined in the openssh source files:
```c
typedef struct identity {
   TAILQ_ENTRY(identity) next;
   struct sshkey *key;
   char *comment;
   char *provider;
   time_t death;
   u_int confirm;
   char *sk_provider;
} Identity;
```
Let's convert the identity structure and go to that address
```
 90 4b 62 f2 0b 56  --> 560bf2624b90

  Address    | next            | key
 560bf2624b90|00000000 00000000|c8f361f2 0b560000  ..........a..V..
             | comment         | provider
 560bf2624ba0|e02e62f2 0b560000|000c62f2 0b560000  ..b..V....b..V..
             | death  | confirm| sk_provider
 560bf2624bb0|00000000|00000000|00000000 00000000  ................
             |        |        |
```
This key pointer is what we want to dig into

The sshkey struct is a pointer that holds the actual RSA key data.  Again we can find this structure definition within the openssh source code.

NOTE: Instead of doing the previous breakdown of memory, I've listed things in-line with the variables of the structure to save space.
```c
struct sshkey {                     //c8 f3 61 f2 0b 56  --> 560bf261f3c8
  int	 type;                      //00000000
  int	 flags;                     //00000000
  RSA	*rsa;                       //e06062f2 0b560000
  DSA	*dsa;                       //00000000 00000000
  int	 ecdsa_nid;                 //ffffffff
  EC_KEY	*ecdsa;                 //00000000 00000000
  u_char	*ed25519_sk;            //00000000 00000000
  u_char	*ed25519_pk;            //00000000 00000000
  char	*xmss_name;                 //00000000 00000000
  char	*xmss_filename;             //00000000 00000000
  void	*xmss_state;                //00000000 00000000
  u_char	*xmss_sk;               //00000000 00000000
  u_char	*xmss_pk;               //00000000 00000000
  char	*sk_application;            //00000000 00000000
  uint8_t	sk_flags;               //00000000
  struct sshbuf *sk_key_handle;     //00000000 00000000
  struct sshbuf *sk_reserved;       //00000000 00000000
  struct sshkey_cert *cert;         //00000000 00000000 
  u_char	*shielded_private;      //b05a62f2 0b560000   --> 560bf2625ab0
  size_t	shielded_len;           //0570                --> 1392
  u_char	*shield_prekey;         //006c62f2 0b560000   --> 560bf2626c00
  size_t	shield_prekey_len;      //4000                --> 16384
};
```
Within that structure is a shielded_private and shielded_prekey that are used to symetrically encrypt/decrypt the key whenever it is used.  When its not in use, its encrypted in memory to prevent that data from being leaked.

However, if we can recover both the pre-key and the private-key, then we can force decryption of the key in memory into its plaintext format.

Using another blog post (https://security.humanativaspa.it/openssh-ssh-agent-shielded-private-key-extraction-x86_64-linux/) as the next point of reference, we are able to see that we need to dump the data of the shielded_private and shield_prekey pointers.

Of considerable note here (and to verify that this is the correct pointer) is the shield_prekey_len value.  This is always 0x4000 (16KB).

So we can be fairly certain that if the shielded_prekey_len is 0x4000 (16,384 bytes), we have found the encrypted key, and the same goes for the shielded_private key.

Let's start with the shielded_private:
```
Step 1 - Go to the address of char* shielded_private: 0x560bf2625ab0
 560bf2625aa0 00000000 00000000 81050000 00000000  ................
 560bf2625ab0 7c089b47 76288db1 a457c7bf c2474949  |..Gv(...W...GII  <<< PTR Address 
 560bf2625ac0 e603c411 666f580a 6abc7b6d 84f0e4f3  ....foX.j.{m....

Step 2 - Add the shielded_len to the start address to find the the expected endpoint:
	0x560bf2625ab0 + 0x570 = 0x560BF2626020

Step 3 - Go to the calcualted endpoint and see if the data ends properly:
 560bf2626010 21f132fd 2d793bf8 ee2597c7 f9128ef7  !.2.-y;..%......
 560bf2626020 00000000 00000000 b1000000 00000000  ................ << END Point
```
It looks like this is a perfect match for the data!!

Now we need to save these raw bytes into a file.

I just removed the ASCII column, the memory address column, and then removed spaces/newlines which left me with a long string of hex values.

Using a hex editor, I just pasted that cleaned up byte data and saved the file as "shielded_private"

Now we need to do the same process again for the shielded_prekey:
```
Step 1 - Go to the address of char* shielded_prekey: 0x560bf2626c00
 560bf2626bf0 00000000 00000000 11400000 00000000  .........@......
 560bf2626c00 14e16a8d 95b0674f 51268721 d3ee22fa  ..j...gOQ&.!..". << PTR Address
 560bf2626c10 8b6521fa ef65c161 4d5837f4 5d52117e  .e!..e.aMX7.]R.~

Step 2 - Add the shielded_prekey_len to the start address to find the expected end:
	0x560bf2626c00 + 0x4000 = 0x560BF262AC00

Step 3 - Go to the calculated endpoint and see if the data ends properly:
 560bf262abd0 550dfb68 953c53ff 0d39dd32 992fd5b8  U..h.<S..9.2./..
 560bf262abe0 4407b759 9a950e21 25bbb18c cb20cd3a  D..Y...!%.... .:
 560bf262abf0 44f05874 8786410b 96579aa3 46bd4ac2  D.Xt..A..W..F.J.
 560bf262ac00 00000000 00000000 01a40100 00000000  ................ << END Point
```
Looks like another perfect match!!

The data just needs to be cleaned up as before and dumped into a hex editor and saved as "shielded_prekey"

![shielded_prekey](/T5/Files/shielded_prekey)

![shielded_private](/T5/Files/shielded_private)

Now that we have the raw values, we need to decrypt the keys.  In order to do this we need to build the sshkeygen binary file with debugging options so that we have access to the functions inside of the program.

Using the same version of openSSH as the blog post (8.6p1), we can find the source code and then prepare to build the ssh-keygen tool:
```sh
$ tar xvfz openssh-8.6p1.tar.gz
$ cd openssh-8.6p1
$ ./configure --with-audit=debug
$ make ssh-keygen
$ gdb ./ssh-keygen
```
Once in GDB, we need to read in our shielded_prekey and shielded_private files into memory and then intialize a structure that points to them so that we can manually call the unshield function:


* Step 1: Set breakpoints and Run
```
b main              // Break on Main
b sshkey_free       // Break before sshkey_free
r                   // Run the program to get functions loaded
```

* Step 2: Create a new sshkey structure and allocate memory for our data
```
set $miak = (struct sshkey *)sshkey_new(0)            // Define new structure
set $shielded_private = (unsigned char *)malloc(1392) // Allocate for private
set $shield_prekey = (unsigned char *)malloc(16384)   // Allocate for prekey
```

* Step 3: Open the shielded_private file and read its data into the allocated memory
```
set $fd = fopen("./shielded_private", "r")   // Get a FD for shielded_private
call fread($shielded_private, 1, 1392, $fd)  // Read that data into our buffer
call fclose($fd)                             // Close the file
```

* Step 4: Open the shielded_prekey file and read its data into the allocated memory
```
set $fd = fopen("/tmp/shielded_prekey", "r")   // Get a FD for shielded_prekey
call fread($shield_prekey, 1, 16384, $fd)      // Read that data into our buffer
call fclose($fd)                               // Close the file
```

* Step 5: Update the sshkey structure pointers to point to the file data
```
set $miak->shielded_private=$shielded_private    // Set the ptr for shielded_private
set $miak->shield_prekey=$shield_prekey          // Set the ptr for shielded_prekey
set $miak->shielded_len=1392                     // Set the size for shielded_private
set $miak->shield_prekey_len=16384               // Set the size for shielded_prekey
```

* Step 6: Call the sshkey_unshield_private function manually
```
call sshkey_unshield_private($miak)
```

This will decrypt the key, but then breaks on the sshkey_free call before exiting.  Reasons why we need to break here:

We don't want the pointer to key that we just unshielded to actually be freed

The program will actually crash trying to free the PTR that GDB created because it doesn't have access to it since it was created in GDB

* Step 7: Capture the decrypted key data

At this point we are technically inside sshkey_free -- However, we want to step back a frame and get into the function that called this so we have access to *kp - The pointer to the decrypted key
```
bt                 // Verify the backtrace
f 1                // Step back to Frame #1 (from Frame #0)
```
Now, we need to examine the *kp value and make sure its not a NULL PTR -- if it is, we messed up somewhere and need to restart this whole process.  (This happened quite a few times for me as I learned how to get the file data setup just right! [Pro-Tip... Don't paste Byte Data in a standard text editor!  Use an actual HEX editor lol])

Note: the data here may still show 0's as the dereferenced value -- This is okay!  We just need to be sure the PTR is available to be dereferenced
```
x *kp             // Examine *kp for a valid pointer
```
Assuming you were able to dereference the pointer, we now need to manually call the sshkey_save_private using *kp from this frame:
```
call sshkey_save_private(*kp, "plaintext_private_key", "", "comment", 0, "\x00", 0)

Then just kill the process & Quit
k                 // Kill ssh-keygen Process
q                 // Quit
```
Now we should have a plaintext private key in OPENSSH format!  If we cat out the plaintext_private_key we just saved, we can see that we got they key!

```
$ cat plaintext_private_key
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0bS0deVWLVuVIAyBh4U6hkXsrc0zKVbIBl8Aa6FNnOkshqFR7bCv
... trimmed ...
cqyoYkmoQTniV1MFB7sW6MhNNIqZue7zC2BC2TIKJxtRVzaxPqHvj2jvULQFfeGxfu71je
t5xTViE7cUv18AAAAHY29tbWVudAECAwQ=
-----END OPENSSH PRIVATE KEY-----
```

One last step remains before we can decrypt the file.  Right now we have an OpenSSH key file, but we need to convert it to the RSA Private Key (PEM) format.  First we need to convert the key into SSHv2 format, then we can use ssh-keygen to convert that into PEM.  

The first conversion can be done with PuTTY:
```sh
# INSTALL PUTTY
sudo apt install putty
sudo apt install putty-tools

# CONVERT TO SSHv2
puttygen plaintext_private_key -O private-sshcom -o private_key_sshv2

# CONVERT TO PEM
ssh-keygen -i -f private_key_sshv2 > private_key.pem
```

If we inspect the contents of private_keu.pem, we can see that we have changed the format of the key into a standard RSA Key Format:
```
-----BEGIN RSA PRIVATE KEY-----
MIIG5AIBAAKCAYEA0bS0deVWLVuVIAyBh4U6hkXsrc0zKVbIBl8Aa6FNnOkshqFR
7bCvfENg6Tp/lpQkiGTT0XMB/8wVQLqbysinE2XRe1OedB2fFc41nnX7jutCoCXb
... trimmed ...
fh6fYFDCi+aP4Rf84a0yvckFSVKW6YGZEW6MbEsQwG8Q9/zM9z88+SleOkOqtZaG
ULvp9eOc4r2vAwZQu++o7/KreUetUrpXBOpDxF+jorPWqJ2YBM1CiA==
-----END RSA PRIVATE KEY-----
```

We can now FINALLY decrypt the data.enc file that was provided in the challenge and grab the token value:
```
$ openssl pkeyutl -decrypt -inkey private_key.pem -in data.enc 
```

And we find...
```
# Netscape HTTP Cookie File
ukzcouspczgmbzmx.ransommethis.net       FALSE   /       TRUE    2145916800      tok     eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM3Mzg4NzEsImV4cCI6MTY1NjMzMDg3MSwic2VjIjoiYWxqMURCWEFlSU1qaXVockt0Ylg4UUFvUU9HTHk2dnkiLCJ1aWQiOjM3MDM3fQ.sL_genzXKpGkNrgu07kV6Plu2AjMHE90DXdrameoegw 
```

```
Answer: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM3Mzg4NzEsImV4cCI6MTY1NjMzMDg3MSwic2VjIjoiYWxqMURCWEFlSU1qaXVockt0Ylg4UUFvUU9HTHk2dnkiLCJ1aWQiOjM3MDM3fQ.sL_genzXKpGkNrgu07kV6Plu2AjMHE90DXdrameoegw
```

![](/T5/Files/badge5.png)
