Using the timestamp and IP address information from the VPN log, the FBI was able to identify a virtual server that the attacker used for staging their attack. They were able to obtain a warrant to search the server, but key files used in the attack were deleted.

Luckily, the company uses an intrusion detection system which stores packet logs. They were able to find an SSL session going to the staging server, and believe it may have been the attacker transferring over their tools.

The FBI hopes that these tools may provide a clue to the attacker's identity

Prompt:
-   What was the username of the account the attacker used when they built their tools?

![[root.tar.bz2]]
![[session.pcap]]

```
The PCAP contains nothing but encrypted data.  So without the proper RSA key, we will not be able to make any use of this.  However, in the root.tar.bz file, we find that there is a .cert.pem file that contains an RSA Private Key + Certificate.

If we import this in the TLS settings, we are able to see an important packet:
```

![[Pasted image 20221116203424.png|center]]

```
So we know that the tools.rar must be the tools that were transferred over.  However, we are still unable to see the raw file data in Wireshark.  We need to do some extra work on this capture to be able to see the traffic.

While I am sure there is probably a way to get this going properly within Wireshark, I opted for a different path using a tool called ssldump -- This should come standard with Kali, but can also be downloaded in a tarball from here: https://ssldump.sourceforge.net/

The first step is to isolate just the Private Key into its own file.  Just copy the private key out of the .cert.pem file and put it into priv.key

Then we can use ssldump with the following options:
	-k   Specifies the Private Key
	-r   Read from a PCAP file
	-d   Decrypt the data using the key
	-n   Don't resolve hostnames
	-w   Write to an output file
```

```
┌──(kali㉿kali)-[/writeups/NSA Codebreakers/A2/Files]
└─$ ssldump -k ./priv.key -r session.pcap -dnw decrypt.pcap
```

```
Opening this new decrypt.pcap file, we can now see that there are no more TLS packets in the list.  It was all stripped away during the decryption from ssldump.  Also, at the end of the capture, we can now see the HTTP 200 OK Packet which helps confirm that the traffic was decrypted as this was not available to us in the original capture.
```

![[Pasted image 20221116204810.png|center]]

```
From here, we can now use HTTP Object Export (File > Export Objects > HTTP) and extract the tools.rar file that we need.
```

![[Pasted image 20221116204918.png|center]]

```
If we open the tools.rar file with 7zip, we are able to see user/group information of the person that created the tools.rar file --- presumably also the same person that created them:
```

![[Pasted image 20221116205115.png|center]]

```
Answer: TenseSulkyPush
```

![[badgea2.png|center|400]]
