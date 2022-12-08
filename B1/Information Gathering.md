The attacker left a file with a ransom demand, which points to a site where they're demanding payment to release the victim's files.

We suspect that the attacker may not have been acting entirely on their own. There may be a connection between the attacker and a larger ransomware-as-a-service ring.

Analyze the demand site, and see if you can find a connection to another ransomware-related site.

Prompt:
-   Enter the domain name of the associated site.

![YOUR_FILES_ARE_SAFE.txt](/B1/Files/YOUR_FILES_ARE_SAFE.txt)

```
Let's start with analyzing what we have -- the txt file:


Your system has been breached by professional hackers.  Your files have been encrypted, but they are safe.
Visit https://txlwuygwxgbvajzp.unlockmyfiles.biz/ to find out how to recover them.


Since we don't have much else to go on, lets visit the site and see what we find:
```

![](/B1/Files/Pasted%20image%2020221116205658.png)

```
There isn't much more to go off of at face value, however we should look into the source code and see if there is anything else.
Within the site content, we see a connect.js script, however it appears to be highly obfuscated.
```

![](/B1/Files/Pasted%20image%2020221116211005.png)


```
Before we dig into that, lets check into the other usual places to see if we see anything else happening.  Next we can check the Network tab for any transactions of interest.  

When we reload the page, we find that there is indeed something different here.  While everything appears to come from one domain, there is one extra GET request that is coming from a different subdomain.  

https://ukzcouspczgmbzmx.ransommethis.net/demand?cid=95876
```

![](/B1/Files/Pasted%20image%2020221101202041)

```
It is technically a subdomain, but its different than the rest of the site.  If we visit the domain we get an Unauthorized message, but the footer lets us know that this is indeed part of the challenge.
```

![](/B1/Files/Pasted%20image%2020221116220423.png)

```
Answer: ukzcouspczgmbzmx.ransommethis.net
```

![](/B1/Files/badgeb1.png)
