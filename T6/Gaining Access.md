We've found the login page on the ransomware site, but we don't know anyone's username or password. Luckily, the file you recovered from the attacker's computer looks like it could be helpful.

Generate a new token value which will allow you to access the ransomware site.

Prompt:
-   Enter a token value which will authenticate you as a user of the site.

```
Starting with the file we decrypted in the previous challenge we are handed this:

# Netscape HTTP Cookie File
ukzcouspczgmbzmx.ransommethis.net       FALSE   /       TRUE    2145916800      tok     eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM3Mzg4NzEsImV4cCI6MTY1NjMzMDg3MSwic2VjIjoiYWxqMURCWEFlSU1qaXVockt0Ylg4UUFvUU9HTHk2dnkiLCJ1aWQiOjM3MDM3fQ.sL_genzXKpGkNrgu07kV6Plu2AjMHE90DXdrameoegw 
```

```
The values seem to be based on a stored Netscape HTTP Cookie file format and appear to map to the following values:

DOMAIN = ukzcouspczgmbzmx.ransommethis.net
SUBDOMAINS = FALSE
PATH = /
SECURE = TRUE
EXPIRY = 2145916800  (Friday, January 1, 2038 12:00:00 AM)
NAME = tok
VALUE = eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM3Mzg4NzEsImV4cCI6MTY1NjMzMDg3MSwic2VjIjoiYWxqMURCWEFlSU1qaXVockt0Ylg4UUFvUU9HTHk2dnkiLCJ1aWQiOjM3MDM3fQ.sL_genzXKpGkNrgu07kV6Plu2AjMHE90DXdrameoegw 
```

```
If we examine the tok value, it resembles a Java Web Token (JWT) format

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTM3Mzg4NzEsImV4cCI6MTY1NjMzMDg3MSwic2VjIjoiYWxqMURCWEFlSU1qaXVockt0Ylg4UUFvUU9HTHk2dnkiLCJ1aWQiOjM3MDM3fQ.sL_genzXKpGkNrgu07kV6Plu2AjMHE90DXdrameoegw

Using cyberchef, we can easily decode this:
```

```json
{
    "iat": 1653738871,
    "exp": 1656330871,
    "sec": "alj1DBXAeIMjiuhrKtbX8QAoQOGLy6vy",
    "uid": 37037
}
```

```
The first two values appear to be epoch times and if we decode them as such, we get:

iat = Saturday, May 28, 2022 11:54:31 AM GMT
exp = Monday, June 27, 2022 11:54:31 AM GMT

So we can presume:
IAT = Issued At Time
EXP = Expiration Time

The UID appears to be the User ID Value
The SEC option still alludes us at this time.
```

```
Let's try updating the IAT and EXP values and see if this token will still allow access.  They appear to be exactly 30 days apart, down to the second, so we should keep this in mind.

Let's update IAT to the start of the current month:
1667260800 = Tuesday, November 1, 2022 12:00:00 AM GMT

And then set EXP to 30 days later (start of the next month):
1669852800 = Thursday, December 1, 2022 12:00:00 AM GMT

The difference between the two is 2592000.  Knowing that there are 86400 seconds in a day, we can do some quick division to make sure that these new epoch times are exactly 30 days apart:

259200 / 86400 = 30

We can use https://jwt.io/ to re-encode the key with these new values, giving us the following token value:

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjcyNjA4MDAsImV4cCI6MTY2OTg1MjgwMCwic2VjIjoiYWxqMURCWEFlSU1qaXVockt0Ylg4UUFvUU9HTHk2dnkiLCJ1aWQiOjM3MDM3fQ.V8Pa0C8BXP1qf1MH7VB9zcO7k3tfQhH8xki7OfeXxKY
```

```
Now we need to create a cookie and set all the proper settings as described but use the updated tok value:
```

![[Pasted image 20221117154103.png|center]]

```
Just updating the times doesn't seem to work though.  It seems that we are missing something.  Going back to Challenge B2, where we had pulled down all the source code for the server, we find some extra clues in server.py:
```

```python
	try:
		uid = util.get_uid()
	except util.InvalidTokenException:
		return redirect(f"/{pathkey}/login", 302)
```

```
It seems that our token is being validated by util.get_uid() --- But what is util?  
If we go to the top of the file we can look for what import this is:
```

```python
from . import util
```

```
It appears this is a local file on the server.  If you haven't already, use the same method from B2 to re-create the util.py file

Within this code we find the get_uid() function:
```

```python
def get_uid():
	""" Gets the logged-in user's uid from their token, if it is valid """
	token = request.cookies.get('tok')
	if token == None:
		print("No token cookie found!", file=sys.stderr)
		raise MissingTokenException
	if not validate_token(token):
		raise InvalidTokenException
	return jwt.decode(token, hmac_key(), algorithms=['HS256'])['uid']
```

```
So it seems its trying to validate our token from another function (validate_token).  If we go to that function, we can find that its using jwt to decode the token in the cookie:
```

```python
def validate_token(token):
	try:	
		claims = jwt.decode(token, hmac_key(), algorithms=['HS256'])
	except:
		# Either invalid format, expired, or wrong key
		return False
	with userdb() as con:
		row = con.execute('SELECT secret FROM Accounts WHERE uid = ?', (claims['uid'],)).fetchone()
		if row is None:
			return False
		return row[0] == claims['sec']
```

```
The token value we are able to generate, but it seems that hmac_key() is generating the secret key used to verify the token -- Which is also found in util.py:
```

```python
def hmac_key():
	return "BCUr5gSMv88JvPqFcbakMK3iSJSiV7LS"
```

```
At last!  We have the HMAC key we need.  Going back to the tool over at https://jwt.io/ we can generate a new token value:

Without the HMAC Key, at the bottom we see "Invalid Signature":
```
![[Pasted image 20221108150310.png]]

```
However, if we update this with the new HMAC key value, we can get a valid signature:
```

![[Pasted image 20221108150407.png]]

```
Now we just need to update the IAT and EXP values with our updated epoch times again:
```

![[Pasted image 20221108150528.png]]

```
Using Developer Mode, we can add a new cookie using the following format:

Name: tok
Value: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjcyNjA4MDAsImV4cCI6MTY2OTg1MjgwMCwic2VjIjoiYWxqMURCWEFlSU1qaXVockt0Ylg4UUFvUU9HTHk2dnkiLCJ1aWQiOjM3MDM3fQ.451NeZuWAH_AjcBMCms0kKJXBBR_NMH-KUXBkyUMAok
Domain: ukzcouspczgmbzmx.ransommethis.net
Path: /
Expires: Fri, 01 Jan 2038 00:00:00 GMT
Size: 202
HttpOnly: false
Secure: true

Then lets try navigating to:
https://ukzcouspczgmbzmx.ransommethis.net/etvdmxhpgpvdweyg/home

...SUCCESS!
```

![[Pasted image 20221108150837.png|center]]

```
Answer: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjcyNjA4MDAsImV4cCI6MTY2OTg1MjgwMCwic2VjIjoiYWxqMURCWEFlSU1qaXVockt0Ylg4UUFvUU9HTHk2dnkiLCJ1aWQiOjM3MDM3fQ.451NeZuWAH_AjcBMCms0kKJXBBR_NMH-KUXBkyUMAok
```

![[badge6.png|center|400]]

