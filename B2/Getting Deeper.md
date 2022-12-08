It looks like the backend site you discovered has some security features to prevent you from snooping. They must have hidden the login page away somewhere hard to guess.

Analyze the backend site, and find the URL to the login page.

_Hint: this group seems a bit sloppy. They might be exposing more than they intend to._

---

**Warning:** Forced-browsing tools, such as DirBuster, are unlikely to be very helpful for this challenge, and may get your IP address automatically blocked by AWS as a DDoS-prevention measure. Codebreaker has no control over this blocking, so we suggest not attempting to use these techniques.

Prompt:
-   Enter the URL for the login page

```
This was a tricky one as there really was not much to go off of.  Nothing in the developer tools immediately gave anything away for the site, so I fired up BurpSuite to check and see if anything was out of the ordinary.

When we do the initial request, we get a single clue to how the backend is running -- The X-Git-Commit-Hash header in the response:
```

![[Pasted image 20221116221039.png|center]]

```
The presence of this header would seem to indicate that the server is using a Git repo in its development.  We can test for this by attempting to access .git as a folder item since all git repos have this folder that contains all the content and history for that repo.

Where before we were getting "Unauthorized", we now get a "Directory Listing Disabled" error.  This would imply that the folder does exist on the server and we should try to enumerate it.
```

![[Pasted image 20221117122755.png|center]]

```
This required some additional research to find out what the structure of the .git folder includes.  I was able to find this graphical representation of a normal .git folder and how things are linked together.
```

![[Git Folder Internals.png|center|center|700]]

```
Starting with the /.git/index file, we see that we are able to download the file.  However this appears to be a mix of ASCII and Byte Data.  In order to make sense of this file an additional tool was used called "gin" (https://github.com/sbp/gin)

We can then point this tool to the downloaded index file and find much more detail about what is in the repo (NOTE: Some output was trimmed to cleanup this writeup):
```

```
┌──(kali㉿kali)-[/writeups/NSA Codebreakers/B2/Files]
└─$ gin index.txt
[entry]
  entry = 1
  sha1 = fc46c46e55ad48869f4b91c2ec8756e92cc01057
  name = Dockerfile

[entry]
  entry = 2
  sha1 = dd5520ca788a63f9ac7356a4b06bd01ef708a196
  name = Pipfile

[entry]
  entry = 3
  sha1 = 47709845a9b086333ee3f470a102befdd91f548a
  name = Pipfile.lock

[entry]
  entry = 4
  sha1 = e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
  name = app/__init__.py

[entry]
  entry = 5
  sha1 = 36fd6147cbf4c6f71396ba5d303370680485b072
  name = app/server.py

[entry]
  entry = 6
  sha1 = a844f894a3ab80a4850252a81d71524f53f6a384
  name = app/templates/404.html

[entry]
  entry = 7
  sha1 = 1df0934819e5dcf59ddf7533f9dc6628f7cdcd25
  name = app/templates/admin.html

[entry]
  entry = 8
  sha1 = b9cfd98da0ac95115b1e68967504bd25bd90dc5c
  name = app/templates/admininvalid.html

[entry]
  entry = 9
  sha1 = bb830d20f197ee12c20e2e9f75a71e677c983fcd
  name = app/templates/adminlist.html

[entry]
  entry = 10
  sha1 = 5033b3048b6f351df164bae9c7760c32ee7bc00f
  name = app/templates/base.html

[entry]
  entry = 11
  sha1 = 10917973126c691eae343b530a5b34df28d18b4f
  name = app/templates/forum.html

[entry]
  entry = 12
  sha1 = fe3dcf0ca99da401e093ca614e9dcfc257276530
  name = app/templates/home.html

[entry]
  entry = 13
  sha1 = 779717af2447e24285059c91854bc61e82f6efa8
  name = app/templates/lock.html

[entry]
  entry = 14
  sha1 = 0556cd1e1f584ff5182bbe6b652873c89f4ccf23
  name = app/templates/login.html

[entry]
  entry = 15
  sha1 = 56e0fe4a885b1e4eb66cda5a48ccdb85180c5eb3
  name = app/templates/navbar.html

[entry]
  entry = 16
  sha1 = ed1f5ed5bc5c8655d40da77a6cfbaed9d2a1e7fe
  name = app/templates/unauthorized.html

[entry]
  entry = 17
  sha1 = c980bf6f5591c4ad404088a6004b69c412f0fb8f
  name = app/templates/unlock.html

[entry]
  entry = 18
  sha1 = 470d7db1c7dcfa3f36b0a16f2a9eec2aa124407a
  name = app/templates/userinfo.html

[entry]
  entry = 19
  sha1 = da4cd40db63e1fdd51979ddfcff77fd49970b4ec
  name = app/util.py

[extension]
  extension = 1
  signature = TREE
  size = 90
  data = "\u000019 1\n\u0095\u009f8G2\u001e\u000f\u0081\u000b\u0004\u001f3l\u0085\r\u00b6\r\u0094\u00cd~app\u000016 1\nn\u0003\u0085\u008e\u001d\u00e5\u00cc$\u0007E>M\u00fb\u008bec\u00f8\u00e2\u00bcUtemplates\u000013 0\n\u00b7L\u0007\u00f2\u00fa#\u00cf\u00fe\u0019\u00ef\u008a\u00f2\u0011\u00a8 \u00f2`\u0094\u00a5;"
```

```
Now we have the names of the files and folders and their associated hashes.  These are all objects in the git repo, however, if we attempt to go to these hashes in the objects folder (/.git/objects/HASH) we get a Not Found.

More research was then needed to figure out how these hashes are used in Git
```

<div align="center">
<iframe width="400" height="275" src="https://www.youtube.com/embed/ADvD-DfSTSU" title="The Definitive Deep Dive into the .git Folder | Rob Richardson | Conf42 Python 2021" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
</div>

```
This video explains how to recsontruct a GIT repo from the .git folder -- While it is long, its very detailed and I highly recommend watching the whole thing.

We learn that all objects are put into additional folders based on their hashes.
/.git/FIRST_TWO_CHARS_OF_HASH/REST_OF_HASH

Now that we know how to access the default files, and the objects, let's re-create the git repo locally by pulling down all the files that we can.

Once that is done, we can use the git cat-file command explained in this video to rebuild all the files from their blobs/trees.
```

```sh
mkdir .git
cd .git
mkdir info
mkdir logs
mkdir objects
mkdir refs
```

```
Using the earlier image, we can start pulling down all of those files and placing them in their respective directories.  Once this is done, we can now start by pulling the blobs/trees found in the intial commit hash and store them in their appropriate folders.

The final directory listing of the .git folder looked like this:
```

```
\---.git
    |   COMMIT_EDITMSG
    |   config
    |   description
    |   HEAD
    |   index
    |
    +---info
    |       exclude
    |
    +---logs
    |   |   HEAD
    |   |
    |   \---refs
    |       \---heads
    |               main
    |
    +---objects
    |   +---05
    |   |       56cd1e1f584ff5182bbe6b652873c89f4ccf23
    |   |
    |   +---10
    |   |       917973126c691eae343b530a5b34df28d18b4f
    |   |
    |   +---1d
    |   |       f0934819e5dcf59ddf7533f9dc6628f7cdcd25
    |   |
    |   +---36
    |   |       fd6147cbf4c6f71396ba5d303370680485b072
    |   |
    |   +---47
    |   |       0d7db1c7dcfa3f36b0a16f2a9eec2aa124407a
    |   |       709845a9b086333ee3f470a102befdd91f548a
    |   |
    |   +---50
    |   |       33b3048b6f351df164bae9c7760c32ee7bc00f
    |   |
    |   +---56
    |   |       e0fe4a885b1e4eb66cda5a48ccdb85180c5eb3
    |   |
    |   +---77
    |   |       9717af2447e24285059c91854bc61e82f6efa8
    |   |
    |   +---a8
    |   |       44f894a3ab80a4850252a81d71524f53f6a384
    |   |
    |   +---b9
    |   |       cfd98da0ac95115b1e68967504bd25bd90dc5c
    |   |
    |   +---bb
    |   |       830d20f197ee12c20e2e9f75a71e677c983fcd
    |   |
    |   +---c9
    |   |       80bf6f5591c4ad404088a6004b69c412f0fb8f
    |   |
    |   +---d4
    |   |       8c1d5c2e34a9db4b0e1faaa8c8cab025f1eeee
    |   |
    |   +---da
    |   |       4cd40db63e1fdd51979ddfcff77fd49970b4ec
    |   |
    |   +---dd
    |   |       5520ca788a63f9ac7356a4b06bd01ef708a196
    |   |
    |   +---e6
    |   |       9de29bb2d1d6434b8b29ae775ad8c2e48c5391
    |   |
    |   +---ed
    |   |       1f5ed5bc5c8655d40da77a6cfbaed9d2a1e7fe
    |   |
    |   +---fc
    |   |       46c46e55ad48869f4b91c2ec8756e92cc01057
    |   |
    |   \---fe
    |           3dcf0ca99da401e093ca614e9dcfc257276530
    |
    \---refs
        \---heads
                main
```

```
Next we need to decode the last bit of data from the TREE data that was encoded as Unicode  (CyberChef:  Unescape String --> To Hex):

If we use the \n markers as delimiters we end up with the following additional hashes for the tree objects

\u000019\n
\u0095\u009f8G2\u001e\u000f\u0081\u000b\u0004\u001f3l\u0085\r\u00b6\r\u0094\u00cd~
	--> 959f3847321e0f810b041f336c850db60d94cd7e

app\u000016 1\n
n\u0003\u0085\u008e\u001d\u00e5\u00cc$\u0007E>M\u00fb\u008bec\u00f8\u00e2\u00bcU
	--> 6e03858e1de5cc2407453e4dfb8b6563f8e2bc55

templates\u000013 0\n
\u00b7L\u0007\u00f2\u00fa#\u00cf\u00fe\u0019\u00ef\u008a\u00f2\u0011\u00a8 \u00f2`\u0094\u00a5;
	--> b74c07f2fa23cffe19ef8af211a820f26094a53b

Let's add those hashes to our .git folder structure.  Now that we have those TREE hashes, we can use git cat-file -p HASH on those hashes to see what each tree contains.
When complete we end up with the following files/hashes from the server:

Trees:
git cat-file -p 959f38 (/)
    100755 blob fc46c46e55ad48869f4b91c2ec8756e92cc01057    Dockerfile
    100755 blob dd5520ca788a63f9ac7356a4b06bd01ef708a196    Pipfile
    100644 blob 47709845a9b086333ee3f470a102befdd91f548a    Pipfile.lock

git cat-file -p 6e0385 (/app)
    100755 blob e69de29bb2d1d6434b8b29ae775ad8c2e48c5391    __init__.py
    100644 blob 36fd6147cbf4c6f71396ba5d303370680485b072    server.py
    100644 blob da4cd40db63e1fdd51979ddfcff77fd49970b4ec    util.py
    
git cat-file -p b74c07 (/app/templates)
    100755 blob a844f894a3ab80a4850252a81d71524f53f6a384    404.html
    100644 blob 1df0934819e5dcf59ddf7533f9dc6628f7cdcd25    admin.html
    100644 blob b9cfd98da0ac95115b1e68967504bd25bd90dc5c    admininvalid.html
    100644 blob bb830d20f197ee12c20e2e9f75a71e677c983fcd    adminlist.html
    100644 blob 5033b3048b6f351df164bae9c7760c32ee7bc00f    base.html
    100644 blob 10917973126c691eae343b530a5b34df28d18b4f    forum.html
    100644 blob fe3dcf0ca99da401e093ca614e9dcfc257276530    home.html
    100644 blob 779717af2447e24285059c91854bc61e82f6efa8    lock.html
    100644 blob 0556cd1e1f584ff5182bbe6b652873c89f4ccf23    login.html
    100644 blob 56e0fe4a885b1e4eb66cda5a48ccdb85180c5eb3    navbar.html
    100755 blob ed1f5ed5bc5c8655d40da77a6cfbaed9d2a1e7fe    unauthorized.html
    100644 blob c980bf6f5591c4ad404088a6004b69c412f0fb8f    unlock.html
    100644 blob 470d7db1c7dcfa3f36b0a16f2a9eec2aa124407a    userinfo.html
```


```
All of these files are able to be reconstructed using the git cat-file -p HASH command and piping that output to the appropiate folder/file.  When we are done we end up with the following file structure:

\---serverData
    |   Dockerfile
    |   Pipfile
    |   Pipfile.lock
    |
    \---app
        |   server.py
        |   util.py
        |   __init__.py
        |
        \---templates
                404.html
                admin.html
                adminlist.html
                adminvalid.html
                base.html
                forum.html
                home.html
                lock.html
                login.html
                navbar.html
                unauthorized.html
                unlock.html
                userinfo.html
```

```
Now we can finally move forward.  Within the app/server.py file we are able to find the following information about how the server actually works:
```

```python
def expected_pathkey():
	return "etvdmxhpgpvdweyg"

...ADDTL CODE...

@app.route("/", defaults={'pathkey': '', 'path': ''}, methods=['GET', 'POST'])
@app.route("/<path:pathkey>", defaults={'path': ''}, methods=['GET', 'POST'])
@app.route("/<path:pathkey>/<path:path>", methods=['GET', 'POST'])
def pathkey_route(pathkey, path):
	if pathkey.endswith('/'):
		# Deal with weird normalization
		pathkey = pathkey[:-1]
		path = '/' + path

	# Super secret path that no one will ever guess!
	if pathkey != expected_pathkey():
		return render_template('unauthorized.html'), 403
```

```
We see that if the path does not contain a pathkey, then we are sent the Unauthorized page.  This tells us that we have to append /etvdmxhpgpvdweyg/ to our path to reach the actual html pages.  -- /etvdmxhpgpvdweyg/login

When we browse to this, we find the login page~!
```

![[Pasted image 20221117125549.png|center]]

```
Answer: https://ukzcouspczgmbzmx.ransommethis.net/etvdmxhpgpvdweyg/login
```

![[badgeb2.png|center|400]]
