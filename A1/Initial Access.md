We believe that the attacker may have gained access to the victim's network by phishing a legitimate users credentials and connecting over the company's VPN. The FBI has obtained a copy of the company's VPN server log for the week in which the attack took place. Do any of the user accounts show unusual behavior which might indicate their credentials have been compromised?  
Note that all IP addresses have been anonymized.

Prompt:
-   Enter the username which shows signs of a possible compromise.

![VPN.log](/A1/Files/vpn.log)

---

There is one key analysis tool that is needed for this -- Excel.

If we import the file as a CSV, we get clean columns.  The next part involves looking at two specific columns:  The Start Time and Duration.

We first need to split the column with the timestamp such that we have the date in column and the HH:MM:SS in another column.  Insert 3 columns to the right of the timestamp (for Date, Time, Timezone) then use the "Text to Columns" button on the Data tab to accomplish this:

![](/A1/Files/Pasted%20image%2020221116183147.png)

![](/A1/Files/Pasted%20image%2020221116183208.png)

Duration appears to be the number of seconds that the user was logged in.  We can use that knowledge to add some columns and calculate the actual end times.

To the right of DURATION we will add a column with the formula of:
```
	=([@Duration]/60)/60
```
This will give us the number of hours that someone was logged in.

We then can make another column to convert those decimal values into actual time values:
```
	=[@Hours]/24
```
Finally, to the right of the time column (HH:MM:SS), we will add one more column to calcuate the end time:
```
	=[@Time]+[@RealHours]
```
With all of these columns setup, we now can see Start + End times

![](/A1/Files/Pasted%20image%2020221116184145.png)

Now comes the boring part - Using the Username column, we can filter by name each user.  We can start by searching for multiple logins on the same day.  If one of the users has two or more logins on the same day, look at the start and stop times and look for things that should not happen

Eventually we run across a single user who has two logins on the same day, but the login/logout times overlap with each other:

![](/A1/Files/Pasted%20image%2020221116184530.png)

There was a login at 09:50 and they logged out at 15:22 -- However during that same window of time, there was another login at 10:47~!  This means two people were logged into the same account at the same time.

Answer: Michael.L

![](/A1/Files/badgea1.png)
