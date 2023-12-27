
## Recon
### ping
```zsh
ping -c 1 10.10.10.7
```
![[Pasted image 20230925103210.png]]
#TTL
So as always, we begin with a ping to identify the operating system based on the ICMP TTL reply.

So we'll send one ICMP request 2.7 And what do we get?

63.=  it's a Linux box

If the TTL is below 65, it's most likely Linux.

If it's between 65 and 128, we're probably talking with a Windows target and anything above 128 is most likely a network appliance.
## nmap
```zsh
sudo nmap -Pn -sCV --reason -T4 -p0-65535 -oN beep.nmap 10.10.10.7
```
![[Pasted image 20230925104122.png]]
![[Pasted image 20230925105921.png]]
![[Pasted image 20230925110125.png]]
![[Pasted image 20230925110141.png]]
## whatweb
```zsh
sudo whatweb 10.10.10.7
```
![[Pasted image 20230925103033.png]]
## burpsuite
1. open burp proxy browser
2.  try http://10.10.10.7
![[Pasted image 20230925110742.png]]

## dirsearch
```zsh
sudo dirsearch --url=https://10.10.10.7 --wordlists=/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --threads 20 --random-agent -o beep.txt --format=simple
```
![[Pasted image 20230925120414.png]]
## searchsploit 
```zsh
searchsploit elastix
```
![[Pasted image 20230925115904.png]]
What is the version of elastix?? 
2.0 of July 2010?
![[Pasted image 20230925120632.png]]

# exploit 

![[Pasted image 20230925152958.png]]

