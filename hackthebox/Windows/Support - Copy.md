---
title: Support - Copy
updated: 2023-12-27 14:04:52Z
created: 2023-12-27 14:04:52Z
---

# Support

- Target: 10.10.11.174
- HTB , Windows machine

### Ping

- As we can see target is alive with "ttl=127" (probably a windows machine).

```bash
ping 10.10.11.174
```
![Pasted image 20231129112024 1.png](../_resources/Pasted%20image%2020231129112024%201.png)

### Nmap

```bash
nmap -T4 -A -v 10.10.11.174
```
![Pasted image 20231129114303.png](../_resources/Pasted%20image%2020231129114303.png)

### crackmapexec

```bash
cme smb 10.10.11.174 -u 'anonymous' -p '' --rid-brute
```
![Pasted image 20231130101102.png](../_resources/Pasted%20image%2020231130101102.png)



```bash
cat u.txt |grep -i user |rev |cut -f2 -d ' ' |rev |grep SUPPO |cut -f2 -d '\' |grep -Ev (DC|SVC) |tail -n +4 > users.txt
```

Result:  
![Pasted image 20231130160809.png](../_resources/Pasted%20image%2020231130160809.png)

![Pasted image 20231130162733.png](../_resources/Pasted%20image%2020231130162733.png)

![Pasted image 20231130195435.png](../_resources/Pasted%20image%2020231130195435.png)

