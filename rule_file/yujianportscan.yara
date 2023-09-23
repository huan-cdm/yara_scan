rule yujianportscan
{
	meta:
		tag="yujian端口扫描工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="端口扫描工具"
		document="https://github.com/foryujian/yujianportscan"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "YujianPortScan.exe"
		$str1 = "YujianPortScan"
		$str2 = "YujianPortScan.FormMain.resources"
		$str3 = "_PortFiles"

	condition:
		$hex0 at 0 and $str0  and  $str1 and  $str2  and  $str3
}