rule LaZagne
{
	meta:
		tag="LaZagne密码提取工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="密码提取工具"
		document="https://github.com/AlessandroZ/LaZagne/releases/tag/2.4.3"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "lazagne("
		$str1 ="lazagne.softwares.sysadmin.vnc("
		$str2 ="lazagne.softwares.windows("
		$str3 = "lazagne.softwares.windows.creddump7.win32.hashdump("

	condition:
		$hex0 and $str0 and $str1 and $str2 and $str3
	//	all of them
}