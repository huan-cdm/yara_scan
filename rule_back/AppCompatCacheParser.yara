rule AppCompatCacheParser
{
	meta:
		tag="AppCompatCacheParser近期的可执行文件操作检测工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="近期的可执行文件操作检测工具"
		document="https://www.sans.org/tools/appcompatcacheparser/"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "AppCompatCacheParser.exe"
		$str1 = "AppCompatCacheParser.Properties"
		$str2 = "AppCompatCacheParser"

	condition:
		$hex0 at 0 and $str0 and $str1 and $str2
	
}