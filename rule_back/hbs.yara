rule hbs
{
	meta:
		tag="hbs端口扫描工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="WIN64&HackTools"
		document="https://huaidan.org/archives/2135.html"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "hbs.txt"
		$str1 = "[%-15s]:   Port %d Open!!!%s"
		
	condition:
		$hex0 at 0 and $str0 and $str1
}