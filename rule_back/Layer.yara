rule Layer
{
	meta:
		tag="Layer子域名爆破工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="WIN64&HackTools"
		document="https://www.webshell.cc/6384.html"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "Layer.exe"
		$str1 = "Layer.Properties.Resources"
		$str2 = "Layer.func"
		$str3 = "Layer.Properties"

	condition:
		$hex0 at 0 and $str0  and  $str1 and  $str2 and  $str3
}