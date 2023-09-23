rule goldenPac
{
	meta:
		tag="MS14-068域提权工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="域提权工具"
		document="https://github.com/maaaaz/impacket-examples-windows"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "sgoldenPac"
		$str1 = "bgoldenPac.exe.manifest"
		$str2 = "opyi-windows-manifest-filename goldenPac.exe.manifest"
		
	condition:
		all of them
}