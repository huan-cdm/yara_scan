rule wce
{
	meta:
		tag="wce"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="wce-windows密码获取工具"
		document="https://www.ampliasecurity.com/index.html"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "WCESERVICE"
		$str1 = "wceaux.dll"
		$str2 = "Converting and saving TGT in UNIX format to file wce_ccache..."
		$str3 = "wce_krbtkts"
		
	condition:
		all of them
}