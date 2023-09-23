rule struts2scan
{
	meta:
		tag="struts2漏洞扫描工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="WIN64&HackTools"
		document="https://github.com/shack2/Struts2VulsTools/releases"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "Test.exe"
		$str1 = "S2-005 CVE-2010-1870"
		$str2 = "Struts2"
		$str3 = "S2-046"
		$str4 = "S2-045"
		$str5 = "S2-016"
		$str6 = "S2-019"
		$str7 = "S2-032"
		$str8 = "S2-037"
		$str9 = "S2-048"
		$str10 = "S2-057"
	condition:
		all of them
	//	$hex0 and $str0 and  $str1 and  $str2
}