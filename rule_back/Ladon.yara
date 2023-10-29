rule Ladon
{
	meta:
		tag="Ladon内网综合漏洞扫描工具"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="内网综合漏洞扫描工具"
		document="https://github.com/k8gege/Ladon/releases/tag/v7.0"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "Ladon"
		$str1 = "LadonGUI.exe"
		$str2 = "Ladon Version"
		$str3 = "Ladon AutoRun"
		$str4 = "Ladon CheckDoor"
		$str5 = "Ladon AutoRun"
	condition:
	
		all of them	
}