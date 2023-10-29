rule xmrig_stratum
{
	meta:
		tag="xmrig_stratum"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="检测xmrig门罗币挖矿协议"
		document="https://github.com/xmrig/xmrig/releases/tag/v6.15.1"
		
	strings:
		$hex0 = {4D 5A}
		$hex1 = {73 74 72 61 74 75 6D}
		$str1 = "XMRig" nocase
		
	condition:
		$hex0 and $hex1 and $str1
}