rule common
{
	meta:
		tag = "common"
		description = "通用检测规则"
		author = "huan666"
	strings:
		$str1 = "shell1.jsp"
		$str2 = "shell.jsp"
		
		
		
	condition:
		//$str1 and $str2 and $str3 and $str4 and $str5 and $str6
		$str1 or $str2
}