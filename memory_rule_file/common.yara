rule common
{
	meta:
	
		tag = "common"
		description = "通用检测规则"
		author = "huan666"

	strings:
		$str1 = "shell1.jsp"
		$str2 = "shell.jsp"
		$str3 = "shell.php"
		$str4 = "shell1.php"
		$str5 = "shell1.asp"
		$str6 = "shell.asp"
		$str7 = "shell1.aspx"
		$str8 = "shell.aspx"
		$str9 = "phpinfo.php"


	condition:
		//$str1 and $str2 and $str3 and $str4 and $str5 and $str6
		$str1 or $str2 or $str3 or $str4 or $str5 or $str6 or $str7 or $str8 or $str9

} 