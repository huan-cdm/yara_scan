rule webshell_rule
{
	meta:
		tag = "webshell"
		description = "webshell扫描"
		author = "huan666"
	strings:
		$str1 = "exec(\""
		$str2 = "add_url_rule"
		$str3 = "Code By Ninty"
		$str4 = "eval"
		
	condition:
		$str1 or $str2 or $str3 or $str4 
}