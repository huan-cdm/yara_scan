rule Behinder
{
	meta:
	
		tag = "Behinder"
		description = "冰蝎内存马检测规则"
		author = "huan666"

	strings:
		$str1 = "ProcessBuilder"
		$str2 = "Runtime"
		$str3 = "Instrument"
		$str4 = "Injected Successfully"
		$str5 = "HttpSessionBindingListener"
		$str6 = "reflect/Constructor"
		
		
	condition:
		//$str1 and $str2 and $str3 and $str4 and $str5 and $str6
		all of them
}