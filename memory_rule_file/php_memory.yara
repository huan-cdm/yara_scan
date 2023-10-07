rule php_memory
{
	meta:
		tag = "php_memory"
		description = "php内存马检测规则"
		author = "huan666"
		
	strings:
		$str1 = "ignore_user_abort"
		$str2 = "set_time_limit"
		$str3 = "unlink"
		$str4 = "file_put_contents"
		$str5 = "usleep"
		
		
		
	condition:

		all of them
}