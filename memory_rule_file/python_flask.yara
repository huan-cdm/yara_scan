rule python_flask
{
	meta:
		tag = "flask"
		description = "yara扫描内存python flask 内存马"
		author = "huan666"
	strings:
		$str1 = "_request_ctx_stack"
		$str2 = "add_url_rule"
		$str3 = "exec"
		$str4 = "eval"
		
	condition:
		($str1 and $str2 and $str3) or
		($str1 and $str2 and $str4)
}