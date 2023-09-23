rule CobaltStrike4_1:beacon
{
	meta:
		tag="CobaltStrike4_1远控木马"
		type="WIN32&EXE&HACKTOOL"
		result="高危"
		author="huan666"
        describe="特洛伊木马"
		document="https://lengjibo.github.io/yara/"
	strings:
		$hex0 = { 4D 5A }
		$str0 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
	condition:
		$hex0 at 0 and $str0  and filesize > 10KB and filesize < 500KB
}