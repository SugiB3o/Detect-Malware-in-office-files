rule emotet_dropper_2019_Q2_campaign : TAU ecrime Emotet
{
	meta:
		author = "CarbonBlack Threat Research"
		date = "2019-Mar-22"
		Validity = 10
		severity = 10
		Jira = "TR-2818"
		TID = "T1193, T1204, T1192, T1055, T1140, T1027"
		description = "Emotet Dropper"
		rule_version = 1
		yara_version = "3.7.0"
		exemplar_hashes = "b2e5f1283d28a330cc1712f9cdfdf1077b120b61b53e33debfa96860a6f2c484, a9b41f27b2714035be665a3295f585068fb407c9be9d998cabb7cd3bb16d18d6, 7377d46ffdd35970a386931a17399165e9a0f7c5b872851d742c296d62103ea4"
	strings:
		$s1 = "hknj]t34q"
		$s2 = "WdgfR111"
		$s3 = "GetPodu)eHa#dle"
		$s4 = {83 F? 41} //Portion of Decoding Routine
		$s5 = {83 F? 74} //Portion of Decoding Routine
		$s6 = {81 ?? ?? ?? ?? 00 2D 37 00 00}
		$s7 = {81 ?? ?? ?? ?? 00 2C 37 00 00}
	condition:
		6 of ($s*) and
		uint16(0) == 0x5a4d and
		filesize < 500KB
}
