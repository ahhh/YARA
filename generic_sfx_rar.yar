# From https://www.youtube.com/watch?v=YFVZ-tjjWos 
# Self Installing / Dropper Auto Extracting RAR
rule GENERIC_SFXRAR_Installer {
	strings:
		$str1 = "RarSFX" ascii wide
		$str2 = "RENAMEDKG" ascii wide
		$str3 = "GETPASSWORD1" ascii wide
		$str4 = "ASKNEXTVOL" ascii wide
		$str5 = "STATIC" ascii wide
		$str6 = "REPLACEFILEDLG" ascii wide
		$str7 = "winrarsfxmappingfile.tmp" ascii wide
	condition:
	    (uint16(0) == 0x5A4D) and 
		all of them
}
