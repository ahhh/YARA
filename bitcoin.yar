rule	bitcoin	{	
    strings:		
    $key = /(L|K)[0-9A-Za-z]{51}/
    $addr = /[1-9a-zA-z]{34}(?!OIl)/	
    condition:	
    any of them	
}
