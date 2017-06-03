/*
 * Match any file containing some basic golang strings.
 */
rule golang {
	strings:
		// A few definitions
		$string1 = "runtime.decoderune"
		$string2 = "golang"
	
	condition:
		// Match any file containing 
		$string1 or $string2
}
