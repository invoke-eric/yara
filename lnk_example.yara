rule lnk_example{
strings: 
$hostname = "host" 
$mac = {AA BB CC DD EE FF} 
$lnk = {4c 00 00 00 01} 
condition: $lnk at 0 and all of them}
