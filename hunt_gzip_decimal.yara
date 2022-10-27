rule hunt_gzip_decimal
{
    meta:
        description = "Detects decimal encoded GZip file headers, useful for hunting encoded malware"
        last_modified = "2022-08-25"        
    strings:
        $a = /31(\,|\;|\:)139(\,|\;|\:)8(\,|\;|\:)0(\,|\;|\:)/
        $html = "<!DOCTYPE html>" nocase
    condition:
        filesize < 5MB and $a and not ($html in (0..10))
}
