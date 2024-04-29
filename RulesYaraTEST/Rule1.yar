rule DetectMalware {

    meta:
        description = "sample.exe malware"
        author = "Islam Essam"

    strings:
        $z = {4d 5A}
        $a = "Software\\VB and VBA Program Settings\\SPYWAREPROTECTION\\CONFIG" nocase
        $b= "\\zvscan\\Md5GSgx.db"
        $x = {28 00 00 00 20 00 00 00 40 00 00 00 01 00 04 00 00 00 00 00 80 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 80 00 00 00 80 80 00 80 00 00 00 80 00 80 00 }
    condition:
        ($a and $x and $z and $b)
}
