rule Detect_XMRig {
  meta:
    description = "Detects XMRig mining software"
    author = "YourName"
    reference = "Example reference or URL"
  strings:
    // XMRig 관련 고유 문자열
    $xmrig_str = "xmrig" nocase
    $xmrig_url = "xmrig.com" nocase
    $stratum_tcp = "stratum+tcp" nocase
  condition:
    any of ($xmrig_str, $xmrig_url, $stratum_tcp)
}
