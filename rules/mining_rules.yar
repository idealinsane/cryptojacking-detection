rule Detect_XMRig {
  meta:
    description = "Detects XMRig mining software"
    author = "YourName"
    reference = "Example reference or URL"
  strings:
    $xmrig_str = "xmrig" nocase
    $xmrig_url = "xmrig.com" nocase
    $stratum_tcp = "stratum+tcp" nocase
  condition:
    any of ($xmrig_str, $xmrig_url, $stratum_tcp)
}

rule Detect_Minerd_Miner {
    meta:
        description = "Detects minerd (cpuminer) crypto miner binary"
    strings:
        $s1 = "minerd"
        $s2 = "cpuminer"
        $s3 = "stratum+tcp://"
        $s4 = "cryptonight"
        $s5 = "Algorithm: "
        $s6 = "Starting Stratum on"
    condition:
        2 of ($s*)
}

rule Detect_Claymore_Miner {
    meta:
        description = "Detects Claymore crypto miner binary"
    strings:
        $s1 = "Claymore"
        $s2 = "ETH - Total Speed:"
        $s3 = "ETH: GPU"
        $s4 = "POOL/SOLO"
        $s5 = "stratum+tcp://"
        $s6 = "No NVIDIA CUDA GPUs detected."
    condition:
        2 of ($s*)
}

rule Detect_ccminer {
    meta:
        description = "Detects ccminer NVIDIA GPU miner"
    strings:
        $s1 = "ccminer" nocase
        $s2 = "tpruvot@github" nocase
        $s3 = "NVIDIA GPU miner" nocase
        $s4 = "stratum+tcp" nocase
    condition:
        2 of ($s*)
}

rule Detect_sgminer {
    meta:
        description = "Detects sgminer AMD GPU miner"
    strings:
        $s1 = "sgminer" nocase
        $s2 = "OpenCL" nocase
        $s3 = "stratum+tcp" nocase
        $s4 = "GPU mining" nocase
    condition:
        2 of ($s*)
}

rule Detect_bfgminer {
    meta:
        description = "Detects bfgminer FPGA/ASIC/GPU miner"
    strings:
        $s1 = "bfgminer" nocase
        $s2 = "FPGA miner" nocase
        $s3 = "stratum+tcp" nocase
        $s4 = "ASIC" nocase
    condition:
        2 of ($s*)
}

rule Detect_ethminer {
    meta:
        description = "Detects ethminer Ethereum GPU miner"
    strings:
        $s1 = "ethminer" nocase
        $s2 = "Ethereum miner" nocase
        $s3 = "stratum+tcp" nocase
        $s4 = "ethash" nocase
    condition:
        2 of ($s*)
}

rule Detect_NBMiner {
    meta:
        description = "Detects NBMiner GPU miner"
    strings:
        $s1 = "nbminer" nocase
        $s2 = "NebuTech" nocase
        $s3 = "stratum+tcp" nocase
        $s4 = "GPU mining" nocase
    condition:
        2 of ($s*)
}

rule Detect_PhoenixMiner {
    meta:
        description = "Detects PhoenixMiner GPU miner"
    strings:
        $s1 = "PhoenixMiner" nocase
        $s2 = "GPU mining" nocase
        $s3 = "stratum+tcp" nocase
        $s4 = "ethash" nocase
    condition:
        2 of ($s*)
}

rule Detect_SRBMiner {
    meta:
        description = "Detects SRBMiner CPU/GPU miner"
    strings:
        $s1 = "SRBMiner" nocase
        $s2 = "RandomX" nocase
        $s3 = "stratum+tcp" nocase
        $s4 = "CPU mining" nocase
    condition:
        2 of ($s*)
}

rule Detect_TeamRedMiner {
    meta:
        description = "Detects TeamRedMiner AMD miner"
    strings:
        $s1 = "TeamRedMiner" nocase
        $s2 = "stratum+tcp" nocase
        $s3 = "AMD GPU" nocase
        $s4 = "ethash" nocase
    condition:
        2 of ($s*)
}

rule Detect_LolMiner {
    meta:
        description = "Detects lolMiner GPU miner"
    strings:
        $s1 = "lolMiner" nocase
        $s2 = "stratum+tcp" nocase
        $s3 = "GPU mining" nocase
        $s4 = "ethash" nocase
    condition:
        2 of ($s*)
}
