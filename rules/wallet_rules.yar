rule DetectBTCWallet
{
    meta:
        coin = "BTC"
        description = "Bitcoin address"
    strings:
        $btc_addr = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,59}/
    condition:
        $btc_addr
}

rule DetectETHWallet
{
    meta:
        coin = "ETH"
        description = "Ethereum address"
    strings:
        $eth_addr = /0x[a-fA-F0-9]{40}/
    condition:
        $eth_addr
}

rule DetectXMRWallet
{
    meta:
        coin = "XMR"
        description = "Monero address"
    strings:
        $xmr_addr = /(4|8)[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{104}/
    condition:
        $xmr_addr
}

rule DetectCryptoMiningBehavior
{
    meta:
        type = "miner"
    strings:
        $stratum = "stratum+tcp://" nocase
        $xmrig = "xmrig" nocase
        $minerd = "/minerd" nocase
    condition:
        any of them

}
