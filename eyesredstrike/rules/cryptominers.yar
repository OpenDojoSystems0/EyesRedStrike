/*
    Règles ciblant les cryptomineurs (cross-platform) : XMRig et dérivés, pools de minage,
    exécution cachée abusant de la puissance CPU/GPU sans consentement.
*/

rule Cryptominer_XMRig_Strings
{
    meta:
        family = "Generic-Cryptominer"
        confidence = "high"
        description = "Chaînes de configuration typiques de XMRig / mineurs dérivés (Monero et autres)"
        reference = "MITRE T1496 (Resource Hijacking)"

    strings:
        $xmrig1 = "xmrig" nocase
        $xmrig2 = "--donate-level" nocase
        $xmrig3 = "randomx" nocase
        $stratum = "stratum+tcp://" nocase
        $stratum_ssl = "stratum+ssl://" nocase
        $pool_arg = "--url=" nocase
        $wallet_arg = "--user=" nocase
        $cpu_max = "cpu-max-threads-hint" nocase

    condition:
        (any of ($xmrig1, $xmrig2, $xmrig3)) or
        (any of ($stratum, $stratum_ssl) and any of ($pool_arg, $wallet_arg, $cpu_max))
}

rule Cryptominer_Hidden_Process_Persistence
{
    meta:
        family = "Generic-Cryptominer"
        confidence = "medium"
        description = "Mineur combiné à une technique de camouflage de processus / persistence discrète"
        reference = "MITRE T1055, T1053, T1543"

    strings:
        $miner_ref = "stratum+tcp://" nocase
        $renice = "nice -n 19" ascii
        $cron_persist = "* * * * *" ascii
        $systemd_hidden = "/tmp/.X11-unix" ascii
        $proc_hide = "/proc/self/exe" ascii

    condition:
        $miner_ref and (any of ($renice, $cron_persist, $systemd_hidden, $proc_hide))
}
