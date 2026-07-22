/*
    Règles ciblant le vol d'identifiants : dump LSASS type Mimikatz, bypass AMSI/Defender,
    exfiltration de tokens/wallets. Vient compléter Generic_Infostealer_BrowserData
    (rules/generic_trojans.yar) qui couvre déjà navigateurs/cookies.
*/

rule Credential_Theft_LSASS_Dump
{
    meta:
        family = "Generic-CredentialTheft"
        confidence = "high"
        description = "Dump mémoire LSASS (technique Mimikatz et dérivés) pour extraction d'identifiants Windows"
        reference = "MITRE T1003.001 (LSASS Memory)"

    strings:
        $lsass = "lsass.exe" nocase
        $minidump = "MiniDumpWriteDump" ascii
        $mimikatz1 = "sekurlsa::logonpasswords" nocase
        $mimikatz2 = "mimikatz" nocase
        $procdump = "procdump" nocase
        $comsvcs = "comsvcs.dll" nocase

    condition:
        any of ($mimikatz1, $mimikatz2) or
        ($lsass and any of ($minidump, $procdump, $comsvcs))
}

rule Credential_Theft_AMSI_Defender_Bypass
{
    meta:
        family = "Generic-CredentialTheft"
        confidence = "high"
        description = "Bypass AMSI / désactivation Windows Defender — étape courante avant exécution de payload de vol de creds"
        reference = "MITRE T1562.001 (Disable or Modify Tools)"

    strings:
        $amsi1 = "amsiInitFailed" nocase
        $amsi2 = "AmsiScanBuffer" ascii
        $amsi3 = "System.Management.Automation.AmsiUtils" nocase
        $defender_disable1 = "Set-MpPreference" nocase
        $defender_disable2 = "-DisableRealtimeMonitoring" nocase
        $defender_disable3 = "Add-MpPreference" nocase
        $defender_exclusion = "-ExclusionPath" nocase

    condition:
        any of ($amsi1, $amsi2, $amsi3) or
        (any of ($defender_disable1, $defender_disable3) and any of ($defender_disable2, $defender_exclusion))
}

rule Credential_Theft_Crypto_Wallet_Targeting
{
    meta:
        family = "Generic-CredentialTheft"
        confidence = "medium"
        description = "Ciblage de fichiers de wallets crypto (fréquent dans les infostealers modernes)"
        reference = "MITRE T1552 (Unsecured Credentials)"

    strings:
        $wallet1 = "wallet.dat" nocase
        $wallet2 = "Electrum" nocase
        $wallet3 = "MetaMask" nocase
        $wallet4 = "Exodus" nocase
        $wallet5 = "\\Local Extension Settings\\" nocase

    condition:
        2 of ($wallet1, $wallet2, $wallet3, $wallet4, $wallet5)
}
