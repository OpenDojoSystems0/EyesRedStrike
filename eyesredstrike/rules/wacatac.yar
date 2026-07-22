/*
    Règles heuristiques ciblant les patterns habituellement associés aux détections
    Trojan:Win32/Wacatac.B!ml et Trojan:Script/Wacatac.B!ml.

    IMPORTANT : Wacatac.B!ml est un verdict ML de Microsoft Defender, pas une famille
    figée avec une signature binaire unique. Ces règles détectent donc des TECHNIQUES
    (droppers de script obfusqués, chargement de payload encodé, persistence discrète)
    qui apparaissent fréquemment dans ces détections — elles peuvent aussi matcher du
    code légitime obfusqué/packé. Confidence = "medium" volontairement : à corréler
    avec hashdb (IOC connu) avant toute suppression automatique.
*/

rule Wacatac_Script_Obfuscated_Dropper
{
    meta:
        family = "Wacatac-like"
        confidence = "medium"
        description = "Script (JS/VBS/PowerShell) fortement obfusqué avec téléchargement + exécution"
        reference = "Patterns publics MSTIC / techniques MITRE T1059, T1027, T1105"

    strings:
        $ps_enc = "-EncodedCommand" nocase
        $ps_enc2 = "-enc " nocase
        $ps_hidden = "-WindowStyle Hidden" nocase
        $ps_bypass = "-ExecutionPolicy Bypass" nocase
        $wscript_shell = "WScript.Shell" nocase
        $adodb = "ADODB.Stream" nocase
        $download1 = ".DownloadString(" nocase
        $download2 = ".DownloadFile(" nocase
        $download3 = "Invoke-WebRequest" nocase
        $download4 = "Net.WebClient" nocase
        $b64_marker = /[A-Za-z0-9+\/]{200,}={0,2}/
        $eval_js = "eval(" nocase
        $unescape_js = "unescape(" nocase
        $charcode_js = "String.fromCharCode(" nocase

    condition:
        filesize < 5MB and
        (
            (2 of ($ps_enc, $ps_enc2, $ps_hidden, $ps_bypass)) or
            (any of ($download1, $download2, $download3, $download4) and any of ($wscript_shell, $adodb)) or
            (2 of ($eval_js, $unescape_js, $charcode_js) and $b64_marker)
        )
}

rule Wacatac_PE_Packed_Suspicious
{
    meta:
        family = "Wacatac-like"
        confidence = "medium"
        description = "PE Windows packé/obfusqué avec imports d'API sensibles typiques de droppers"
        reference = "MITRE T1027 (obfuscation), T1055 (process injection)"

    strings:
        $mz = { 4D 5A }
        $api_process_inject = "VirtualAllocEx" ascii
        $api_write_mem = "WriteProcessMemory" ascii
        $api_create_remote = "CreateRemoteThread" ascii
        $api_crypt = "CryptDecrypt" ascii
        $section_upx = "UPX" ascii
        $section_themida = "Themida" ascii
        $api_reg_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide

    condition:
        $mz at 0 and
        filesize < 15MB and
        (
            (2 of ($api_process_inject, $api_write_mem, $api_create_remote)) or
            (any of ($section_upx, $section_themida) and $api_reg_run) or
            ($api_crypt and $api_reg_run)
        )
}

rule Wacatac_MSHTA_HTA_Chain
{
    meta:
        family = "Wacatac-like"
        confidence = "high"
        description = "Chaîne d'exécution mshta/rundll32/regsvr32 avec payload distant (LOLBins abuse)"
        reference = "MITRE T1218 (System Binary Proxy Execution)"

    strings:
        $mshta = "mshta.exe" nocase
        $rundll = "rundll32.exe" nocase
        $regsvr = "regsvr32.exe /s /n /u /i:" nocase
        $http = /https?:\/\/[a-zA-Z0-9\.\-]+\/[a-zA-Z0-9_\-\.\/]*\.(hta|sct|dll|vbs)/ nocase

    condition:
        any of ($mshta, $rundll, $regsvr) and $http
}
