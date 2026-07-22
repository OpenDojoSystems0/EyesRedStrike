/*
    Règles génériques pour trojans courants : keyloggers, infostealers, RATs commerciaux.
    Basées sur des techniques publiques (MITRE ATT&CK) et des chaînes/API récurrentes.
*/

rule Generic_Keylogger_API
{
    meta:
        family = "Generic-Keylogger"
        confidence = "medium"
        description = "Combinaison d'API de capture clavier/écran typique d'un keylogger"
        reference = "MITRE T1056.001 (Input Capture)"

    strings:
        $hook = "SetWindowsHookEx" ascii
        $getkey = "GetAsyncKeyState" ascii
        $getkeyboard = "GetKeyboardState" ascii
        $bitblt = "BitBlt" ascii
        $clipboard = "GetClipboardData" ascii

    condition:
        (any of ($getkey, $getkeyboard)) and (any of ($hook, $bitblt, $clipboard))
}

rule Generic_Infostealer_BrowserData
{
    meta:
        family = "Generic-Infostealer"
        confidence = "medium"
        description = "Accès aux fichiers de credentials/cookies des navigateurs (pattern infostealer)"
        reference = "MITRE T1555.003 (Credentials from Web Browsers)"

    strings:
        $chrome_login = "Login Data" ascii wide
        $chrome_cookies = "Network\\Cookies" ascii wide nocase
        $firefox_login = "logins.json" ascii
        $key_dpapi = "CryptUnprotectData" ascii
        $sqlite_hdr = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 }

    condition:
        (any of ($chrome_login, $chrome_cookies, $firefox_login) and $key_dpapi) or
        ($sqlite_hdr and $key_dpapi)
}

rule Generic_RAT_Commercial_Strings
{
    meta:
        family = "Generic-RAT"
        confidence = "low"
        description = "Chaînes associées à des RATs commerciaux/publics fréquemment abusés"
        reference = "Threat intel publique (njRAT, AsyncRAT, QuasarRAT, etc.)"

    strings:
        $s1 = "njRAT" nocase
        $s2 = "AsyncRAT" nocase
        $s3 = "QuasarRAT" nocase
        $s4 = "DcRat" nocase
        $s5 = "Client.exe" nocase wide
        $s6 = "keylogger" nocase
        $s7 = "\\Plugins\\HVNC" nocase

    condition:
        2 of them
}

rule Generic_Persistence_Scheduled_Task_Suspicious
{
    meta:
        family = "Generic-Persistence"
        confidence = "medium"
        description = "Création de tâche planifiée avec exécution de script encodé/caché"
        reference = "MITRE T1053.005 (Scheduled Task)"

    strings:
        $schtasks = "schtasks" nocase
        $create = "/create" nocase
        $hidden_arg = "-WindowStyle Hidden" nocase
        $enc_arg = "-EncodedCommand" nocase

    condition:
        $schtasks and $create and (any of ($hidden_arg, $enc_arg))
}
