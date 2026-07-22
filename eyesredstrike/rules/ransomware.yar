/*
    Règles ciblant les indicateurs de ransomware : chiffrement de masse, suppression
    de sauvegardes/shadow copies, notes de rançon, extensions de fichiers chiffrés.
*/

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        family = "Generic-Ransomware"
        confidence = "high"
        description = "Suppression des sauvegardes Windows (shadow copies, backup catalog) — étape classique pré-chiffrement"
        reference = "MITRE T1490 (Inhibit System Recovery)"

    strings:
        $vssadmin = "vssadmin" nocase
        $delete_shadows = "delete shadows" nocase
        $resize_shadow = "resize shadowstorage" nocase
        $wbadmin = "wbadmin" nocase
        $delete_catalog = "delete catalog" nocase
        $bcdedit = "bcdedit" nocase
        $recoveryenabled = "recoveryenabled no" nocase
        $wmic_shadow = "wmic shadowcopy delete" nocase

    condition:
        (any of ($vssadmin, $wmic_shadow) and any of ($delete_shadows, $resize_shadow)) or
        (any of ($wbadmin) and $delete_catalog) or
        ($bcdedit and $recoveryenabled)
}

rule Ransomware_Note_And_Extension_Pattern
{
    meta:
        family = "Generic-Ransomware"
        confidence = "medium"
        description = "Chaînes typiques d'une note de rançon associées à une logique de renommage de fichiers"
        reference = "MITRE T1486 (Data Encrypted for Impact)"

    strings:
        $note1 = "your files have been encrypted" nocase
        $note2 = "all your files" nocase ascii wide
        $note3 = "decrypt" nocase
        $note4 = "bitcoin" nocase
        $note5 = "restore_files" nocase
        $note6 = "how_to_decrypt" nocase
        $renam_api = "MoveFileExW" ascii
        $crypt_api = "CryptEncrypt" ascii

    condition:
        (2 of ($note1, $note2, $note3, $note4, $note5, $note6)) or
        ($crypt_api and $renam_api and any of ($note1, $note3, $note4))
}

rule Ransomware_Mass_File_Enumeration
{
    meta:
        family = "Generic-Ransomware"
        confidence = "medium"
        description = "Combinaison énumération récursive de fichiers utilisateur + chiffrement + suppression de l'original"
        reference = "MITRE T1486"

    strings:
        $findfirst = "FindFirstFileW" ascii
        $findnext = "FindNextFileW" ascii
        $crypt_encrypt = "CryptEncrypt" ascii
        $delete_file = "DeleteFileW" ascii
        $user_docs = "\\Documents\\" ascii wide nocase
        $user_desktop = "\\Desktop\\" ascii wide nocase

    condition:
        all of ($findfirst, $findnext, $crypt_encrypt, $delete_file) and
        any of ($user_docs, $user_desktop)
}
