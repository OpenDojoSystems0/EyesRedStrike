/*
    Règles ciblant les backdoors : reverse shells, bind shells cachés, C2 patterns.
    Couvre Windows (PE/PowerShell) et Unix (ELF/Bash/Python/Perl) — cross-platform.
*/

rule Backdoor_Reverse_Shell_Bash_Python_Perl
{
    meta:
        family = "Generic-Backdoor"
        confidence = "high"
        description = "One-liner reverse shell classique (bash/python/perl/nc)"
        reference = "MITRE T1059 (Command and Scripting Interpreter)"

    strings:
        $bash_dev_tcp = "/dev/tcp/" ascii
        $bash_i = "bash -i" ascii
        $py_socket = "socket.socket(" ascii
        $py_dup2 = "os.dup2(" ascii
        $py_subprocess_pty = "pty.spawn(" ascii
        $perl_socket = "IO::Socket" ascii
        $nc_e = "nc -e" ascii
        $nc_mkfifo = "mkfifo" ascii

    condition:
        $bash_dev_tcp or
        ($bash_i and $nc_mkfifo) or
        (any of ($py_socket, $py_dup2, $py_subprocess_pty) and 2 of ($py_socket, $py_dup2, $py_subprocess_pty)) or
        $perl_socket or
        $nc_e
}

rule Backdoor_PowerShell_Reverse_Shell
{
    meta:
        family = "Generic-Backdoor"
        confidence = "high"
        description = "Reverse shell PowerShell (TCPClient + stream redirection)"
        reference = "MITRE T1059.001"

    strings:
        $tcpclient = "New-Object System.Net.Sockets.TCPClient" nocase
        $getstream = ".GetStream()" nocase
        $streamreader = "StreamReader" nocase
        $streamwriter = "StreamWriter" nocase
        $invoke_expr = "Invoke-Expression" nocase

    condition:
        $tcpclient and $getstream and (any of ($streamreader, $streamwriter, $invoke_expr))
}

rule Backdoor_Webshell_PHP_ASP_JSP
{
    meta:
        family = "Generic-Webshell"
        confidence = "high"
        description = "Webshell générique (exécution de commandes via requête HTTP)"
        reference = "MITRE T1505.003 (Web Shell)"

    strings:
        $php_exec1 = "shell_exec(" nocase
        $php_exec2 = "passthru(" nocase
        $php_exec3 = "system($_" nocase
        $php_eval = "eval($_POST" nocase
        $php_eval2 = "eval($_GET" nocase
        $asp_exec = "Server.CreateObject(\"WSCRIPT.SHELL\")" nocase
        $jsp_exec = "Runtime.getRuntime().exec(" ascii

    condition:
        any of them
}

rule Backdoor_Hidden_Listener_Setup
{
    meta:
        family = "Generic-Backdoor"
        confidence = "medium"
        description = "Configuration de listener réseau discret combinée à de la persistence"
        reference = "MITRE T1071 (C2), T1547 (Boot/Logon Autostart)"

    strings:
        $bind_listen = "bind(" ascii
        $listen_call = "listen(" ascii
        $accept_call = "accept(" ascii
        $cron_persist = "/etc/cron" ascii
        $systemd_persist = "/etc/systemd/system" ascii
        $launchd_persist = "LaunchAgents" ascii
        $reg_run_persist = "CurrentVersion\\Run" ascii wide

    condition:
        (all of ($bind_listen, $listen_call, $accept_call)) and
        (any of ($cron_persist, $systemd_persist, $launchd_persist, $reg_run_persist))
}

rule Backdoor_SSH_Authorized_Keys_Injection
{
    meta:
        family = "Generic-Backdoor"
        confidence = "high"
        description = "Script injectant une clé publique dans authorized_keys — backdoor SSH persistante classique"
        reference = "MITRE T1098.004 (SSH Authorized Keys)"

    strings:
        $auth_keys = ".ssh/authorized_keys" ascii
        $echo_append = />>\s*.{0,40}authorized_keys/ nocase
        $ssh_keygen = "ssh-keygen" ascii
        $chmod_ssh = "chmod 600" ascii
        $chattr = "chattr +i" ascii

    condition:
        $auth_keys and (any of ($echo_append, $ssh_keygen, $chmod_ssh, $chattr))
}

rule Backdoor_LDPreload_Rootkit
{
    meta:
        family = "Generic-Rootkit"
        confidence = "high"
        description = "Rootkit userland type LD_PRELOAD interceptant des appels systèmes courants pour se cacher"
        reference = "MITRE T1014 (Rootkit), T1574.006 (LD_PRELOAD)"

    strings:
        $ld_preload_env = "LD_PRELOAD" ascii
        $dlsym = "dlsym" ascii
        $hook_readdir = "readdir" ascii
        $hook_getdents = "getdents" ascii
        $hook_accept = "accept" ascii
        $rtld_next = "RTLD_NEXT" ascii

    condition:
        $ld_preload_env and $dlsym and (any of ($hook_readdir, $hook_getdents, $hook_accept)) and $rtld_next
}

rule Backdoor_MacOS_Malicious_LaunchAgent_Installer
{
    meta:
        family = "Generic-Backdoor"
        confidence = "medium"
        description = "Script d'installation silencieuse d'un LaunchAgent/LaunchDaemon exécutant un binaire caché"
        reference = "MITRE T1543.001 (Launch Agent), T1547.011 (Plist Modification)"

    strings:
        $launchctl_load = "launchctl load" nocase
        $plist_path = "~/Library/LaunchAgents" nocase
        $plist_path2 = "/Library/LaunchDaemons" nocase
        $hidden_flag = "RunAtLoad" ascii
        $keep_alive = "KeepAlive" ascii
        $curl_pipe = /curl\s+.{0,60}\|\s*(ba)?sh/ nocase

    condition:
        (any of ($plist_path, $plist_path2) and $launchctl_load and any of ($hidden_flag, $keep_alive)) or
        $curl_pipe
}
