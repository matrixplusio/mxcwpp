/*
 * ASPX / Python / Perl / Go Webshell YARA 规则集 (P2-8)
 */

rule Webshell_ASPX_Eval {
    meta:
        description = "ASPX 一句话: eval + Request"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $aspx = /<%@\s+Page\s+Language/ nocase
        $eval1 = "eval(Request" nocase
        $eval2 = "Execute(Request" nocase
        $cmd1 = "System.Diagnostics.Process" nocase
    condition:
        $aspx and ($eval1 or $eval2 or $cmd1)
}

rule Webshell_Python_Reverse_Shell {
    meta:
        description = "Python 反弹 shell 典型 pattern"
        author = "mxsec"
        severity = "critical"
        category = "reverse_shell"
        attck = "T1059.006"
    strings:
        $py = /#!\/usr\/bin\/(env\s+)?python/
        $s1 = "socket.socket("
        $s2 = "os.dup2"
        $s3 = "pty.spawn"
        $s4 = "subprocess.call(['/bin/sh'])"
        $s5 = "subprocess.call(['/bin/bash'])"
    condition:
        ($py or filesize < 4KB) and (3 of ($s*))
}

rule Webshell_Perl_Eval {
    meta:
        description = "Perl 反弹 shell / 一句话"
        author = "mxsec"
        severity = "high"
        category = "reverse_shell"
        attck = "T1059.006"
    strings:
        $perl = /#!\/usr\/bin\/(env\s+)?perl/
        $s1 = "Socket::"
        $s2 = "exec(\"/bin/sh"
        $s3 = "exec('/bin/bash"
        $s4 = "STDIN->fdopen"
    condition:
        $perl and (2 of ($s*))
}

rule Webshell_Bash_Reverse {
    meta:
        description = "Bash 反弹 shell - /dev/tcp 经典 pattern"
        author = "mxsec"
        severity = "critical"
        category = "reverse_shell"
        attck = "T1059.004"
    strings:
        $b1 = /bash\s+-i\s+>&\s*\/dev\/tcp/
        $b2 = /\/dev\/tcp\/[^/]+\/\d+/
        $b3 = /0<&\d+/
        $b4 = /1>&\d+/
    condition:
        $b1 or ($b2 and ($b3 or $b4))
}

rule Webshell_Generic_Encoded_PHP {
    meta:
        description = "PHP 通用 obfuscated (chr/ord/str_replace 拼接)"
        author = "mxsec"
        severity = "medium"
        category = "webshell"
        attck = "T1027"
    strings:
        $obf1 = /eval\s*\(\s*chr\s*\(/ nocase
        $obf2 = /\$[a-zA-Z0-9_]+\s*=\s*chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)/
        $obf3 = /str_replace\s*\(\s*['"][a-zA-Z0-9]['"]\s*,\s*['"][a-zA-Z0-9]['"]/ nocase
        $php_open = "<?php"
    condition:
        $php_open and (2 of ($obf*))
}
