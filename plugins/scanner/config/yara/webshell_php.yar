/*
 * PHP Webshell YARA 规则集 (P2-8)
 *
 * 覆盖经典 PHP webshell:
 *   - 一句话 木马 (eval/assert + base64)
 *   - 大马 (Filemanager / Bypass / WSO)
 *   - 内存马类 (Behinder Java 兼容 PHP 版本 / Godzilla / AntSword)
 *   - 命令执行 / 文件操作 / 数据库 dump 类
 *
 * 命中 → 严重 critical, 自动隔离 + 主机 isolation 推荐
 *
 * 参考: Yara-Rules / Neo23x0/signature-base / godaddy/yara-rules-srm
 */

rule Webshell_PHP_Eval_Base64 {
    meta:
        description = "PHP 一句话: eval/assert + base64_decode"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $php_open = "<?php"
        $eval_b64_1 = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $eval_b64_2 = /assert\s*\(\s*base64_decode\s*\(/ nocase
        $eval_gz   = /eval\s*\(\s*gzinflate\s*\(/ nocase
        $eval_str_rot = /eval\s*\(\s*str_rot13\s*\(/ nocase
    condition:
        $php_open and any of ($eval_b64_*, $eval_gz, $eval_str_rot)
}

rule Webshell_PHP_Shell_Exec {
    meta:
        description = "PHP webshell 含命令执行函数 + 参数取自 GET/POST/COOKIE"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $php_open = "<?php"
        $get = /\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $exec1 = /\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(/ nocase
        $exec2 = /\bbackticks\s*\(/
    condition:
        $php_open and $get and any of ($exec*)
}

rule Webshell_PHP_Behinder {
    meta:
        description = "PHP Behinder (冰蝎) 一句话特征"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $b1 = "openssl_decrypt" nocase
        $b2 = "Z2V0X2NvbnRlbnRz" nocase  // base64 'get_contents'
        $b3 = "rebeyond"
        $b4 = /\$key\s*=\s*"e45e329feb5d925b"/ nocase
        $php_open = "<?php"
    condition:
        $php_open and (2 of ($b*))
}

rule Webshell_PHP_Godzilla {
    meta:
        description = "PHP Godzilla (哥斯拉) 特征 - aes 加密 + base64 payload"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $g1 = "AES" nocase
        $g2 = "openssl_decrypt" nocase
        $g3 = /encode\s*=\s*"base64"/ nocase
        $g4 = "shell.class.php" nocase
        $php_open = "<?php"
    condition:
        $php_open and (3 of ($g*))
}

rule Webshell_PHP_AntSword {
    meta:
        description = "PHP AntSword (蚁剑) 特征"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $a1 = "antsword"
        $a2 = "@ini_set(\"display_errors"
        $a3 = "Z=base64_decode" nocase
        $a4 = "M=str_replace" nocase
        $php_open = "<?php"
    condition:
        $php_open and (2 of ($a*))
}

rule Webshell_PHP_C99_R57 {
    meta:
        description = "PHP C99 / R57 大马特征"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $c1 = "c99shell"
        $c2 = "r57shell"
        $c3 = "FilesMan"
        $c4 = "WSO 2.5"
        $c5 = "Bypass mode"
        $c6 = "Captain Crunch Security"
    condition:
        any of ($c*)
}

rule Webshell_PHP_File_Upload_To_Web {
    meta:
        description = "PHP 写入 .php 到 web 根目录 (上传后落地)"
        author = "mxsec"
        severity = "high"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $php_open = "<?php"
        $f1 = /file_put_contents\s*\([^,]+\.php['"]/ nocase
        $f2 = /fwrite\s*\([^,]+,\s*['"]<\?php/ nocase
        $f3 = /move_uploaded_file\s*\([^)]+,\s*[^)]+\.php['"]?\s*\)/ nocase
    condition:
        $php_open and any of ($f*)
}
