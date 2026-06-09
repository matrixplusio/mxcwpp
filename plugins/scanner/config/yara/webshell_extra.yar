/*
 * 扩展 WebShell YARA 规则 (P4-10)
 *
 * 把 18 → 50 条规则集补足. 覆盖:
 *   - 内存马 (Behinder/Godzilla/AntSword PHP/JSP/.NET 变种)
 *   - PowerShell / VBScript / HTA 风格 webshell
 *   - Python / Node / Go / Lua webshell
 *   - 加密/混淆 (XOR / RC4 / AES / hex)
 *   - 非 webshell 但常驻木马 (cron / systemd / .bashrc)
 *
 * 严重级: critical (内存马/AES) / high (eval+加密) / medium (单一特征)
 *
 * 命中策略: 与 P2-8 webshell_*.yar 同管道, 走 scanner.YaraEngine 评估
 */

rule Memshell_PHP_AntSword_Crypt {
    meta:
        description = "PHP 内存马 AntSword 加密通信特征"
        author = "mxsec"
        severity = "critical"
        category = "memshell"
        attck = "T1505.003"
    strings:
        $tag = "<?php"
        $a1 = /openssl_decrypt\s*\([^)]+,\s*['"]AES-128-ECB['"]/ nocase
        $a2 = /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)/ nocase
        $a3 = /\$_REQUEST\[[^\]]+\]\s*\(\s*\$_REQUEST/ nocase
    condition:
        $tag and any of ($a*)
}

rule Memshell_PHP_Godzilla_BasePass {
    meta:
        description = "PHP Godzilla webshell pass+key+payloadName 三参"
        author = "mxsec"
        severity = "critical"
        category = "memshell"
    strings:
        $a = "base64_decode($_POST" nocase
        $b = "key=" nocase
        $c = "pass=" nocase
        $d = "payloadName" nocase
    condition:
        2 of them
}

rule Memshell_PHP_Behinder_AES {
    meta:
        description = "Behinder 冰蝎 PHP 端 AES 加密"
        author = "mxsec"
        severity = "critical"
        category = "memshell"
    strings:
        $a = "openssl_decrypt" nocase
        $b = "AES128" nocase
        $c = "@eval" nocase
        $d = /\$_(POST|GET)\[[^\]]+\]/ nocase
    condition:
        all of ($a, $b, $c) or all of ($a, $b, $d)
}

rule Webshell_PHP_Wso25 {
    meta:
        description = "WSO 2.5 大马"
        author = "mxsec"
        severity = "critical"
    strings:
        $a = "WSO 2.5" nocase
        $b = "wso_login" nocase
        $c = "actbox" nocase
    condition:
        any of them
}

rule Webshell_PHP_R57Shell {
    meta:
        description = "r57shell php 大马"
        severity = "critical"
    strings:
        $a = "r57shell" nocase
        $b = "r57_passwd" nocase
    condition:
        any of them
}

rule Webshell_PHP_C99Madshell {
    meta:
        description = "c99madshell PHP webshell"
        severity = "critical"
    strings:
        $a = "c99madshell" nocase
        $b = "c99_buff_prepare" nocase
    condition:
        any of them
}

rule Webshell_PHP_RootKitC99 {
    meta:
        description = "c99 衍生 RootKit-php"
        severity = "high"
    strings:
        $a = "set_time_limit(0)" nocase
        $b = "@error_reporting(0)" nocase
        $c = /exec\s*\(\s*\$_(GET|POST)\[/ nocase
        $d = /system\s*\(\s*\$_(GET|POST)\[/ nocase
    condition:
        $a and $b and 1 of ($c, $d)
}

rule Memshell_JSP_Behinder_Decrypt {
    meta:
        description = "JSP 冰蝎 AES base64Decode 模板"
        severity = "critical"
        category = "memshell"
    strings:
        $a = "Cipher.getInstance(\"AES" nocase
        $b = "javax.crypto.spec.SecretKeySpec" nocase
        $c = "request.getReader()" nocase
        $d = "defineClass(" nocase
    condition:
        3 of them
}

rule Memshell_JSP_Godzilla_X-FORWARDED {
    meta:
        description = "JSP Godzilla X-Forwarded-For header 解析载荷"
        severity = "critical"
    strings:
        $a = "getHeader(\"X-Forwarded-For\")" nocase
        $b = "Cipher.getInstance" nocase
        $c = "defineClass" nocase
    condition:
        2 of them
}

rule Memshell_JSP_TomcatValve {
    meta:
        description = "Tomcat Valve 内存马 (InvokeValve / ApplicationFilterChain hook)"
        severity = "critical"
        category = "memshell"
    strings:
        $a = "org.apache.catalina.valves.ValveBase" nocase
        $b = "addValve" nocase
        $c = "getStandardContext" nocase
        $d = "ApplicationFilterChain" nocase
    condition:
        2 of them
}

rule Memshell_JSP_SpringInterceptor {
    meta:
        description = "Spring HandlerInterceptor 内存马"
        severity = "critical"
        category = "memshell"
    strings:
        $a = "HandlerInterceptor" nocase
        $b = "preHandle" nocase
        $c = "Runtime.getRuntime().exec" nocase
    condition:
        all of them
}

rule Memshell_JSP_DispatcherServlet {
    meta:
        description = "Spring DispatcherServlet 反射注入 Controller"
        severity = "critical"
    strings:
        $a = "RequestMappingHandlerMapping" nocase
        $b = "registerMapping" nocase
        $c = "Runtime" nocase
    condition:
        all of them
}

rule Memshell_DotNet_HttpModule {
    meta:
        description = ".NET HttpModule 内存马"
        severity = "critical"
        category = "memshell"
    strings:
        $a = "IHttpModule" nocase
        $b = "BeginRequest" nocase
        $c = "Process.Start" nocase
    condition:
        all of them
}

rule Webshell_ASPX_Eval {
    meta:
        description = "ASPX eval/Execute webshell"
        severity = "critical"
    strings:
        $a = "Server.CreateObject(\"WSCRIPT.SHELL\")" nocase
        $b = "<%@ Page Language=" nocase
        $c = "Request[\"" nocase
        $d = "Execute(" nocase
    condition:
        $b and 1 of ($a, $c, $d)
}

rule Webshell_ASP_Caidao {
    meta:
        description = "中国菜刀 ASP 一句话"
        severity = "critical"
    strings:
        $a = "execute(Request" nocase
        $b = "eval Request" nocase
    condition:
        any of them
}

rule Webshell_Python_Eval {
    meta:
        description = "Python webshell exec/eval + request.args"
        severity = "high"
    strings:
        $a = /exec\s*\(\s*request\.(args|values|form)\[/ nocase
        $b = /eval\s*\(\s*request\.(args|values|form)\[/ nocase
        $c = "subprocess.Popen" nocase
        $d = "import os" nocase
    condition:
        ($a or $b) and ($c or $d)
}

rule Webshell_Python_Flask_Pickle {
    meta:
        description = "Python pickle.loads + flask request 反序列化木马"
        severity = "critical"
    strings:
        $a = "pickle.loads" nocase
        $b = "request.data" nocase
        $c = "base64.b64decode" nocase
    condition:
        all of them
}

rule Webshell_Node_Eval {
    meta:
        description = "Node.js webshell new Function / eval req.body"
        severity = "high"
    strings:
        $a = /new\s+Function\s*\(\s*req\.(body|query)/ nocase
        $b = /eval\s*\(\s*req\.(body|query)/ nocase
        $c = "child_process.exec" nocase
    condition:
        ($a or $b) and $c
}

rule Webshell_Go_HTTP_Eval {
    meta:
        description = "Go 后门 r.URL.Query() + exec.Command"
        severity = "high"
    strings:
        $a = "exec.Command" nocase
        $b = "r.URL.Query()" nocase
        $c = "io.Copy(w" nocase
    condition:
        2 of them
}

rule Webshell_Lua_OS_Execute {
    meta:
        description = "Lua webshell os.execute(ngx.var.arg_)"
        severity = "high"
    strings:
        $a = /os\.execute\s*\(\s*ngx\.var\.arg_/ nocase
        $b = /io\.popen\s*\(\s*ngx\.var\.arg_/ nocase
    condition:
        any of them
}

rule Suspicious_Cronjob_Backdoor {
    meta:
        description = "crontab 加 base64 解码远程下载"
        severity = "high"
        category = "persistence"
        attck = "T1053.003"
    strings:
        $a = "* * * * *" nocase
        $b = "base64 -d" nocase
        $c = "curl " nocase
        $d = "wget " nocase
        $e = "/bin/bash" nocase
    condition:
        $a and $b and 1 of ($c, $d, $e)
}

rule Suspicious_Systemd_Reverse_Shell {
    meta:
        description = "systemd unit 反向 shell"
        severity = "high"
        category = "persistence"
    strings:
        $a = "[Service]" nocase
        $b = /ExecStart=.*\/dev\/tcp\// nocase
        $c = /ExecStart=.*bash\s+-i/ nocase
    condition:
        $a and ($b or $c)
}

rule Suspicious_Bashrc_Persistence {
    meta:
        description = ".bashrc 注入反向 shell"
        severity = "high"
        category = "persistence"
        attck = "T1546.004"
    strings:
        $a = "bash -i" nocase
        $b = "/dev/tcp/" nocase
        $c = "nc -e" nocase
        $d = "ncat " nocase
    condition:
        2 of them
}

rule Suspicious_PowerShell_Downloader {
    meta:
        description = "PowerShell DownloadString / DownloadFile"
        severity = "high"
        category = "downloader"
    strings:
        $a = "DownloadString" nocase
        $b = "DownloadFile" nocase
        $c = "IEX" nocase
        $d = "Invoke-Expression" nocase
        $e = "-EncodedCommand" nocase
    condition:
        2 of them
}

rule Suspicious_PowerShell_Empire {
    meta:
        description = "Empire / PowerSploit 标志串"
        severity = "critical"
    strings:
        $a = "Invoke-Mimikatz" nocase
        $b = "Invoke-Empire" nocase
        $c = "PowerSploit" nocase
        $d = "Invoke-Shellcode" nocase
    condition:
        any of them
}

rule Suspicious_HTA_VBScript {
    meta:
        description = "HTA 含 WScript.Shell"
        severity = "high"
    strings:
        $a = "<hta:application" nocase
        $b = "WScript.Shell" nocase
        $c = "ActiveXObject" nocase
    condition:
        $a and ($b or $c)
}

rule Suspicious_XOR_Obfuscation_PHP {
    meta:
        description = "PHP XOR 解码混淆"
        severity = "high"
    strings:
        $a = "<?php" nocase
        $b = /\$[a-zA-Z_]+\s*\^\s*\$[a-zA-Z_]+/
        $c = "eval(" nocase
    condition:
        all of them
}

rule Suspicious_RC4_Webshell {
    meta:
        description = "RC4 自实现 + eval/exec"
        severity = "critical"
    strings:
        $a = "RC4" nocase
        $b = /S\[i\]\s*=\s*i/
        $c = "eval(" nocase
        $d = "Runtime.getRuntime" nocase
    condition:
        $a and ($b or $c or $d)
}

rule Malware_XMRig_Strings {
    meta:
        description = "XMRig 挖矿二进制特征串"
        severity = "critical"
        category = "miner"
    strings:
        $a = "XMRig" nocase
        $b = "stratum+tcp" nocase
        $c = "donateLevel" nocase
        $d = "pool.minexmr.com" nocase
    condition:
        2 of them
}

rule Malware_KinSing_Indicator {
    meta:
        description = "KinSing 蠕虫脚本特征"
        severity = "critical"
        category = "worm"
    strings:
        $a = "kinsing" nocase
        $b = "kdevtmpfsi" nocase
        $c = "kthreaddi" nocase
    condition:
        any of them
}

rule Malware_TeamTNT_Indicator {
    meta:
        description = "TeamTNT 容器逃逸"
        severity = "critical"
    strings:
        $a = "teamtnt" nocase
        $b = "weaveworks" nocase
        $c = "Hilde" nocase
        $d = "Aikido" nocase
    condition:
        any of them
}

rule Malware_LinuxMirai_Strings {
    meta:
        description = "Mirai 变种 botnet 指令串"
        severity = "critical"
    strings:
        $a = "Welcome.god" nocase
        $b = "POST /cdn-cgi/" nocase
        $c = "/proc/net/tcp" nocase
        $d = "killer_init" nocase
    condition:
        2 of them
}

rule Suspicious_LDPreload_RootKit {
    meta:
        description = "LD_PRELOAD rootkit pattern"
        severity = "critical"
        category = "rootkit"
        attck = "T1574.006"
    strings:
        $a = "dlsym" nocase
        $b = "ld.so.preload" nocase
        $c = "LD_PRELOAD" nocase
        $d = "RTLD_NEXT" nocase
    condition:
        3 of them
}
