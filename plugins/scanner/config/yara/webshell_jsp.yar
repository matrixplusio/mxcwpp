/*
 * JSP Webshell YARA 规则集 (P2-8)
 *
 * 覆盖:
 *   - JSP 一句话 (Runtime.exec / ProcessBuilder)
 *   - 内存马 JSP (Filter / Servlet 动态注入)
 *   - 经典 jspspy / Behinder JSP / Godzilla JSP / AntSword
 */

rule Webshell_JSP_Runtime_Exec {
    meta:
        description = "JSP 一句话: Runtime.exec + Request 参数"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $jsp = "<%@"
        $req = /request\.getParameter\s*\(/ nocase
        $exec1 = /Runtime\.getRuntime\(\)\.exec\s*\(/ nocase
        $exec2 = /new\s+ProcessBuilder\s*\(/ nocase
    condition:
        $jsp and $req and any of ($exec*)
}

rule Webshell_JSP_Behinder {
    meta:
        description = "JSP Behinder (冰蝎) 特征"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $b1 = "rebeyond"
        $b2 = "e45e329feb5d925b" nocase
        $b3 = "javax.crypto.Cipher"
        $b4 = /Class\.forName\s*\(\s*"javax\.crypto/
        $b5 = "Base64.getDecoder"
        $jsp_open = "<%"
    condition:
        $jsp_open and (3 of ($b*))
}

rule Webshell_JSP_Godzilla {
    meta:
        description = "JSP Godzilla (哥斯拉) 特征"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $g1 = "shell.class.jsp"
        $g2 = "javax.crypto.Cipher.getInstance"
        $g3 = "AES/ECB/PKCS5Padding"
        $g4 = "ClassLoader.defineClass"
        $g5 = "writeBytes("
        $jsp_open = "<%"
    condition:
        $jsp_open and (3 of ($g*))
}

rule Webshell_JSP_Memshell_Filter {
    meta:
        description = "JSP 内存马 - 运行时注册 Filter (T1505.003 内存 webshell)"
        author = "mxsec"
        severity = "critical"
        category = "memshell"
        attck = "T1505.003"
    strings:
        $m1 = "StandardContext"
        $m2 = "addFilterDef"
        $m3 = "FilterChain.doFilter"
        $m4 = "registerCleanupMethods"
        $m5 = "filterMaps"
    condition:
        2 of ($m*)
}

rule Webshell_JSP_Memshell_Servlet {
    meta:
        description = "JSP 内存马 - 运行时注册 Servlet"
        author = "mxsec"
        severity = "critical"
        category = "memshell"
        attck = "T1505.003"
    strings:
        $s1 = "StandardWrapper"
        $s2 = "addServletMappingDecoded"
        $s3 = "servletMappings"
        $s4 = "createServlet"
    condition:
        2 of ($s*)
}

rule Webshell_JSP_JspSpy {
    meta:
        description = "JspSpy 经典大马"
        author = "mxsec"
        severity = "critical"
        category = "webshell"
        attck = "T1505.003"
    strings:
        $j1 = "jspspy"
        $j2 = "jspspider"
        $j3 = "WebShell By Ninty"
        $j4 = /<title>JspSpy/
    condition:
        any of ($j*)
}
