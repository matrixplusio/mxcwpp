<?php
/**
 * mxsec PHP RASP — auto_prepend_file 模式 (P4-3).
 *
 * 启用 (无需重新编译 PHP):
 *
 *   ; /etc/php/8.x/fpm/php.ini
 *   auto_prepend_file = /opt/mxsec/rasp/mxsec_rasp.php
 *
 *   ; 通过 hook 注册的危险函数会被包装报警
 *
 * 严格 read-only (PR63 哲学硬约束):
 *   - 仅 register_shutdown_function + override 包装, 不阻断 PHP 执行
 *   - 失败必须 silent (永不影响业务流)
 *
 * 完整 Zend extension (libmxsec_rasp_php.so) 留 Sprint 5+, 性能 5x+.
 */

namespace MxsecRasp;

class Agent {
    private static $reporter = null;
    private static $config = [
        'uds_path' => '/var/run/mxsec-rasp.sock',
        'tenant_id' => 't-default',
        'enabled' => true,
    ];

    public static function install(array $cfg = []) {
        if (isset($cfg['uds_path'])) self::$config['uds_path'] = $cfg['uds_path'];
        if (isset($cfg['tenant_id'])) self::$config['tenant_id'] = $cfg['tenant_id'];
        if (!self::$config['enabled']) return;

        self::$reporter = new Reporter(self::$config['uds_path'], self::$config['tenant_id']);

        // 注册 shutdown handler 把队列 flush
        register_shutdown_function(function () {
            if (self::$reporter) self::$reporter->flush();
        });
    }

    public static function emit($kind, $className, $methodName, array $args = []) {
        if (!self::$reporter) return;
        try {
            $ev = [
                'kind' => $kind,
                'class_name' => $className,
                'method_name' => $methodName,
                'arguments' => array_map(function ($a) {
                    $s = is_string($a) ? $a : (is_scalar($a) ? (string)$a : gettype($a));
                    return strlen($s) > 256 ? substr($s, 0, 256) . '...' : $s;
                }, array_slice($args, 0, 5)),
                'pid' => getmypid(),
                'tenant_id' => self::$config['tenant_id'],
                'timestamp' => (int)(microtime(true) * 1000),
                'mode' => 'observe',
                'language' => 'php',
                'http_method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : null,
                'http_url' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : null,
                'http_remote_ip' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null,
                'stack_trace' => self::captureStack(),
            ];
            self::$reporter->emit($ev);
        } catch (\Throwable $t) {
            // 永不影响业务
        }
    }

    private static function captureStack($maxFrames = 30) {
        $stack = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, $maxFrames);
        $out = [];
        foreach ($stack as $frame) {
            if (isset($frame['class']) && strpos($frame['class'], 'MxsecRasp\\') === 0) continue;
            $file = isset($frame['file']) ? basename($frame['file']) : '?';
            $line = isset($frame['line']) ? $frame['line'] : 0;
            $func = isset($frame['function']) ? $frame['function'] : '?';
            $class = isset($frame['class']) ? $frame['class'] . '::' : '';
            $out[] = "{$class}{$func}({$file}:{$line})";
        }
        return $out;
    }
}

class Reporter {
    private $uds;
    private $tenant;
    private $sock = null;
    private $queue = [];

    public function __construct($udsPath, $tenant) {
        $this->uds = $udsPath;
        $this->tenant = $tenant;
    }

    public function emit($ev) {
        $this->queue[] = $ev;
        if (count($this->queue) >= 50) {
            $this->flush();
        }
    }

    public function flush() {
        if (empty($this->queue)) return;
        try {
            if ($this->sock === null) {
                $this->sock = @stream_socket_client("unix://{$this->uds}", $errno, $errstr, 5);
                if (!$this->sock) {
                    $this->queue = []; // 丢
                    return;
                }
            }
            foreach ($this->queue as $ev) {
                $body = json_encode($ev, JSON_UNESCAPED_UNICODE);
                $header = pack('N', strlen($body));
                @fwrite($this->sock, $header . $body);
            }
            $this->queue = [];
        } catch (\Throwable $t) {
            $this->queue = []; // 丢
        }
    }
}

// 自动启动 (auto_prepend_file 即执行)
Agent::install([
    'uds_path' => getenv('MXSEC_RASP_UDS') ?: '/var/run/mxsec-rasp.sock',
    'tenant_id' => getenv('MXSEC_RASP_TENANT') ?: 't-default',
]);

/**
 * PHP 危险函数监控走 disable_functions + open_basedir 没法 hook 拒绝, 走 auto_prepend
 * 包装常见 sink 函数. 完整列表:
 *   - eval / assert (语言结构, 无法 override)
 *   - system / exec / shell_exec / passthru / popen / proc_open / pcntl_exec
 *   - include / require / file_put_contents / fwrite / move_uploaded_file
 *
 * 替代方案: declare(ticks=1) + register_tick_function (慢, 已弃用)
 * 推荐: 编译 libmxsec_rasp_php.so Zend extension 走 zend_compile_string +
 *      zend_execute_internal hook (Sprint 5+).
 */
