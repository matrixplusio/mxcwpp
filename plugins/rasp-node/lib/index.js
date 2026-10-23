/**
 * @mxcwpp/rasp — Node.js RASP entrypoint (P4-13).
 *
 * 用法:
 *   require('@mxcwpp/rasp').install({
 *     udsPath: '/var/run/mxcwpp/rasp-node.sock',
 *     tenantId: 't-default',
 *   });
 *
 * 严格 read-only RASP 哲学: 仅观察 + 上报, 不阻塞业务调用.
 *
 * Hook 覆盖:
 *   - child_process.exec / spawn / execSync (命令执行)
 *   - fs.readFile / writeFile / unlink (文件操作)
 *   - http.request / https.request (出站请求)
 *   - net.connect (socket 出站)
 *   - vm.runInThisContext / Function 构造 (eval)
 *   - require (动态加载 .so / .node native)
 *   - process.dlopen (native module load)
 */
'use strict';

const Reporter = require('./reporter');
const Hooks = require('./hooks');

const DEFAULT_CONFIG = {
  udsPath: '/var/run/mxcwpp/rasp-node.sock',
  tenantId: 't-default',
  enabled: true,
  queueCapacity: 10000,
  maxEventsPerSecond: 5000,
  reconnectInterval: 3000,
};

let installed = false;
let reporter = null;

function install(userConfig) {
  if (installed) {
    return reporter;
  }
  const config = Object.assign({}, DEFAULT_CONFIG, userConfig || {});
  if (!config.enabled) {
    return null;
  }
  reporter = new Reporter(config);
  reporter.start();
  Hooks.install(reporter, config);
  installed = true;

  process.on('beforeExit', () => {
    try {
      reporter.flush();
    } catch (e) {
      // 失败不阻塞退出
    }
  });

  return reporter;
}

function uninstall() {
  if (!installed) return;
  Hooks.uninstall();
  if (reporter) reporter.stop();
  installed = false;
}

module.exports = {
  install,
  uninstall,
  get reporter() { return reporter; },
};
