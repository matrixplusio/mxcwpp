/**
 * 模块 hook 集合.
 *
 * 严格 read-only: 包装原方法, 上报事件后调用原方法, 不阻塞.
 */
'use strict';

const installed = {};

function captureStack(skip = 2) {
  const e = new Error();
  const lines = (e.stack || '').split('\n').slice(skip, skip + 30);
  return lines.map((l) => l.trim()).join('\n');
}

function nowEvent(kind, opts, config) {
  return Object.assign({
    kind,
    pid: process.pid,
    tenant_id: config.tenantId,
    timestamp: Date.now(),
    mode: 'observe',
    language: 'nodejs',
    stack_trace: captureStack(3),
  }, opts);
}

function installChildProcess(reporter, config) {
  const cp = require('child_process');
  const originalExec = cp.exec;
  const originalSpawn = cp.spawn;
  const originalExecSync = cp.execSync;

  cp.exec = function (cmd) {
    reporter.enqueue(nowEvent('cmd_exec', {
      class_name: 'child_process',
      method_name: 'exec',
      arguments: [String(cmd).slice(0, 1024)],
    }, config));
    return originalExec.apply(this, arguments);
  };
  cp.spawn = function (cmd, args) {
    reporter.enqueue(nowEvent('cmd_spawn', {
      class_name: 'child_process',
      method_name: 'spawn',
      arguments: [String(cmd), Array.isArray(args) ? args.map(String).join(' ').slice(0, 1024) : ''],
    }, config));
    return originalSpawn.apply(this, arguments);
  };
  cp.execSync = function (cmd) {
    reporter.enqueue(nowEvent('cmd_exec_sync', {
      class_name: 'child_process',
      method_name: 'execSync',
      arguments: [String(cmd).slice(0, 1024)],
    }, config));
    return originalExecSync.apply(this, arguments);
  };

  installed.child_process = { originalExec, originalSpawn, originalExecSync, mod: cp };
}

function installFs(reporter, config) {
  const fs = require('fs');
  const originalUnlink = fs.unlink;
  const originalUnlinkSync = fs.unlinkSync;
  const originalWriteFile = fs.writeFile;

  fs.unlink = function (path) {
    reporter.enqueue(nowEvent('fs_unlink', {
      class_name: 'fs',
      method_name: 'unlink',
      arguments: [String(path).slice(0, 512)],
    }, config));
    return originalUnlink.apply(this, arguments);
  };
  fs.unlinkSync = function (path) {
    reporter.enqueue(nowEvent('fs_unlink_sync', {
      class_name: 'fs',
      method_name: 'unlinkSync',
      arguments: [String(path).slice(0, 512)],
    }, config));
    return originalUnlinkSync.apply(this, arguments);
  };
  fs.writeFile = function (path) {
    reporter.enqueue(nowEvent('fs_write', {
      class_name: 'fs',
      method_name: 'writeFile',
      arguments: [String(path).slice(0, 512)],
    }, config));
    return originalWriteFile.apply(this, arguments);
  };

  installed.fs = { originalUnlink, originalUnlinkSync, originalWriteFile, mod: fs };
}

function installHttp(reporter, config) {
  const http = require('http');
  const https = require('https');
  const originalHttpRequest = http.request;
  const originalHttpsRequest = https.request;

  http.request = function (opts) {
    const url = typeof opts === 'string' ? opts : (opts && opts.host) || '';
    reporter.enqueue(nowEvent('http_request', {
      class_name: 'http',
      method_name: 'request',
      arguments: [String(url).slice(0, 512)],
    }, config));
    return originalHttpRequest.apply(this, arguments);
  };
  https.request = function (opts) {
    const url = typeof opts === 'string' ? opts : (opts && opts.host) || '';
    reporter.enqueue(nowEvent('https_request', {
      class_name: 'https',
      method_name: 'request',
      arguments: [String(url).slice(0, 512)],
    }, config));
    return originalHttpsRequest.apply(this, arguments);
  };

  installed.http = { originalHttpRequest, originalHttpsRequest, http, https };
}

function installVm(reporter, config) {
  const vm = require('vm');
  const originalRun = vm.runInThisContext;
  vm.runInThisContext = function (code) {
    reporter.enqueue(nowEvent('vm_eval', {
      class_name: 'vm',
      method_name: 'runInThisContext',
      arguments: [String(code).slice(0, 1024)],
    }, config));
    return originalRun.apply(this, arguments);
  };
  installed.vm = { originalRun, mod: vm };
}

function installDlopen(reporter, config) {
  const originalDlopen = process.dlopen;
  process.dlopen = function (mod, path) {
    reporter.enqueue(nowEvent('native_load', {
      class_name: 'process',
      method_name: 'dlopen',
      arguments: [String(path).slice(0, 512)],
    }, config));
    return originalDlopen.apply(this, arguments);
  };
  installed.dlopen = { originalDlopen };
}

function install(reporter, config) {
  try { installChildProcess(reporter, config); } catch (_) {}
  try { installFs(reporter, config); } catch (_) {}
  try { installHttp(reporter, config); } catch (_) {}
  try { installVm(reporter, config); } catch (_) {}
  try { installDlopen(reporter, config); } catch (_) {}
}

function uninstall() {
  if (installed.child_process) {
    installed.child_process.mod.exec = installed.child_process.originalExec;
    installed.child_process.mod.spawn = installed.child_process.originalSpawn;
    installed.child_process.mod.execSync = installed.child_process.originalExecSync;
  }
  if (installed.fs) {
    installed.fs.mod.unlink = installed.fs.originalUnlink;
    installed.fs.mod.unlinkSync = installed.fs.originalUnlinkSync;
    installed.fs.mod.writeFile = installed.fs.originalWriteFile;
  }
  if (installed.http) {
    installed.http.http.request = installed.http.originalHttpRequest;
    installed.http.https.request = installed.http.originalHttpsRequest;
  }
  if (installed.vm) {
    installed.vm.mod.runInThisContext = installed.vm.originalRun;
  }
  if (installed.dlopen) {
    process.dlopen = installed.dlopen.originalDlopen;
  }
}

module.exports = { install, uninstall };
