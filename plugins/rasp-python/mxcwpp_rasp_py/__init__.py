"""mxcwpp Python RASP (P4-2).

PEP 578 audit hook + sys.settrace 双通道监控 Python 应用运行时危险调用.

启用:

    # 方式 1: 应用启动时 import
    import mxcwpp_rasp_py
    mxcwpp_rasp_py.install(uds_path='/var/run/mxcwpp-rasp.sock',
                          tenant_id='t-default')

    # 方式 2: PYTHONSTARTUP 环境变量自动注入
    export PYTHONSTARTUP=/opt/mxcwpp/rasp/mxcwpp_startup.py

严格 read-only (PR63 哲学硬约束):
    - 仅观察 + 上报, 不抛异常 / 不修改返回值
    - audit hook 不允许调用 sys.addaudithook 自身 (无限递归保护)
    - 失败必须 silent (永不影响业务流)

监控的 audit events (subset, PEP 578):
    - compile               代码动态编译
    - exec                  exec/eval 调用
    - subprocess.Popen      子进程创建
    - os.system             shell 调用
    - os.exec*              execve 系列
    - socket.connect/.bind  出站/监听
    - pickle.find_class     反序列化 sink
    - marshal.loads         marshal 反序列化
    - importlib.find_spec   动态 import
    - urllib.Request        出站 HTTP
    - open                  文件打开 (写模式时关注)
"""

from .agent import install, RaspConfig
from .reporter import EventReporter
from .event import RaspEvent

__version__ = "0.1.0"

__all__ = ["install", "RaspConfig", "EventReporter", "RaspEvent"]
