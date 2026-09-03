# 中间件基线规则集 (M1-3)

50 条规则覆盖 4 大中间件:

| 文件 | 中间件 | 版本 | 规则数 |
|---|---|---|---|
| nginx.json   | Nginx HTTP Server | 1.18+         | 12 |
| apache.json  | Apache HTTP Server | 2.4+         | 12 |
| tomcat.json  | Apache Tomcat | 9 / 10           | 12 |
| mysql.json   | MySQL | 5.7 / 8.0                | 14 |
| **合计**     |       |                          | **50** |

来源:
- CIS Benchmarks (Apache HTTP Server 2.4 / Tomcat 9 / MySQL Community 8.0 / Nginx 1.0)
- DevSec Hardening Framework
- OWASP Application Security Verification Standard (ASVS)
- 等保 2.0 三级要求

ref/03-基线 M1-P1-2 目标: 160 条 (4 种 ×40)
当前: 50 起步, 后续 PR 补足:
- 防火墙/网络配置类 ~30
- 性能调优安全类 ~20
- 日志审计类 ~30
- 高级访问控制类 ~30

待 M1-3b: 扩到 160 条 + 加 Redis / Postgres / RabbitMQ / Kafka 4 种中间件
