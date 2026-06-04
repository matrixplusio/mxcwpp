-- 清理 dep_scanner 历史数据（P0-1 砍 handler 后部署时跑一次）
--
-- 背景：dep_scanner 扫源码文件（go.sum / requirements.txt / pom.xml / package-lock.json / Cargo.lock），
-- CWPP 不该扫开发文件。1.2.0 起 handler 已砍，旧 software 表残留记录需清理，
-- 否则匹配引擎仍会消费这些虚假"已装"包，与运行实际不符。
--
-- 受影响 package_type：go / npm / yarn / pip / pipfile / poetry / maven / gradle / cargo
-- （这些既被 dep_scanner 写，也被 python_packages/node_packages/jar_scanner/go_buildinfo 写——
--  后四者通过 source_handler 区分。1.2.0 前无 source_handler，按 source_file 路径特征判定。）
--
-- 判定准则：source_file 指向 go.sum / package-lock.json / requirements.txt / pom.xml / Pipfile.lock /
--           poetry.lock / build.gradle / Cargo.lock 的均为 dep_scanner 历史脏数据。
--
-- 跑之前建议先 SELECT COUNT(*) 看影响行数。

-- 1. 预览待清理行数
SELECT
    package_type,
    COUNT(*) AS rows_affected
FROM software
WHERE source_file LIKE '%/go.sum'
   OR source_file LIKE '%/package-lock.json'
   OR source_file LIKE '%/requirements.txt'
   OR source_file LIKE '%/pom.xml'
   OR source_file LIKE '%/Pipfile.lock'
   OR source_file LIKE '%/poetry.lock'
   OR source_file LIKE '%/build.gradle'
   OR source_file LIKE '%/build.gradle.kts'
   OR source_file LIKE '%/Cargo.lock'
   OR source_file LIKE '%/yarn.lock'
GROUP BY package_type;

-- 2. 清理 software 表脏数据
DELETE FROM software
WHERE source_file LIKE '%/go.sum'
   OR source_file LIKE '%/package-lock.json'
   OR source_file LIKE '%/requirements.txt'
   OR source_file LIKE '%/pom.xml'
   OR source_file LIKE '%/Pipfile.lock'
   OR source_file LIKE '%/poetry.lock'
   OR source_file LIKE '%/build.gradle'
   OR source_file LIKE '%/build.gradle.kts'
   OR source_file LIKE '%/Cargo.lock'
   OR source_file LIKE '%/yarn.lock';

-- 3. 清理孤儿 host_vulnerabilities（其 software 记录已删，vuln 关联也应清）
--    本步骤可选——若担心丢历史告警可不跑。仅清理已被 1.2.0 collector 重扫确认不存在的 vuln-host 关联。
--    保守起见，建议先看下次 ScanAll 后人工核对再决定是否跑此步。
