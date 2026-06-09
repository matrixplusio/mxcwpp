#!/usr/bin/env bash
set -euo pipefail
DIR="test-results/deep-pages-report"
[ -d "$DIR" ] || { echo "no $DIR"; exit 1; }
OUT="$DIR/report.md"
node -e "
const fs=require('fs'),path=require('path');
const dir='$DIR';
const all=fs.readdirSync(dir).filter(f=>/^report-w\d+\.json\$/.test(f))
  .flatMap(f=>JSON.parse(fs.readFileSync(path.join(dir,f),'utf8')));
const pass=all.filter(r=>r.status==='PASS').length;
const warn=all.filter(r=>r.status==='WARN').length;
const fail=all.filter(r=>r.status==='FAIL').length;
const tabsTotal=all.reduce((s,r)=>s+r.tabsClicked,0);
const md=[];
md.push(\`# UI 深度巡检报告 (\${all.length} 场景, 累计 \${tabsTotal} tabs 点击)\\n\`);
md.push(\`- PASS: \${pass} / WARN: \${warn} / FAIL: \${fail}\\n\`);
md.push('| Scenario | Status | tabs | 5xx | 4xx | console | notes |');
md.push('|---|---|---|---|---|---|---|');
for(const r of all.sort((a,b)=>a.scenario.localeCompare(b.scenario)))
  md.push(\`| \${r.scenario} | \${r.status} | \${r.tabsClicked} | \${r.http5xx.length} | \${r.http4xx.length} | \${r.consoleErrors.length} | \${r.notes.join('; ').slice(0,80)} |\`);
md.push('\\n## 详细 (FAIL/WARN)\\n');
for(const r of all.filter(x=>x.status!=='PASS')){
  md.push(\`### \${r.scenario} (\${r.status})\`);
  if(r.consoleErrors.length) md.push('- console:\\n'+r.consoleErrors.slice(0,5).map(e=>'  - '+e).join('\\n'));
  if(r.http5xx.length) md.push('- 5xx:\\n'+r.http5xx.slice(0,5).map(e=>'  - '+e).join('\\n'));
  if(r.http4xx.length) md.push('- 4xx:\\n'+r.http4xx.slice(0,8).map(e=>'  - '+e).join('\\n'));
  if(r.notes.length) md.push('- notes:\\n'+r.notes.slice(0,8).map(e=>'  - '+e).join('\\n'));
}
fs.writeFileSync('$OUT', md.join('\\n'));
console.log('merged: $OUT', 'PASS='+pass, 'WARN='+warn, 'FAIL='+fail, 'tabsClicked='+tabsTotal);
"
