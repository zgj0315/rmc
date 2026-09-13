import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const head = readFileSync('_shell_head.txt', 'utf8');

const APP_ICON = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="1.75" y="3.25" width="12.5" height="8" rx="1.25" stroke="#0067c0" stroke-width="1.3"/><path d="M5.5 13.6h5" stroke="#0067c0" stroke-width="1.3" stroke-linecap="round"/><path d="M4.4 7.3h1.9l1-1.7 1.4 3 .9-1.3h1.9" stroke="#0067c0" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function shell(active, body) {
  const tab = (name) =>
    `<div class="tab${name === active ? ' tab-on' : ''}">${name}</div>`;
  return `<div class="win">
  <div class="tbar">
    ${APP_ICON}
    <span style="font-size: 12px; color: #3b3b3b">Remote Maintenance</span>
    <span style="flex-grow: 1"></span>
    <div style="display: flex">
      <div class="wbtn"><svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 6h8" stroke="#4a4a4a" stroke-width="1.1"/></svg></div>
      <div class="wbtn"><svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2.6 2.6l6.8 6.8M9.4 2.6l-6.8 6.8" stroke="#4a4a4a" stroke-width="1.1"/></svg></div>
    </div>
  </div>
  <div class="tabs">
    ${tab('维护')}
    ${tab('诊断')}
    ${tab('日志')}
  </div>
  <div class="body">
${body}
  </div>
</div>`;
}

const targets = [
  ['Main', '维护'],
  ['Preflight', '维护'],
  ['Connected', '维护'],
  ['Degraded', '维护'],
  ['Backoff', '维护'],
  ['AuthFailed', '维护'],
  ['Diagnostics', '诊断'],
  ['Logs', '日志'],
];

for (const [name, active] of targets) {
  const f = `body-${name}.html`;
  if (!existsSync(f)) { console.error(`missing ${f}`); continue; }
  const out = `${head}${shell(active, readFileSync(f, 'utf8').trimEnd())}
</x-dc>
</body>
</html>
`;
  writeFileSync(`${name}.dc.html`, out);
  console.log(`${name}.dc.html  ${out.length} bytes`);
}
