const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const gsd = 'C:\\Users\\nhdinh\\.claude\\gsd-core\\bin\\gsd-tools.cjs';
const root = '.planning/phases';
const dirs = fs.readdirSync(root).filter(d => fs.statSync(path.join(root, d)).isDirectory()).sort();
const results = [];
for (const dir of dirs) {
    const files = fs.readdirSync(path.join(root, dir)).filter(f => f.endsWith('-VALIDATION.md'));
    if (files.length === 0) {
        results.push({ phase_dir: dir, validation: 'missing' });
        continue;
    }
    for (const f of files) {
        const p = path.join(root, dir, f);
        try {
            const cmd = `node "${gsd}" query frontmatter get "${p}" --raw`;
            const out = execSync(cmd, { encoding: 'utf8' });
            const fm = JSON.parse(out);
            results.push({ phase_dir: dir, file: f, nyquist_compliant: fm.nyquist_compliant, wave_0_complete: fm.wave_0_complete, status: fm.status });
        } catch (e) {
            results.push({ phase_dir: dir, file: f, error: String(e.message).split('\n')[0] });
        }
    }
}
const outPath = '.planning/v0.10.0-nyquist-aggregate.json';
fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
console.log('wrote', outPath, 'with', results.length, 'entries');
