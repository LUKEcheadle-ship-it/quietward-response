"""Apply the reviewed frontend migration before freezing the next candidate.

The caller regenerates the lockfile and requires a clean npm security audit.
No action policy, authentication, backend, or release threshold is changed.
"""
from pathlib import Path
import json
import sys

root = Path(sys.argv[1]).resolve()
front = root / "frontend"
package_path = front / "package.json"
package = json.loads(package_path.read_text(encoding="utf-8"))
assert package["dependencies"]["next"] == "16.3.3"
assert package["devDependencies"]["tailwindcss"] == "^3.4.17"
package["dependencies"]["next"] = "16.4.0"
package["devDependencies"]["tailwindcss"] = "4.3.3"
package["devDependencies"]["@tailwindcss/postcss"] = "4.3.3"
package["devDependencies"].pop("autoprefixer", None)
package_path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
(front / "postcss.config.mjs").write_text('export default {\n  plugins: {\n    "@tailwindcss/postcss": {}\n  }\n};\n', encoding="utf-8")
css_path = front / "src/app/globals.css"
css = css_path.read_text(encoding="utf-8")
old = "@tailwind base;\n@tailwind components;\n@tailwind utilities;"
assert css.count(old) == 1
css = css.replace(old, '@import "tailwindcss";\n@config "../../tailwind.config.ts";')
css_path.write_text(css, encoding="utf-8")
for path in front.rglob("*.tsx"):
    if "node_modules" in path.parts or ".next" in path.parts:
        continue
    text = path.read_text(encoding="utf-8")
    if "outline-none" in text:
        path.write_text(text.replace("outline-none", "outline-hidden"), encoding="utf-8")
notes = root / "docs/FRONTEND_SECURITY_UPDATE.md"
notes.write_text('''# Frontend security update

This candidate replaces the Next.js 16.3.3 dependency with 16.4.0 and moves the
Tailwind build pipeline from version 3 to 4.3.3. The old dependency tree included
GHSA-vcvr-r3jv-pc5j (Next.js) and the unpatched braces chain described in
GHSA-vfj7-8cjw-p6xm. Dependency qualification must use the regenerated lockfile
and a fresh audit; this note is not an evergreen claim of zero vulnerabilities.

The dedicated @tailwindcss/postcss plugin replaces the old Tailwind/autoprefixer
PostCSS configuration. The existing custom color and shadow theme remains loaded
explicitly through @config. Existing outline-none controls become outline-hidden
to preserve their former forced-colors focus behavior.

The Tailwind 4 browser baseline is Safari 16.4+, Chrome 111+, and Firefox 128+.
Older browsers are outside this candidate's documented UI support. This update
does not introduce remote shell access, automatic remediation, or new action
permissions. The separate guided-response resolution-coverage gate remains in
force; dependency and current-slice checks do not certify future remediation.

Sources:
- https://github.com/advisories/GHSA-vcvr-r3jv-pc5j
- https://github.com/advisories/GHSA-vfj7-8cjw-p6xm
- https://github.com/vercel/next.js/releases/tag/v16.4.0
- https://tailwindcss.com/docs/upgrade-guide
''', encoding="utf-8")
print("Frontend migration prepared; lock regeneration and all qualification remain required.")
