# Frontend security update

This candidate replaces Next.js 16.3.3 with 16.4.0 and moves the Tailwind build
pipeline from version 3 to 4.3.3. The old dependency tree included
GHSA-vcvr-r3jv-pc5j (Next.js) and the unpatched braces chain described in
GHSA-vfj7-8cjw-p6xm. Qualification requires the regenerated lockfile and a fresh
audit; this note is not an evergreen claim of zero vulnerabilities.

The dedicated @tailwindcss/postcss plugin replaces the old Tailwind/autoprefixer
PostCSS configuration. The existing custom color and shadow theme is explicitly
loaded through @config. Existing outline-none controls become outline-hidden
to preserve their former forced-colors focus behavior.

Next's generated next-env.d.ts is no longer tracked. The typecheck script runs
next typegen before tsc --noEmit so a clean checkout still receives all required
type declarations. This avoids false source-drift failures when dev and build
regenerate different declaration imports; TypeScript checks remain mandatory.

The Tailwind 4 browser baseline is Safari 16.4+, Chrome 111+, and Firefox 128+.
Older browsers are outside this candidate's documented UI support. This update
does not add remote shell access, automatic remediation, or action permissions.
The separate resolution-coverage gate remains in force; dependency and
current-slice checks do not certify future remediation families.

Sources:
- https://github.com/advisories/GHSA-vcvr-r3jv-pc5j
- https://github.com/advisories/GHSA-vfj7-8cjw-p6xm
- https://github.com/vercel/next.js/releases/tag/v16.4.0
- https://tailwindcss.com/docs/upgrade-guide
- https://nextjs.org/docs/app/api-reference/config/typescript
