# Static sites and single-page applications against agensio's redirect and header design (2026-10-13)

This note checks two proposals against what static sites and single-page applications (SPAs)
actually ask of a web server: `docs/redirects.md` (sections 1 to 8: `http`, `canonical`, `hsts`,
`[[site.redirect]]`) and `docs/headers.md` (sections 1 to 4: `[[site.response_headers]]`, the
refused names, the baseline per preset). Three kinds of evidence:

1. the documentation of the static hosting platforms whose rule files these sites ship
   (section 2);
2. the deployment documentation of the static site generators and SPA frameworks (section 3);
3. the rule files of real public repositories, counted (section 4).

Each recurring need is then classified against the design (section 5), followed by a summary
table (section 6) and the design changes the evidence supports (section 7).

## Method

- Both design documents were read in full, and `docs/configuration.md` for what exists today (1
  static site, 5 presets, 6 locations, 6b `refuse`, 15 `rules`). agensio's own behaviour, where a
  classification depends on it, was read in the working tree of 2026-10-13:
  - `try_files` accepts only `$uri`, `$uri/`, `=403`, `=404` and a `/path` fallback
    (`src/config.cpp` `parse_try_files`); there is no `$uri.html`;
  - a directory requested without its slash gets a 301 to the slash form
    (`src/handlers/static.cpp` `plain_lookup`, `try_files_lookup`);
  - error answers are agensio's built-in pages (`src/response.cpp` `error_page`); no key serves a
    file of the site as the 404 page;
  - the MIME table is compiled in (`src/mime.cpp`, default `application/octet-stream`) and no
    configuration key changes it (`docs/keys.md` has none; CLAUDE.md's "overridable from config"
    is not what the code does);
  - `content_hashed()` (`src/handlers/static.cpp`), used by the Django preset's `/static/`,
    recognises only `name.HEX.ext` with 8 to 64 lowercase hex digits;
  - on a managed site, `rules.front_controller` is refused unless the preset runs PHP
    (`src/control/sites.cpp`), and `rules.cache` renders `Cache-Control: public, max-age=N` with
    no way to add `immutable`.
- Platform documentation was read on 2026-10-13 on the platforms' own sites (Netlify, Cloudflare,
  Vercel, Render, AWS through their published Markdown pages; GitHub, Firebase and Azure through
  their HTML pages). Quotes are verbatim.
- Generator and framework documentation was read on 2026-10-13 on each project's own site or
  repository. Quotes are verbatim.
- Real files came from Sourcegraph's public code search (`sourcegraph.com/.api/search/stream`,
  no account, forks and archived repositories excluded by its defaults), on 2026-10-13:

| corpus | how it was taken | files | rules |
|---|---|---|---|
| `_redirects` (Netlify and Cloudflare Pages share the name and the syntax) | every line of every indexed file: `file:(^\|/)_redirects$ patterntype:regexp \S count:all` | 2,585 files in 2,143 repositories; 2,512 with at least one rule | 47,025 rules (26,320 of them in the 17 files above 500 rules) |
| `_headers` (both platforms) | the same query on `_headers` | 617 files returned (the index lists at least 1,907; the line search stopped at its match limit), 610 with a rule | 1,947 path blocks |
| `netlify.toml` | the lines of `[[redirects]]` and `[[headers]]` tables (`from`, `to`, `status`, `force`, `conditions`, `query`, `for`, field lines) | 1,913 files; 680 with redirects, 303 with headers | 3,478 redirects, 609 header blocks |
| `vercel.json` | a random 1,200 of the 6,684 listed, fetched raw from GitHub at the indexed commit and parsed as JSON | 1,198 parsed; 638 with any of `rewrites`, `redirects`, `headers`, `routes`, `cleanUrls`, `trailingSlash` | |
| `firebase.json` with `"hosting"` | a random 700 of the 1,370 listed, fetched raw | 653 parsed, 646 with a hosting section | |
| `staticwebapp.config.json` (Azure) | all 283 listed, fetched raw | 269 parsed | |
| AWS Amplify `customHttp.yml` / `amplify.yml` with `customHeaders` | all 12 listed | 12 | |

  Caveats:
  - Sourcegraph indexes a subset of GitHub (popular and recently active repositories), and its
    listings carry `shard-match-limit`, so every count is a lower bound and a sample, not the
    population.
  - A `_redirects` file does not say whether it serves Netlify or Cloudflare Pages.
  - Templates and copied examples weigh more than once. The Azure corpus is dominated by Uno
    Platform WebAssembly samples. Some `_redirects` files are Liquid or Hugo templates, whose
    template lines were not counted as rules.
  - Classification is by pattern, by ad hoc scripts. A rule can count in several classes (a
    domain-level rule with a splat counts as both).
  - Percentages in sections 4 to 6 are shares of the files of that corpus that hold at least one
    rule of the kind compared.
- Example rules are linked to the file at the indexed commit, so the line quoted is the line that
  was counted.

### Classification

The marks are those of the sibling note `php_apps.md`:

| mark | meaning |
|---|---|
| **E** (EXPRESSIBLE) | a setting of the two designs expresses it; the TOML is given |
| **E≈** | expressible, with a stated difference that does not change what the site needs |
| **N** (NEEDS A CHANGE) | the designs lack something; the smallest change that would cover it is named |
| **O** (NOT OFFERED ON PURPOSE) | the designs exclude it, with the reason, and what the site owner does instead |
| **X** (NOT A REDIRECT/HEADER RULE) | it belongs to another agensio feature, which is named; **X-gap** where no agensio feature covers it today |

## 1. What these sites are, and what they ask

A static site or an SPA is a directory of files that a build wrote. The server never runs code
for it. Everything a site needs beyond "serve the file at this path" is written by its author or
its generator into one of the platform files above. The same few needs recur, and they fall into
two groups.

- **Routing**:
  - the SPA fallback (an unknown path gets `/index.html` with `200`);
  - clean URLs (`/about` served from `about.html`) and a trailing-slash policy;
  - a custom `404.html` answered with status 404;
  - migration redirects, exact or by section;
  - domain moves and `www`;
  - proxying `/api/` to a backend;
  - rarely, conditions on language or country.
- **Headers**:
  - a year-long `immutable` lifetime on the build's fingerprinted assets, and `no-cache` (or
    `max-age=0, must-revalidate`) on the HTML and the service worker;
  - the security fields on every answer;
  - CORS on fonts and data;
  - `Cross-Origin-Opener-Policy` and `Cross-Origin-Embedder-Policy` for WebAssembly threads;
  - a `Content-Type` for files whose name does not tell it.

## 2. The platforms (documentation, 2026-10-13)

### 2.1 Netlify `_redirects`, `[[redirects]]`, `_headers`, `[[headers]]`

Sources: https://docs.netlify.com/manage/routing/redirects/overview/ ,
https://docs.netlify.com/manage/routing/redirects/redirect-options/ ,
https://docs.netlify.com/manage/routing/redirects/rewrites-proxies/ ,
https://docs.netlify.com/manage/routing/headers/ ,
https://docs.netlify.com/build/caching/caching-overview/

- **Syntax.** One rule per line, `from to [status][!] [conditions]`.
  - Quote: "Paths are case-sensitive and special characters in paths must be url-encoded."
  - The default status: "If left unspecified, the default is `301`."
  - The documented codes are 301, 302, 404 and 200. Quote: "Use this status code instead of
    `307`, which is currently unsupported." 410 is not documented (unverified).
- **Order.** Quote: "The redirects engine will process the first matching rule it finds, reading
  from top to bottom."
- **Shadowing.** Quote: "By default, you can't shadow a URL that actually exists within the site."
  A rule fires over an existing file only with `!` (`force = true`).
- **Trailing slash.**
  - Quote: "Netlify will match paths to rules regardless of whether or not they contain a
    trailing slash."
  - Quote: "You cannot use a redirect rule to add or remove a trailing slash."
- **Splats and placeholders.**
  - `/news/*  /blog/:splat`.
  - `/news/:month/:date/:year/:slug  /blog/:year/:month/:date/:slug`.
  - Quote: "It's not possible to use an asterisk as a wildcard in the middle of a path, for
    example `/jobs/*.html`. You can only use asterisks at the end of the path segment".
  - Whether `:splat` may sit inside `to` (`/:splat.html`) is not stated (unverified); real files
    do it (section 4.1).
- **Query parameters.** Kept on 200, 301 and 302. A rule may match and capture them:
  `/store id=:id  /blog/:id  301`, which "matches only URLs that have only the `id` parameter and
  no others."
- **Conditions.**
  - `Country=au,nz`, `Language=he`. Quote: Language matches "against the first language reported
    by the browser in the `Accept-Language` header regardless of quality value weighting".
  - `Role=` (Netlify Identity or a JWT) and `Cookie=`.
- **Rewrites, proxies, the SPA.**
  - Quote: "When you assign an HTTP status code of `200` to a redirect rule, it becomes a
    **rewrite**."
  - Proxy: `/api/*  https://api.example.com/:splat  200`.
  - The section titled "History `pushState` and single-page apps": `/*    /index.html   200`.
    Quote: "this is typically the last rule listed."
- **404.**
  - Quote: "If you add a `404.html` page to your site, it will be picked up and displayed
    automatically for any failed paths."
  - Per-language versions: `/en/* /en/404.html 404`.
- **Pretty URLs** (on by default). Quote: it "forwards paths like `/about` to `/about/`… and
  rewrites paths like `/about.html` to `/about/`."
- **Headers.**
  - Quote: "Wildcards (`*`) can be used at any place inside of a path segment", so `/*.js` is a
    valid path.
  - Values of a field listed twice are concatenated. How two different matching rules combine is
    not documented (unverified).
  - `Location`, `Content-Length`, `Content-Encoding`, `Set-Cookie` and others "are typically
    ignored".
  - `Basic-Auth` (paid plans) is set in `_headers`.
- **Defaults.** Static files get `Cache-Control: public, max-age=0, must-revalidate`, with a
  year-long CDN lifetime in `Netlify-CDN-Cache-Control`.

### 2.2 Cloudflare Pages and Workers static assets

Sources: https://developers.cloudflare.com/pages/configuration/redirects/ ,
https://developers.cloudflare.com/pages/configuration/headers/ ,
https://developers.cloudflare.com/pages/configuration/serving-pages/ ,
https://developers.cloudflare.com/workers/static-assets/routing/advanced/html-handling/ ,
https://developers.cloudflare.com/workers/static-assets/routing/single-page-application/

- **The same file with different meanings.**
  - The default status is 302: "`code` `number` (default: 302)". The same line without a status
    is 301 on Netlify (2.1).
  - Quote: "Redirects are always followed, regardless of whether or not an asset matches the
    incoming request." There is no shadowing and no `!`.
  - Quote: "If there are multiple redirects for the same `source` path, the top-most redirect is
    applied."
- **Not supported** (its own table): rewrites with other status codes (`/blog/* /blog/404.html
  404`), query parameters, domain-level redirects, country and language, cookies, proxying to
  another domain.
- **Limits.**
  - Quote: "limited to 2,000 static redirects and 100 dynamic redirects, for a combined total of
    2,100 redirects. Each redirect declaration has a 1,000-character limit."
  - Bulk Redirects beyond that.
  - At most 100 header rules.
- **Splats.** Quote: "a splat (asterisk, `*`) will greedily match all characters. You may only
  include a single splat in the URL." The destination "Can include fragments, query strings,
  splats, and placeholders."
- **Headers combine.**
  - Quote: "An incoming request which matches multiple rules' URL patterns will inherit all
    rules' headers."
  - Quote: "If a header is applied twice in the `_headers` file, the values are joined with a
    comma separator."
  - A field is removed with `! Field`, documented with `/*.jpg` and `! Content-Security-Policy`.
- **Defaults on every answer.**
  - `Access-Control-Allow-Origin: *`, `Referrer-Policy: strict-origin-when-cross-origin`,
    `X-Content-Type-Options: nosniff`.
  - `Cache-Control: public, max-age=0, must-revalidate` when cacheable.
  - `X-Robots-Tag: noindex` on preview URLs.
- **Clean URLs and 404.**
  - Quote: "Pages will also redirect HTML pages to their extension-less counterparts: for
    instance, `/contact.html` will be redirected to `/contact`, and `/about/index.html` will be
    redirected to `/about/`."
  - The nearest `404.html` up the tree is the 404 page.
  - Quote: "If your project does not include a top-level `404.html` file, Pages assumes that you
    are deploying a single-page application".
- **Workers** have the same files, plus:
  - `html_handling`: `"auto-trailing-slash"` (default), `"force-trailing-slash"`,
    `"drop-trailing-slash"`, `"none"`. In auto mode, `/file.html` gets `307 to /file` and
    `/folder` gets `307 to /folder/`.
  - `not_found_handling`: `"single-page-application"` serves `/index.html` with `200`;
    `"404-page"` serves "the nearest `404.html` file with a `404 Not Found` status".

### 2.3 Vercel `vercel.json`

Sources: https://vercel.com/docs/project-configuration/vercel-json ,
https://vercel.com/docs/routing/redirects/configuration-redirects ,
https://vercel.com/docs/routing/redirects/bulk-redirects , https://vercel.com/docs/routing/rewrites ,
https://vercel.com/docs/limits , https://vercel.com/kb/guide/custom-404-page

- **Redirects.** `source`, `destination`, `permanent` ("When `true`, the status code is 308. When
  `false` the status code is 307"), `statusCode`, `has`, `missing`.
  - Patterns: `"/blog/:path*"` → `"/news/:path*"`, `"/(.*)"`, `"/:path((?!uk/).*)"`.
  - Quote: "URLs are case-sensitive".
- **Conditions.** `has`/`missing` with type "Must be either `header`, `cookie`, `host`, or
  `query`".
- **Rewrites.**
  - The SPA: `{ "rewrites": [{ "source": "/(.*)", "destination": "/index.html" }] }`.
  - Quote: "precedence is given to the filesystem prior to rewrites being applied".
- **`cleanUrls`.** Quote: "all HTML files and Vercel functions will have their extension removed.
  When visiting a path that ends with the extension, a 308 response will redirect the client to
  the extensionless path."
- **`trailingSlash`.**
  - `false`: "`/about/` path will redirect to `/about`".
  - `true`: "/about will redirect to /about/… paths with a file extension will not redirect".
  - Unset: "both `/about` and `/about/` will serve the same content without redirecting."
- **Limits.**
  - Quote: "Number of redirects in the array | 2,048". Each rewrite, redirect or header rule is a
    route, 2,048 per deployment.
  - Bulk redirects (Pro and Enterprise): up to 1,000,000; quote: they "do not support wildcard or
    header matching"; `preserveQueryParams` defaults to false.
- **404.** Quote: "Emit a `404.html` file to your Output Directory and it will be served as the 404
  page".
- **HSTS by default.** Quote: "The default value is `strict-transport-security: max-age=63072000`".

### 2.4 GitHub Pages

Sources:
https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-custom-404-page-for-your-github-pages-site ,
https://pages.github.com/versions.json

- The documentation has no section on custom headers or server-side redirects. The limitation
  shows by absence; there is no sentence to quote.
- Platform redirects that do exist: HTTPS enforcement, and apex to `www` (quote: "GitHub Pages
  will automatically create redirects between the domains").
- A custom 404 is `404.html` or `404.md`. A 404 status was observed (`HTTP/2 404`), not
  documented.
- `jekyll-redirect-from` 0.16.0 is in the supported plugin list (versions.json). It writes HTML
  pages with a meta refresh. That comes from the plugin's README, not from GitHub's docs.
- The SPA trick (a `404.html` that reloads the app) is a community pattern, not in GitHub's docs
  (unverified there).
- Observed on pages.github.com: `cache-control: max-age=600`.

### 2.5 Render static sites

Sources: https://render.com/docs/redirects-rewrites , https://render.com/docs/static-site-headers

- Every redirect is a 301. Quote: "Render does not apply redirect or rewrite rules to a path if a
  resource exists at that path."
- `*` and `:name` work; the SPA is `/*` → `/index.html` (rewrite).
- Header paths:
  - `/*.css` "Matches `/tokens.css`… but not `/assets/theme.css`";
  - `/**/*.css` "Matches `/assets/theme.css` but not `/tokens.css`".

### 2.6 Firebase Hosting `firebase.json`

Sources: https://firebase.google.com/docs/hosting/full-config ,
https://firebase.google.com/docs/hosting/i18n-rewrites

- **Priority**, verbatim:
  1. "Reserved namespaces that begin with a `/__/*` path segment"
  2. "Configured redirects"
  3. "Exact-match static content"
  4. "Configured rewrites"
  5. "Custom 404 page"
  6. "Default 404 page"
- **Redirects.**
  - Globs or RE2, 301 or 302.
  - Captures: `"source": "/blog/:post*"` → `"https://blog.myapp.com/:post"`.
- **Rewrites.**
  - The SPA: `"source": "**", "destination": "/index.html"`.
  - Quote: a rewrite applies "if a file or directory does not exist".
- **Headers.**
  - By glob: `"source": "**/*.@(jpg|jpeg|gif|png)"` with `max-age=7200`, commented "Overrides the
    default 1 hour browser cache".
  - Quote: "Matching rules are applied in the order they are defined."
- **`cleanUrls`.** Quote: "If an `.html` extension is added in the request, Hosting performs a
  `301` redirect to the same path but eliminates the `.html` extension."
- **`trailingSlash`.** `true` adds the slash, `false` removes it. Unset: "Hosting only uses
  trailing slashes for directory index files".
- **i18n.** `"i18n": {"root": "/localized-files"}` serves folders by country (from the IP) and
  language (from `Accept-Language`).

### 2.7 Azure Static Web Apps `staticwebapp.config.json`

Source: https://learn.microsoft.com/en-us/azure/static-web-apps/configuration

- **Routes.** Quote: "Rules are evaluated in the order as they appear in the `routes` array. Rule
  evaluation stops at the first match… Each request can match at most one rule."
  - The default redirect status is 302.
  - Wildcards only at the end; extension filters `"/images/thumbnails/*.{png,jpg,gif}"`.
  - `allowedRoles`.
- **`navigationFallback`.** `{"rewrite": "/index.html", "exclude": ["/images/*.{png,jpg,gif}",
  "/css/*"]}`.
- **`responseOverrides`.** `"404": {"rewrite": "/404.html"}`; `"401": {"statusCode": 302,
  "redirect": "/login"}`.
- **`globalHeaders`.** Quote: "applied to each response, unless overridden by a route header
  rule".
- **`mimeTypes`.** `{".json": "text/json"}`.
- **`trailingSlash`.** `"always"`, `"never"` or `"auto"`, each with 301s. Auto: `/privacy.html` →
  `/privacy`, `/about` → `/about/`.

### 2.8 AWS Amplify Hosting

Sources: https://docs.aws.amazon.com/amplify/latest/userguide/redirect-rewrite-examples.html ,
https://docs.aws.amazon.com/amplify/latest/userguide/custom-header-YAML-format.html

- **Rules.** `{"source", "target", "status", "condition"}`, applied top-down.
  - Statuses: `200`, `301`, `302`, `404`, `404-200`.
  - Country: `"condition": "<US>"`.
  - Placeholders `<id>`; one `<*>`, only at the end.
- **The SPA**, verbatim from the current docs (note `woff2` and `webp`):
  `"source": "</^[^.]+$|\.(?!(css|gif|ico|jpg|js|png|txt|svg|woff|woff2|ttf|map|json|webp)$)([^.]+$)/>", "status": "200", "target": "/index.html"`.
  It sends a path without an extension, or with an extension outside the list, to the shell.
- **Clean URLs.** `/about` → `/about.html`, else `/about/index.html`. Quote: "Amplify
  automatically creates clean URLs by adding a trailing slash when required."
- **Headers.** `customHttp.yml` with `pattern: '**'`. Quote: "Amplify only applies Cache-Control
  custom headers for successful responses with a `200 OK` status code."

### 2.9 What the platforms agree on

| behaviour | Netlify | Cloudflare Pages | Vercel | Firebase | Azure SWA | Amplify | Render | GitHub Pages |
|---|---|---|---|---|---|---|---|---|
| rule order | first match | first match | array order | first match | first match | top-down | first match | (none) |
| a redirect over an existing file | only with `!` | always | (redirects before the filesystem; unverified) | always | (unverified) | (unverified) | never | (none) |
| default redirect status | 301 | 302 | 308 | `type` 301 or 302 | 302 | `status` given per rule | 301 only | (none) |
| SPA fallback | `/* /index.html 200` | automatic without `404.html` | rewrite `/(.*)` | rewrite `**` | `navigationFallback` | regex rule | rewrite `/*` | (none) |
| custom 404 page | `404.html`, automatic | nearest `404.html` | `404.html` | `404.html` | `responseOverrides` | rule `404` | (unverified) | `404.html` |
| `.html` dropped from the URL | Pretty URLs (default) | automatic | `cleanUrls` (308) | `cleanUrls` (301) | `trailingSlash: "auto"` | automatic | (unverified) | serves `/about` from `about.html` (VitePress's docs say so; unverified in GitHub's) |
| header rule by extension | `/*.js` | `/*.jpg` | regex | `**/*.@(js\|css)` | `/*.{png,jpg}` | `*.json` | `/**/*.css` | (none) |
| several header rules on one answer | (unverified) | all, values comma-joined | (unverified) | in order | route rule over global | (unverified) | (unverified) | (none) |
| default `Cache-Control` on files | `public, max-age=0, must-revalidate` | the same | (unverified) | one hour (its docs' comment) | (unverified) | (unverified) | (unverified) | `max-age=600` (observed) |

Every platform orders rules by position. agensio's "the most specific rule decides" (redirects.md
5.1, headers.md 2.2) is the exception, which the design already says the agent's texts must
state.

## 3. The generators and frameworks (documentation, 2026-10-13)

### 3.0 Sources

The documentation was read from each project's documentation source repository, sparse-cloned on
2026-10-13. These are the files the live sites are built from:

| project | repository and commit |
|---|---|
| Hugo | gohugoio/hugoDocs b732eba |
| Jekyll | jekyll/jekyll docs 541d8b2 |
| Eleventy | 11ty/11ty-website 8c37643 |
| Astro | withastro/docs f29faa4 |
| Docusaurus | facebook/docusaurus c245217 |
| VitePress | vuejs/vitepress 2287aa9 |
| MkDocs | mkdocs/mkdocs 2862536 |
| Material for MkDocs | squidfunk/mkdocs-material 6d3dc57 |
| Next.js | vercel/next.js e7feae7d |
| Nuxt | nuxt/nuxt a433430 |
| SvelteKit | sveltejs/kit 7063654 |
| Angular | angular/angular adev b1375e4 |
| Vite | vitejs/vite dce9fe6 |
| React Router | remix-run/react-router dee9ad2 |
| Vue Router | vuejs/router 0729ce7 |
| Gatsby | gatsbyjs/gatsby 8999a2e |
| gatsby-plugin-netlify | netlify/gatsby-plugin-netlify 2afa677 |
| Hexo | hexojs/site d1e2672 |
| jekyll-redirect-from | 839a798 |
| mkdocs-redirects | d0e3d52 |

Each item below gives the published URL. Asset names marked "live" are what the project's own
site served on 2026-10-13. Version notes:
- SvelteKit's live docs describe SvelteKit 3.
- Angular's current deployment guide no longer carries per-server snippets; the older ones are
  quoted from the v17 guide and marked so.
- Material for MkDocs is in maintenance mode since 9.7.0.

### 3.1 What each asks of the server

**SPA fallback (a rewrite with 200, never a redirect)**
- **Angular**, https://angular.dev/tools/cli/deployment: "you must configure the server to return
  the application's host page (`index.html`) when asked for a file that it does not have". The v17
  guide's nginx line was `try_files $uri $uri/ /index.html;`.
- **Vue Router**, https://router.vuejs.org/guide/essentials/history-mode.html: "If the URL doesn't
  match any static assets, it should serve the same `index.html` page that your app lives in".
  - nginx: `location / { try_files $uri $uri/ /index.html; }`.
  - Netlify: `/* /index.html 200`.
  - Azure: `"navigationFallback": {"rewrite": "/index.html", "exclude": ["/assets/*",
    "/favicons/*"]}`.
  - Its caveat: "Your server will no longer report 404 errors".
- **React Router**:
  - https://reactrouter.com/how-to/spa: `/*    /index.html   200`.
  - With pre-rendering, https://reactrouter.com/how-to/pre-rendering: the fallback is
    `build/client/__spa-fallback.html` when `/` is prerendered, e.g. `/*    /__spa-fallback.html
    200`.
- **Vite**, https://vite.dev/guide/static-deploy: the Firebase rewrite only.
- **Nuxt**, https://nuxt.com/docs/getting-started/deployment#static-hosting. Quote: "`200.html` is
  the single-page app fallback… `404.html` is the not-found fallback. Configure your host to serve
  it for routes that should keep a 404 status."
- **SvelteKit**, https://svelte.dev/docs/kit/adapter-static: `fallback` "is commonly `200.html`… You
  should avoid `index.html` where possible to avoid conflicting with a prerendered homepage."
- **Gatsby**, client-only routes,
  https://www.gatsbyjs.com/docs/how-to/routing/client-only-routes-and-user-authentication/:
  `/app/*` is served from `/app/[...]/index.html`. Quote: "the response code should be a **200**
  (an OK) and not a **301** (a redirect)."

**`/x` served from `x.html`, without a redirect**
- **VitePress**, https://vitepress.dev/guide/routing#generating-clean-urls: "your server must be
  able to serve `/foo.html` when visiting `/foo` **without a redirect**." Its nginx recipe
  (https://vitepress.dev/guide/deploy#nginx) is `try_files $uri $uri.html $uri/index.html =404;`.
- **Next.js static export**, https://nextjs.org/docs/app/guides/static-exports: the default output
  is `/out/blog/post-1.html`. Its nginx recipe:
  - `try_files $uri $uri.html $uri/ =404;`
  - "This is necessary when `trailingSlash: false`": `rewrite ^/blog/(.*)$ /blog/$1.html break;`.
- **SvelteKit**, adapter-static: "If your host does not render `/a.html` upon receiving a request
  for `/a` then you will need to set `trailingSlash: 'always'`". The default `'never'` writes
  `about.html`.
- **Docusaurus**, https://docusaurus.io/docs/api/docusaurus-config#trailingSlash. With `false`:
  "remove trailing slashes from URLs/links, and emit `/docs/myDoc.html`".
- **Astro**, `build.format: 'file'`: "`src/pages/about.astro`… build the file `/about.html`".
- **Jekyll**:
  - Extensionless permalinks (`permalink: /about`) write `about.html` (`lib/jekyll/page.rb`).
  - jekyll-redirect-from turns `"/foo"` into `foo.html` (its spec).
- **Eleventy**, opt-in, https://www.11ty.dev/docs/permalinks/#trailing-slashes: the `.html` recipe
  "works on GitHub Pages, Netlify, Cloudflare Pages, Render, and Azure Static Web Apps".
- **Hexo**, `pretty_urls.trailing_html: false` (https://hexo.io/docs/configuration#URL). That the
  server must map `/x` to `x.html` is an inference.

**`/x` served from `x/index.html`, without a 301**
- **Docusaurus default**: it keeps URLs untouched and emits `/docs/myDoc/index.html`. Quote: "Some
  hosting providers differentiate between them using the presence of a trailing slash, and may or
  may not tolerate the other."
- **Nuxt** (Nitro `autoSubfolderIndex: true`, https://nitro.build/config#prerender): `/about`
  becomes `about/index.html`.
- **React Router pre-rendering**: `build/client/blog/index.html` for `/blog`.
- **Gatsby `trailingSlash: "never"`**: `/about` is served and `/about/` redirects.
- **Astro's own Docker recipe** (https://docs.astro.build/en/recipes/docker/):
  `try_files $uri $uri/index.html =404;`.
- **Gatsby's default `always`** asks for the 301 from `/x` to `/x/`, which is what agensio does.

**A `404.html` answered with status 404**
- These document their 404 page:
  - Hugo (https://gohugo.io/templates/404/);
  - Jekyll (https://jekyllrb.com/tutorials/custom-404-page/, `error_page 404 /404.html;` and
    `ErrorDocument 404 /404.html`);
  - Eleventy (https://www.11ty.dev/docs/quicktips/not-found/);
  - Astro (`error_page 404 /404.html;`);
  - Docusaurus;
  - VitePress (`error_page 404 /404.html;`);
  - MkDocs (https://www.mkdocs.org/user-guide/deploying-your-docs/#404-pages);
  - Next.js (`error_page 404 /404.html; location = /404.html { internal; }`);
  - Nuxt (it should "keep a 404 status");
  - Gatsby (https://www.gatsbyjs.com/docs/how-to/adding-common-features/add-404-page/: "you'll
    need to set up a custom rule to serve this file for 404 errors").
- Localised 404 pages:
  - Docusaurus's i18n tutorial: "configuring your host to redirect `/fr/*` to `/fr/404.html`";
  - Hugo writes `404.de.html`.
- Angular, Vue Router and SvelteKit's SPA mode accept soft 404s (status 200).

**Caching of fingerprinted files and of HTML**
- **VitePress**, https://vitepress.dev/guide/deploy#http-cache-headers. Files such as
  `assets/app.4f283b18.js` get `Cache-Control: max-age=31536000,immutable`. Its nginx sets
  `~^/assets/  "public, max-age=31536000, immutable"; default "no-cache";`, plus `nosniff`,
  `SAMEORIGIN` and `strict-origin-when-cross-origin` `always`.
- **Gatsby**, https://www.gatsbyjs.com/docs/how-to/previews-deploys-hosting/caching/:
  - HTML, `page-data/` and `app-data.json`: `public, max-age=0, must-revalidate`;
  - `static/` and the webpack JS and CSS at the root: `public, max-age=31536000, immutable`;
  - the exception: "The only exception to this is the file `/sw.js`, which needs to be
    revalidated upon each load";
  - its Firebase example uses `**/*.@(css|js)`.
- **Vite**, https://vite.dev/guide/build#load-error-handling: "make sure to set `Cache-Control:
  no-cache` on the HTML file, otherwise the old assets will be still referenced."
- **Next.js**, https://nextjs.org/docs/app/guides/cdn-caching: `/_next/static/` "have a 1 year
  `max-age` and `immutable` directive". That is what `next start` sends; an export needs the
  server to.
- **Astro**: the Node adapter sends `public, max-age=31536000, immutable` on `_astro/`.
- **SvelteKit**: adapter-bun does the same for `_app/immutable`.
- **React Router**: its Express example puts `immutable` and `maxAge: "1y"` on `/assets`.
- **Hugo**: the `hugo deploy` example caches `^.+\.(js|css|svg|ttf)$` for a year,
  fingerprinted or not.
- **Version files that must revalidate inside or beside the hashed directories:**
  - Gatsby's `page-data/` and `app-data.json`;
  - SvelteKit's `/_app/version.json` (live, `public, max-age=0, must-revalidate`; unverified in the
    docs);
  - Nuxt's `/_nuxt/builds/latest.json` (live, `public, max-age=1, immutable`). It sits **inside**
    `/_nuxt/`, so a blanket year-long rule on `/_nuxt/` would freeze it. That is an observation,
    not in the docs.

**Hashed file names** (examples, live or from the docs):

| tool | example |
|---|---|
| Vite | `assets/foo-BRBmoGS9.js` (dash, 8 base64url) |
| Astro | `/_astro/page.4AM5fX2K.js` |
| VitePress | `/assets/app.BxDp-eS7.js` |
| Nuxt | `/_nuxt/9QtFQA7H.js` |
| SvelteKit | `_app/immutable/entry/start.BbyJB1oN.js` |
| Angular | `chunk-CTLATUxU.js` at the root of `browser/` |
| Next.js | `/_next/static/immutable/chunks/1m_45crq_rkgw.js` |
| Gatsby | `/app-66f260220c0076326990.js` at the root |
| Docusaurus | `/assets/js/main.2672a8ee.js` |
| Material for MkDocs | `assets/javascripts/bundle.9d1edc04.min.js` |
| Hugo | `/css/styles.min.<64 hex>.css`, beside unhashed files |

Of these, agensio's `content_hashed()` (`name.HEX.ext`, 8 to 64 lowercase hex) recognises only
Docusaurus's and Hugo's.

**Redirects the tools generate**
- Most write HTML pages with a meta refresh, served with 200:
  - Hugo `aliases` (https://gohugo.io/content-management/urls/#aliases): `<meta
    http-equiv="refresh" content="0; url={{ .Permalink }}">` with `rel="canonical"`;
  - jekyll-redirect-from. Quote: "No `.htaccess` file, nginx conf, xml file, or anything else will
    be generated". It also writes `redirects.json`;
  - Docusaurus `@docusaurus/plugin-client-redirects`. Quote: "It is better to use server-side
    redirects whenever possible";
  - Astro `redirects` on static output. Quote: "will produce a client redirect using a `<meta
    http-equiv="refresh">` tag and does not support status codes". Dynamic `'/blog/[...slug]':
    '/articles/[...slug]'` is allowed "as long as both the new and old routes contain the same
    parameters";
  - mkdocs-redirects;
  - hexo-generator-alias;
  - SvelteKit's prerendered `redirect()`.
- Server-side files are opt-in:
  - Hugo's documented recipe writes a `_redirects` output format
    (`{{- printf "%s %s 301\n" . $p.RelPermalink -}}`);
  - Astro's adapters write the host's file;
  - gatsby-plugin-netlify writes `_redirects` and `_headers` (302 by default, 301 when
    `isPermanent`). Gatsby's `createRedirect` has `conditions: { language, country }`.
- Next.js export lists "Rewrites, Redirects, Headers" under unsupported features.

**Security headers and CSP**
- **Gatsby's defaults** (core adapter constants and gatsby-plugin-netlify `SECURITY_HEADERS`) on
  `/*`: `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `X-Content-Type-Options:
  nosniff`, `Referrer-Policy: same-origin`.
- **CSP in a `<meta>` tag** (Astro `security.csp`, SvelteKit prerendered pages, Angular `autoCsp`)
  cannot carry `frame-ancestors`, `report-uri` or `sandbox`. Angular
  (https://angular.dev/best-practices/security): "Send these directives in a
  `Content-Security-Policy` HTTP header… omit both `script-src` and `default-src` from the
  header".
- **Next.js export** (https://nextjs.org/docs/app/guides/content-security-policy): "Static pages
  are generated at build time… so no nonce can be injected."
- None of the sixteen tools' documentation asks for `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Embedder-Policy` or `Service-Worker-Allowed`.

**Language by `Accept-Language` at the server**
- **Angular**, https://angular.dev/guide/i18n/deploy. Quote: "Users are redirected to the preferred
  language defined in the browser using the `Accept-Language` HTTP header". Its nginx uses `map
  $http_accept_language` and `rewrite ^/$ /$accept_language permanent;`, a 301 that depends on a
  request header, without `Vary`.
- **Eleventy**, https://www.11ty.dev/docs/i18n/. Quote: "Requires _some_ server configuration to
  handle the `Accept-Language` header". Netlify recipes such as `/* /es/:splat 302 Language=es`.
- **VitePress**, https://vitepress.dev/guide/i18n. Quote: "VitePress won't redirect `/` to `/en/` by
  default. You'll need to configure your server for that." Recipe: `/*  /es/:splat  302
  Language=es`.
- **Docusaurus**: "Automatic locale detection: opinionated, and best done on the server".
- **Gatsby**: `createRedirect` conditions.
- **Next.js export**: "Internationalized Routing does not integrate with `output: 'export'`".
- Hugo and Astro on static output write a fixed root redirect page. Nuxt i18n detects on the
  client.

### 3.2 Cross-tool table

| tool | SPA fallback | `/x` from `x.html` | `/x` from `x/index.html` without 301 | `404.html` with 404 | hashed directory | caching advice |
|---|---|---|---|---|---|---|
| Hugo | no | with `uglyURLs` links `.html` | default pretty URLs `/x/` | yes | none (beside source) | `hugo deploy` example only |
| Jekyll | no | yes (extensionless permalinks, redirect-from pages) | `pretty` gives `/x/` | yes (`error_page`) | none | none |
| Eleventy | no | opt-in | default `/x/` | yes | none | none |
| Astro | no | `build.format: 'file'` | its nginx recipe | yes (`error_page`) | `/_astro/` | Node adapter `immutable` |
| Docusaurus | no | `trailingSlash: false` | default | yes (localised) | `/assets/` | none |
| VitePress | no | `cleanUrls` | its nginx recipe | yes (`error_page`) | `/assets/` | full nginx recipe |
| MkDocs / Material | no | `use_directory_urls: false` links `.html` | default `/x/` | yes | Material `/assets/` | none |
| Next.js export | no | default | with `trailingSlash: true` | yes (`error_page`) | `/_next/static/` | `next start` only |
| Nuxt generate | `200.html` | no | default | yes ("keep a 404 status") | `/_nuxt/` (with `builds/latest.json` inside) | none for static |
| SvelteKit static | `fallback` (`200.html`) | default | `trailingSlash: 'always'` | no | `/_app/immutable/` | adapter-bun only |
| Angular | `index.html` | n/a | n/a | soft 404 | none (root) | none |
| React Router / Vite | `index.html` or `__spa-fallback.html` | no | prerendered `x/index.html` | no | `/assets/` | Vite: HTML `no-cache` |
| Vue Router | `index.html` | n/a | n/a | soft 404 | (Vite) | none |
| Gatsby | client-only routes | no | `trailingSlash: "never"` | yes (custom rule) | `/static/` plus root JS/CSS | full, by path and by ending |
| Hexo | no | `trailing_html: false` | default `/x/` | not documented | none | none |

## 4. What real files contain (Sourcegraph corpus, 2026-10-13)

### 4.1 `_redirects` (2,512 files with rules, 47,025 rules)

| kind of rule | files | share of files | rules | example |
|---|---|---|---|---|
| SPA fallback `/* /index.html 200` | 1,143 | 45.5 % | 1,142 | `/* /index.html 200`, [tailchat](https://github.com/msgbyte/tailchat/blob/89ab8bba033603415f46fc228b5771d99daa6a21/client/web/assets/_redirects) |
| ... and nothing else in the file | 998 | 39.7 % | | |
| exact path redirect (301/302/307/308) | 961 | 38.3 % | 37,183 | `/guide/api-vite-runtime /guide/api-environment 301`, [vitejs/docs-ko](https://github.com/vitejs/docs-ko/blob/e786fb4c0e7473eb2145f1609da5134c3e832836/public/_redirects) |
| redirect to an external URL | 596 | 23.7 % | 10,160 | |
| section moved, remainder kept (`/a/* /b/:splat`) | 510 | 20.3 % | 3,010 | `/css-in-js/* /styles/:splat 301`, [mui/material-ui](https://github.com/mui/material-ui/blob/ade9a69112d76d1213fee5750bf5dbdb23db8efe/docs/public/_redirects); `/feedback/*  /feature-requests/:splat  301!`, [docusaurus](https://github.com/facebook/docusaurus/blob/c245217563f6491fdb79bf5ac91bfa16536e5de9/website/static/_redirects) |
| no status written (Netlify 301, Cloudflare 302) | 336 | 13.4 % | 10,749 | `/blog/ /`, [TalonCommunity/Wiki](https://github.com/TalonCommunity/Wiki) |
| forced (`!`) | 332 | 13.2 % | 5,305 | |
| domain-level `from` (`https://host/...`) | 253 | 10.1 % | 949 | `https://yihui.netlify.app/*  https://yihui.org/:splat  301!`, [yihui.org](https://github.com/yihui/yihui.org/blob/fb6db2718c6325c9dd517073ca55aeb5b61f6744/static/_redirects) |
| status 302 | 230 | 9.2 % | 2,854 | |
| section to one page, remainder dropped (`/a/* /b`) | 170 | 6.8 % | 1,736 | `/docs/rpg/* /zh-tw/docs/find-food 301` |
| internal rewrite (200) of one path | 165 | 6.6 % | 784 | `/install  /install.sh  200` |
| internal rewrite (200) by pattern, including self-exemptions | 145 | 5.8 % | 499 | `/docs/*  /docs/index.html  200` |
| proxy (200 to another host) | 96 | 3.8 % | 651 | `/_sukka/api/*  https://api.cloudflare.com/:splat  200`, [dashflare](https://github.com/SukkaW/dashflare/blob/453072040f0731e424b27563e43c6238f78e97f1/public/_redirects) |
| custom 404 page by pattern (`/* /404.html 404`) | 90 | 3.6 % | 150 | `/docs/* /404.html 404` then `/* /404.html 404`, [probelabs/probe](https://github.com/probelabs/probe/blob/10d4a76db1833f41f0129cd4739e744df14c74e6/docs/public/_redirects) |
| sub-path SPA fallback (`/x/* /x/index.html 200`) | 82 | 3.3 % | 143 | `/your-memory/*  /your-memory/index.html  200` |
| `:placeholder` in `from` | 79 | 3.1 % | 1,780 | see below |
| `.html` <-> clean form of the same page, as exact rules | 58 | 2.3 % | 283 | `/index.html / 301`, `/install /install/index.html 301` ([lando/core](https://github.com/lando/core/blob/7a87f80576c5cdb5c7d616108bc9aff81150d463/_redirects)) |
| self-rewrite exempting a path from a later fallback (`/assets/* /assets/:splat 200`) | 39 | 1.6 % | 95 | `/@static/* /@static/:splat 200` |
| a broader splat before a narrower rule it covers (meaning depends on first match) | 34 | 1.4 % (3.4 % of files with two or more rules) | | `/*  /index.html  200` before `/samples  https://github.com/stripe-samples  301`, [stripe.github.io](https://github.com/stripe/stripe.github.io/blob/455f506a628dc3f6c505e3001db45a64e29e9fc3/samples/_redirects) |
| trailing slash only, as exact rules | 33 | 1.3 % | 161 | `/tutorials/getting-started/  /tutorials/getting-started  301`, [hook0](https://github.com/hook0/hook0/blob/81c37d6aa3cdffb7c751bfbbd0e7c30972979b69/documentation/static/_redirects) |
| splat not at the end of `from` | 30 | 1.2 % | 321 | `/*/readme.html  /:splat 301!`, `/*.txt /:splat.md 301` ([vite](https://github.com/vitejs/vite/blob/dce9fe69d37e957b62f3b5df61a761f7f2f949f5/docs/public/_redirects)) |
| `:splat` inside the target | 24 | 1.0 % | 52 | `/tiers/tiered/prestige-1/*.png /prestiges/brawlers/:splat/4.png 301`, [Brawlify/CDN](https://github.com/Brawlify/CDN/blob/45eabc3ebd910c6998c1abd3cf21d9fe970dab15/_redirects) |
| splat glued to a partial segment | 18 | 0.7 % | 266 | `/faq/codestructure*  /faq/code-structure:splat`, [redux-in-chinese](https://github.com/nefe/redux-in-chinese/blob/4bb9166a16fc7e2b418b1a28444c058d7496d88f/website/_redirects) |
| status 308 / 307 / 303 | 18 / 13 / 4 | 0.7 / 0.5 / 0.2 % | 160 / 99 / 9 | |
| query parameter captured into the target | 15 | 0.6 % | 116 | `/search q=:q  /blog?q=:q`, [old-kentcdodds.com](https://github.com/kentcdodds/old-kentcdodds.com/blob/70dafadb690bf6ffe53282e02bfcde5240f3cb10/static/_redirects) |
| case-only redirect (`/iOS/quickstart /ios/quickstart`) | 13 | 0.5 % | 178 | [dyte-io/docs](https://github.com/dyte-io/docs/blob/3caf7418b06dd74f8901c60f6a0385835c4de950/static/_redirects), [Kong docs](https://github.com/Kong/docs.konghq.com/blob/83ad772bd62d0e581a8ca17062e7ec674531e211/app/_redirects) |
| `Language=` | 11 | 0.4 % | 86 | `/guide/*   /zh/guide/:splat    302  Language=zh`, [Artalk](https://github.com/ArtalkJS/Artalk/blob/796ee2d7ca9bbfc643ee4131abe6f78ab00200c6/docs/docs/public/_redirects) |
| 404 for one path | 9 | 0.4 % | 20 | `/.env / 404` |
| a pattern dropping `.html` (`/*.html /:splat`) | 11 | 0.4 % | 18 | `/*.html /:splat 301`, [chaxus/ran](https://github.com/chaxus/ran/blob/55aa6c516f385a3003a8f3fee9c4db38bc0793ed/packages/site/public/_redirects) |
| a pattern adding a slash (`:splat/`) | 10 | 0.4 % | 28 | `/*/index.html /:splat/ 301` |
| a pattern removing the slash (`/*/ /:splat`) | 5 | 0.2 % | 5 | `/*/ /:splat 308`, [evolu](https://github.com/evoluhq/evolu/blob/6a156dd658ea5665ff958f4752d4facdbc6cdbac/apps/web/public/_redirects) |
| a pattern dropping `index.html` | 4 | 0.2 % | 8 | `/:foo/:bar/index.html  /:foo/:bar/  302!`, [prometheus/docs](https://github.com/prometheus/docs/blob/bb636b7918b0cdd4961d43cf6dd57cc9801a4148/public/_redirects) |
| query parameter with a fixed value | 3 | 0.1 % | 4 | `/info/refs service=git-upload-pack https://github.com/...` |
| `Country=` | 2 | 0.1 % | 3 | `https://ohshitgit.com/  https://ohshitgit.com/pt_BR  302  Country=br`, [ohshitgit](https://github.com/ksylor/ohshitgit/blob/5f908089c6b9f676ef0d5f3ec208ae87ba80e269/_redirects); `/* /access-denied 403! Country=cu,ir,kp,...`, [EnterpriseDB/docs](https://github.com/EnterpriseDB/docs/blob/2ae7dd5e9b174525e34fe423a742a24253f99af9/static/_redirects) |
| `Header:Accept=text/markdown` (a 303 to a `.md` twin for agents) | 1 | | 6 | `/:a/  /:a.md  303!  Header:Accept=text/markdown`, [tetherto/qvac](https://github.com/tetherto/qvac/blob/0a661bb4e27259745a994375712f68f9f471319e/docs/website/public/_redirects) |
| 410 | 1 | | 2 | `/author/*  /410.html  410` |
| `Role=`, `Cookie=` | 0 | | 0 | |

The 79 files with placeholders split by what the placeholders do:

| shape | files | rules | example |
|---|---|---|---|
| placeholder in the first segment, carried (`/:lang/x → /:lang/y`) | 26 | 461 | `/:lang/api/grid-list/ /:lang/material-ui/api/image-list/ 301`, [mui docs](https://github.com/mui/material-ui-docs/blob/8ae1c0ce7df374e32f9bc6bd4da5a9052d2b7c44/docs/public/_redirects) |
| segments reordered, dropped or embedded (`/web/:year/:month/:day/* → /web/:splat`) | 29 | 326 | [zachleat.com](https://github.com/zachleat/zachleat.com/blob/426922e4adcc99499d0bb479d34e653f8ffd665f/_redirects); `/docs/:version/overview/ /docs/:version/overview/what-is-kuma 301` |
| trailing placeholders carried to the end (`/a/:x → /b/:x`, the same as a prefix rule) | 22 | 45 | `/interview/concept/:path  /fe/concept/:path  301` |
| `.html` dropped (`/:slug.html → /:slug`) | 2 | 4 | |

Rule counts per file:
- 1,758 of 2,585 files hold one or two rules.
- 82 hold more than 100, 17 more than 500 and 7 more than 1,000. The largest are the Kong docs
  (3,576) and LoginRadius's engineering portal (3,550).

### 4.2 `_headers` (610 files with rules, 1,947 path blocks)

Paths:

| path kind | files | share | blocks |
|---|---|---|---|
| `/*` (whole site) | 339 | 55.6 % | 347 |
| directory prefix (`/assets/*`) | 326 | 53.4 % | 571 |
| exact file or path (`/sw.js`, `/index.html`) | 202 | 33.1 % | 572 |
| extension glob at the root or any depth (`/*.js`) | 103 | 16.9 % | 257 |
| `/` exact | 44 | 7.2 % | 44 |
| extension glob under a directory (`/assets/*.js`) | 34 | 5.6 % | 84 |
| another glob (`/workbox-*`, `/*.js.map`, `/pagefind/*.pf_meta`) | 22 | 3.6 % | 25 |
| host-specific (`https://name.pages.dev/*`) | 20 | 3.3 % | 25 |
| `:placeholder` | 3 | 0.5 % | 3 |

Field names, by files (lines):

| field | files | share | lines |
|---|---|---|---|
| `Cache-Control` | 390 | 63.9 % | 1,333 |
| `X-Content-Type-Options` | 198 | 32.5 % | 236 |
| `Referrer-Policy` | 172 | 28.2 % | 191 |
| `X-Frame-Options` | 165 | 27.0 % | 178 |
| `Content-Security-Policy` | 109 | 17.9 % | 125 |
| `Permissions-Policy` | 107 | 17.5 % | 110 |
| `Content-Type` | 104 | 17.0 % | 290 |
| `Access-Control-Allow-Origin` | 101 | 16.6 % | 171 |
| `Strict-Transport-Security` | 66 | 10.8 % | 69 |
| `X-XSS-Protection` | 66 | 10.8 % | 75 |
| `Cross-Origin-Opener-Policy` | 61 | 10.0 % | 62 |
| `X-Robots-Tag` | 51 | 8.4 % | 91 |
| `Cross-Origin-Embedder-Policy` | 43 | 7.0 % | 48 |
| `Link` | 23 | 3.8 % | 79 |
| `Access-Control-Allow-Headers` / `-Methods` | 22 / 20 | 3.6 / 3.3 % | 27 / 32 |
| `Cross-Origin-Resource-Policy` | 17 | 2.8 % | 22 |
| `! Field` (Cloudflare detach) | 17 | 2.8 % | 54 |
| `Vary` | 7 | 1.1 % | 19 |
| `Service-Worker-Allowed` | 3 | 0.5 % | 3 |
| `Content-Disposition` | 3 | 0.5 % | 6 |
| `Clear-Site-Data`, `Refresh`, `ETag`, `Last-Modified`, `Content-Encoding` | 1 each | | |

Caching:
- **Long lifetimes.** The 390 files with `Cache-Control` set a year-long or `immutable` lifetime
  by path kind:
  - directory: 283 files (46.4 % of all 610), 410 lines;
  - extension glob: 54 files (8.9 %), 160 lines;
  - exact file: 12 files;
  - another glob: 9 files;
  - `/*`, i.e. HTML included: 6 files.
- **Directories that get the long lifetime**, by lines:
  - `/assets/*` 171;
  - `/_next/static/*` 63;
  - `/_astro/*` 28;
  - `/fonts/*` 26;
  - `/build/*` 14;
  - `/images/*` 12;
  - `/img/*` 10;
  - `/js/*` 9;
  - `/css/*` 8;
  - `/static/*` 4;
  - `/_app/immutable/*` 4.
- **`no-cache` kinds** (`no-cache`, `max-age=0`, `no-store`, `must-revalidate`), by lines:
  - `/*` 53;
  - `/index.html` 38;
  - `/sw.js` 24;
  - `/` 18;
  - `/service-worker.js` 6;
  - `/manifest.webmanifest` 5;
  - `/registerSW.js` 4.
- **Commonest values:**
  - `public, max-age=31536000, immutable` (456 lines);
  - `no-cache` (96);
  - `public, max-age=86400` (77);
  - `public, max-age=3600` (68);
  - `public, max-age=0, must-revalidate` (62).
- **Overlap.** 37 files (6.1 %) set `Cache-Control` both on `/*` and on a narrower path. On
  Cloudflare Pages the two values are joined with a comma (2.2), so `/assets/x.js` gets
  `no-cache, public, max-age=31536000, immutable`.
- **Extensions in globs**, by files: `js` 55, `css` 41, `png` 27, `svg` 22, `html` 22, `woff2` 14,
  `jpg` 14, `md` 13, `webp` 12, `wasm` 12, `mjs` 10.
- **Security fields at `/*`:** 222 files (36.4 %) set at least one of the six there.

`Content-Type` overrides (290 lines in 104 files), by the path they are set on:
- **Most restate what agensio's table already sends:**
  - `.txt` text/plain: 46 lines;
  - `.js` and `.mjs`: 56;
  - `.css`: 24;
  - `.md`: 13;
  - `.json`: 15;
  - `.webmanifest`: 8;
  - `.wasm`: 8;
  - `.woff2`, `.svg`, `.ico`.
- **The rest are what a table by extension cannot give:**
  - extensionless names: `/.well-known/apple-app-site-association` → `application/json` (8 lines),
    `/.well-known/api-catalog` → `application/linkset+json` (6), Next.js `opengraph-image` →
    `image/png` (8), `/.well-known/openid-configuration`, `oauth-authorization-server`,
    `oauth-protected-resource`, `traffic-advice`;
  - install scripts and endpoints such as `/install.sh`, `/sh`, `/pwsh`, `/latest_version` →
    `text/plain`, so `curl | sh` users and browsers see text (agensio sends `.sh` and `.ps1` as
    `application/octet-stream`);
  - feeds named `.xml` as `application/rss+xml` or `atom+xml` (7 lines);
  - Markdown under a directory (`/md/*`).
- Examples:
  [glink25/Cent](https://github.com/glink25/Cent/blob/03ae57ad3a1d98c9db08fc71224704150765b96f/apps/cent/public/_headers),
  [openacme](https://github.com/sandydasari/openacme/blob/e76a79b40705df25c66760981917cfc1aae3a50a/apps/docs/public/_headers),
  [iannuttall/seo](https://github.com/iannuttall/seo/blob/5b794fe9c8addbc227c49262bb6ac79ad8429452/apps/web/public/_headers).

Representative files:

- [passkeys.dev](https://github.com/passkeydeveloper/passkeys.dev/blob/ecad1b24d16018a7d690c3024c82d07c944bad85/static/_headers):
  `/*` with CSP, HSTS `max-age=31536000; includeSubDomains; preload` and
  `Access-Control-Allow-Origin: *`.
- [vuejs-translations/docs-ja](https://github.com/vuejs-translations/docs-ja/blob/edc1273e61d3f46668bd78b29d18ef04adcf5138/src/public/_headers):
  `/assets/*` with `Cache-Control: max-age=31536000` and `Cache-Control: immutable` on two lines,
  which Netlify concatenates; `/*` with `Content-Security-Policy: frame-ancestors ...`.
- [HamishMW/portfolio](https://github.com/HamishMW/portfolio/blob/b7444bc16216f38c64f4afb8d2f53b8c4cbb2bda/public/_headers):
  `/*.css` and `/*.woff2` with `public, max-age=31536000, immutable`.
- [eero-lehtinen/oklch-color-picker](https://github.com/eero-lehtinen/oklch-color-picker/blob/6eed6ac195099cc008c1378030a07a45b2e0cee7/assets/_headers):
  `/oklch-color-picker-*` and `/site-*` immutable (hashed names at the root, matched by name
  prefix); `/` with `public, max-age=0, must-revalidate`.
- [padenot/ringbuf.js](https://github.com/padenot/ringbuf.js/blob/7996bf20b3e6872d7a15da551c4e990c7f4dff94/public/_headers):
  `/*` with `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy:
  require-corp` (SharedArrayBuffer for WebAssembly threads).
- [rbbydotdev/opal](https://github.com/rbbydotdev/opal/blob/2c86c83021a19df6da969bcf22b8ba5efdc108ed/public/_headers):
  `/*` with `Service-Worker-Allowed: /`.
- [tommy351/kosko](https://github.com/tommy351/kosko/blob/8a0c345e816e14db9ced66da6526b392bea73330/website/static/_headers):
  `https://kosko.pages.dev/*` with `Refresh: 0; url=https://kosko.dev/:splat` (a redirect of the
  preview host written as a header, because Pages has no domain-level redirects).

### 4.3 `netlify.toml` (680 files with redirects, 303 with headers)

- **Redirects:**
  - SPA fallback: 389 files (57.2 %);
  - `force = true`: 188;
  - exact: 127 files, 2,133 rules;
  - prefix, remainder kept: 99;
  - domain-level: 76;
  - rewrite to a Netlify Function: 70;
  - proxy to another host: 57;
  - prefix, remainder dropped: 34;
  - 404 page: 32;
  - placeholders: 8;
  - `Country` condition: 6;
  - `query`: 4;
  - `:splat` inside the target: 2.
- **Country examples:**
  - [hop-protocol](https://github.com/hop-protocol/hop/blob/3ae90badbed5708d72cec46d0efeb004a4d0c587/packages/frontend/netlify.toml):
    `from = "/*"`, `to = "/451.html"`, `status = 451`, with a country list;
  - [virtual-lolly](https://github.com/philhawksworth/virtual-lolly/blob/3fde915602bc1eaac83e34cc45ad01712af44bb0/netlify.toml),
    Netlify's own demo: `Country = ["US"]` rewrites.
- **Headers:**
  - `for = "/*"`: 190 files;
  - exact path: 88;
  - directory: 82;
  - extension glob: 39 (12.9 % of the files with headers).
  - [Hugo's own documentation site](https://github.com/gohugoio/hugo/blob/53aae44633bae913dfede21a02cdcfd99f4dd5b2/docs/netlify.toml)
    sets `Cache-Control` by `/*.jpg`, `/*.png`, `/*.css`, `/*.js`, `/*.ttf`;
  - [redux](https://github.com/reduxjs/redux/blob/56abca4749921d68f40cda20afd2043af9751f72/netlify.toml)
    sets COOP/COEP on specific tutorial pages (exact and `/*`).

### 4.4 `vercel.json` (random 1,198 of 6,684; 638 with a routing or header key)

Most `vercel.json` files configure serverless functions, so these shares are of all files sampled.

- **SPA fallback rewrite:** 160 files (13.4 %), plus 29 with the legacy `routes`.
- **Redirects:**
  - exact: 85 files, 3,411 rules;
  - prefix with the remainder kept (`/jp/:path*` → `/ja/:path*`, `/(.*)` → `https://host/$1`): 14
    files, 56 rules;
  - remainder dropped: 11 files;
  - a single trailing segment carried: 2 files;
  - anything else (a parameter inside the target, a regex, several parameters): 32 files, 336
    rules. For example `/kb/guides/:path+.md` → `/kb/markdown/guides/:path+.md`
    ([supabase](https://github.com/supabase/supabase/blob/cb4307f15b99e02a8a56e103086d1eab72eb9e9a/apps/kb/vercel.json)),
    and `/:page(manuals|manual-[a-z0-9-]+).html` → `/:page`
    ([ai-engineering-from-scratch](https://github.com/rohitg00/ai-engineering-from-scratch/blob/56c886c8821fc488b6f9608895c983d18f0d1ea3/vercel.json)).
- **Statuses** by files: 308 (default) 84, 307 28, 301 6, 302 1.
- **Conditions (`has`/`missing`):**
  - redirects: `host` 11 files, `query` 4, `header` 3;
  - rewrites: `header` 4 (an `Accept` test that serves Markdown to agents), `host` 4;
  - headers: 3.
- **`cleanUrls: true`:** 86 files (7.2 %).
- **`trailingSlash`:** `false` 65 files (5.4 %), `true` 12 (1.0 %).
- **Headers:**
  - `/(.*)`: 114 files;
  - prefix: 95;
  - exact: 56;
  - extension pattern: 41 (`/(.*)\.(css|js)`, `/(.*).png` in
    [vuejs/docs](https://github.com/vuejs/docs/blob/40aa88af0094f7bab4aaf786e55c748a6a251d88/vercel.json));
  - `Cache-Control` by prefix 76 files, exact 42, extension 34.
- **Rewrites:**
  - `/:path*` → `/:path*.html` (clean URLs by hand, vuejs/docs);
  - to `/api`: 64 files;
  - proxy to another host: 37 files.

### 4.5 `firebase.json` (random 653 of 1,370; 646 with hosting)

- **SPA fallback `"source": "**", "destination": "/index.html"`:** 365 files (56.5 %), plus 10 with
  exclusions. For example `/**/!(*.@(js|ts|html|css|json|svg|png|jpg|jpeg))` in
  [angular/components](https://github.com/angular/components/blob/f6b465757df95cb7d4ca6903811a408c2298954d/firebase.json).
- **Rewrite to a function or Cloud Run:** 74 files (11.5 %).
- **Headers by extension glob:** 56 files (8.7 %; `Cache-Control` 50).
  - by exact path: 45 (`/service-worker.js`, `ngsw-worker.js`, `/version.json`);
  - whole site: 42;
  - directory: 25.
  - [monkeytype](https://github.com/monkeytypegame/monkeytype/blob/d3f17224ce88f986b0bac10c8c11dac2bb80df2a/frontend/firebase.json)
    combines all four.
- **`cleanUrls: true`:** 38 files (5.9 %). **`trailingSlash: false`:** 18; **`true`:** 2.
- **Redirects:** 26 files; exact rules dominate (1,189 rules, most of them in Flutter's blog move).
- **Redirects by regex:** 8 files. For example `(.*)\.html$` → `:1`, the `.html` drop
  ([dart.cn](https://github.com/cfug/dart.cn/blob/cf553cbe1a2bbd00bfcbfedaa8312f1babfdda30/firebase.json)),
  and `/(.*)-([0-9a-f]{10,12})/?` → `https://flutter.dev/blog/:1`, which strips Medium's id
  suffix
  ([flutter/website](https://github.com/flutter/website/blob/11cca2fa630b605f11b217acf55722c1bb520feb/sites/blog_redirects/firebase.json)).

### 4.6 `staticwebapp.config.json` (269; Uno Platform samples weigh heavily)

- **`navigationFallback`:** 227 files, 198 with `exclude` (mostly `*.{css,js}`, images, `*.wasm`).
- **Route headers:** 138 files, 121 of them by extension.
- **`globalHeaders`:** 42 files.
- **`mimeTypes`:** 37 files (13.8 %). For example `{".md": "text/markdown; charset=utf-8", ".txt":
  "text/plain; charset=utf-8", ".webp": "image/webp", ".json": "application/json"}`
  ([datacontract-cli](https://github.com/datacontract/datacontract-cli/blob/fdce74e913543757596aff3f5c37e40fb29df3db/docs/static/staticwebapp.config.json)).
- **`responseOverrides`:**
  - 404 → rewrite: 36 files (`/404.html`, or `/index.html` with `statusCode: 200`);
  - 401 → redirect to login: 11 files.
- **Routes:**
  - `allowedRoles`: 22 files;
  - redirect: 19 files (`/index.html` → `/` 301);
  - rewrite: 18 files.
- **`trailingSlash`:** 16 files (auto 10, never 4, always 2).

### 4.7 AWS Amplify (12 files)

- Every file sets the security fields on `'**'` or `'**/*'`.
- [aws-amplify/docs](https://github.com/aws-amplify/docs/blob/714b208f8b79f630d9c0432fcca189c35b5ce212/customHttp.yml)
  explains why its `Link` field sits on the global block:
  > "with trailingSlash: true the actual page requests are extensionless directory URLs (e.g.
  > /react/build-a-backend/), so an `**/*.html` pattern would miss real page loads".

  The same file sets `Content-Type: application/linkset+json` on the extensionless
  `/.well-known/api-catalog`.

## 5. The needs, one by one

Ids:
- **SR-n**: routing and redirects.
- **SH-n**: response headers.

Frequencies are from section 4: "`_redirects` 45.5 %" means that share of the 2,512 `_redirects`
files with a rule.

### SR-1 SPA fallback: an unknown path gets the shell with 200

- **Platforms.**
  - Netlify `/* /index.html 200`.
  - Cloudflare Pages: automatic without a `404.html`.
  - Workers: `not_found_handling = "single-page-application"`.
  - Vercel: `{"source": "/(.*)", "destination": "/index.html"}`.
  - Firebase: `"source": "**"`.
  - Azure: `navigationFallback`.
  - Amplify: the regex rule.
  - Render: `/*` rewrite.
- **Tools.** Angular, Vue Router, React Router, Vite, Nuxt (`200.html`), SvelteKit (`200.html`),
  Gatsby (client-only routes).
- **Frequency.**
  - `_redirects` 45.5 % (39.7 % hold nothing else).
  - `netlify.toml` 57.2 % of the files with redirects.
  - `firebase.json` 56.5 %.
  - `vercel.json` 13.4 % of all sampled.
  - Azure 84 %.
- **Class X: `try_files` (exists).**

  ```toml
  [[site]]
  root = "/var/www/app.example.com/dist"
  try_files = ["$uri", "$uri/", "/index.html"]   # Nuxt and SvelteKit: "/200.html"; React Router: "/__spa-fallback.html"
  ```

  This is Netlify's unforced rule exactly: an existing file wins, the rest get the shell. The
  cookbook has the recipe (`docs/examples/basics.md`, "A single-page application").
- **X-gap on a managed site.** `rules.front_controller` is refused unless the preset runs PHP
  (`src/control/sites.cpp`), and `site_update` has no `try_files`. A managed `app = "static"` SPA
  can get its fallback only from a root additions file (root's).
  - Smallest change: accept `rules.front_controller` naming an `.html` file on `app = "static"`. It
    renders the same `try_files` line (section 7, change 7).
- **Design point.** Path redirects must match only the path the client asked for, never a
  `try_files` target or a directory's index.
  - 28 `_redirects` files redirect `/index.html` to `/`.
  - If `[[site.redirect]]` were judged again on the fallback hop, as `refuse` and the access
    rules are (configuration.md 6b), such a rule would turn every SPA route into a 301 to `/`.
  - headers.md 1 says this for headers; redirects.md does not say it.

### SR-2 Keeping asset paths out of the fallback

- **Platforms.**
  - Azure: `"exclude": ["/images/*.{png,jpg,gif}", "/css/*"]`.
  - Amplify: the regex sends only paths without an extension, or with an unlisted one, to the
    shell.
  - Firebase: `"!/@(js|css)/**"`.
  - Netlify and Cloudflare: a self-rewrite before the fallback, `/assets/* /assets/:splat 200`
    (39 `_redirects` files).
- **Purpose.** A deleted or mistyped chunk should answer 404, not HTML that the browser then
  fails to run as JavaScript.
- **Class X: a location with its own `try_files`.** A prefix location works, and a suffix location
  works for endings:

  ```toml
  [[site.location]]
  path = "/assets/"
  try_files = ["$uri", "=404"]

  [[site.location]]          # Amplify's "anything with an extension" for the common ones
  path = ".js"
  match = "suffix"
  try_files = ["$uri", "=404"]
  ```

- **Design point.** With the SPA fallback, a missing `/assets/x.js` that is not excluded gets
  `/index.html` with 200.
  - A rule `path = "/assets/"`, `when = "success"`, `set` a year of `immutable` would then apply
    to that shell, because rules match the client's path whatever the internal hops
    (headers.md 1).
  - Browsers and CDNs would then keep the HTML under the asset's URL for a year. This is Vite's
    load-error scenario.
  - In the joined sample, 11 directories ship both an SPA fallback in `_redirects` and a
    year-long directory rule in `_headers`. Only 3 of those name the directory in `_redirects`
    (an exemption or a 404).
  - Whether Netlify applies the `/assets/*` header to the rewritten shell is unverified.
  - Smallest change: `-t` warns when a freshness-granting rule covers a prefix that a `try_files`
    fallback to another path can answer, with the exclusion location as the fix. Alternatively,
    such rules skip answers made by a fallback to a different path.

### SR-3 Sub-path SPA

- **Rules.** `/app/* /app/index.html 200` (82 `_redirects` files, 3.3 %); Gatsby's
  `/app/[...]/index.html`; Hugo's development server `/myspa/**` → `/myspa/`; 7 `firebase.json`
  files.
- **Class X:**

  ```toml
  [[site.location]]
  path = "/app/"
  try_files = ["$uri", "$uri/", "/app/index.html"]
  ```

### SR-4 A custom `404.html`, answered with status 404

- **Platforms.**
  - Netlify, Vercel, Firebase and GitHub Pages: `404.html`, automatic.
  - Cloudflare: the nearest `404.html` up the tree.
  - Workers: `"404-page"`.
  - Azure: `responseOverrides`.
  - Amplify: a `404` rule.
- **Tools.** Ten of the sixteen generate a `404.html` and document it (3.1). Four give nginx's
  `error_page 404 /404.html` (Jekyll, Astro, VitePress, Next.js). Nuxt says it should "keep a 404
  status". Docusaurus and Hugo localise it (`/fr/404.html`, `404.de.html`).
- **Frequency.** The corpus undercounts, because the platforms serve it without a rule.
  Explicitly:
  - `/* /404.html 404` in 90 `_redirects` files (3.6 %) and 32 `netlify.toml` files;
  - 404 → rewrite in 36 Azure files (13 %).
- **Class N (X-gap).** agensio answers 404 with its built-in page (`src/response.cpp`).
  `try_files = ["$uri", "$uri/", "/404.html"]` would serve the page with 200, a soft 404 that
  search engines index.
  - Not a redirect or header rule; it belongs to the static handler.
  - Smallest change: a site or location key, nginx's `error_page` with `internal`:

    ```toml
    error_page = { 404 = "/404.html" }        # proposed: a 404 from the static handler serves this file, status kept

    [[site.location]]
    path = "/fr/"
    error_page = { 404 = "/fr/404.html" }      # proposed: per-language pages
    ```

    The built-in page stays the answer when the file is missing.

### SR-5 Clean URLs: `/x` served from `x.html` without a redirect

- **Tools.** Eight of sixteen need it:
  - by default: Next.js export, SvelteKit;
  - as an option: VitePress `cleanUrls` ("without a redirect"), Docusaurus `trailingSlash:
    false`, Astro `format: 'file'`, Eleventy's recipe, Hexo `trailing_html: false`;
  - Jekyll's extensionless permalinks, and jekyll-redirect-from's `/foo` → `foo.html`.
- **Platforms.** Netlify (Pretty URLs), Cloudflare Pages, Vercel `cleanUrls`, Firebase
  `cleanUrls`, Azure `trailingSlash: "auto"` and Amplify all do it.
- **Frequency.**
  - `vercel.json` `cleanUrls: true` 7.2 %; `firebase.json` 5.9 %.
  - In `_redirects` only 3 files write `/* /:splat.html 200`, because the platforms do it
    themselves.
  - vuejs/docs writes it by hand on Vercel (`/:path*` → `/:path*.html`).
- **Class N (X-gap, `try_files`).** `parse_try_files` accepts only `$uri`, `$uri/`, `=403`, `=404`
  and a path.
  - Smallest change: a `$uri` followed by a fixed suffix as a step. It is the line both Next.js
    and VitePress give for nginx:

    ```toml
    try_files = ["$uri", "$uri.html", "$uri/", "=404"]   # proposed $uri.html
    ```

### SR-6 `/x` served from `x/index.html` without a 301

- **Tools.** Docusaurus by default, Nuxt by default, React Router pre-rendering, Gatsby `never`,
  and Astro's own nginx recipe (`try_files $uri $uri/index.html =404`).
- **Class E≈ today.** agensio answers `/x` with a 301 to `/x/` for a directory, which works.
  Gatsby's default `always` asks for exactly that, and so do GitHub Pages and Netlify's Pretty
  URLs. The cost:
  - one hop for every link the generator wrote without the slash;
  - the slash form becomes the canonical URL, which Docusaurus warns about.
- **N for the no-redirect form.** The same change as SR-5, the step `"$uri/index.html"`.

### SR-7 A site-wide trailing-slash policy (add or remove, 301 or 308)

- **Platforms.**
  - Vercel `trailingSlash` (`false` 5.4 %, `true` 1.0 %).
  - Firebase `trailingSlash` (2.8 % `false`).
  - Azure (16 files).
  - Workers `html_handling`.
  - Netlify says it cannot: "You cannot use a redirect rule to add or remove a trailing slash."
- **Tools.** Gatsby (its RFC expects the host to 301 to the chosen form).
- **Files.**
  - 33 `_redirects` files write slash pairs as exact rules, e.g.
    `/tutorials/getting-started/  /tutorials/getting-started  301`.
  - 5 write `/*/ /:splat 301` or `308`.
- **Class O** (redirects.md 5.4: "it fights the applications' own rules").
  - The owner picks the generator's slash form that matches agensio's (the directory form with
    the slash is the default of Hugo, Jekyll's `pretty`, Eleventy, Astro, MkDocs, Hexo and
    Gatsby), and writes exact rules where old links differ.
  - For static sites there is no application to fight: the generator decides the form. If the
    question is reopened, the smallest form is a static-only policy that knows the files: remove
    the slash only where `x.html` exists, and add it only for directories.

### SR-8 `.html` and `/index.html` redirected to the clean form

- **Platforms.**
  - Vercel `cleanUrls` (308).
  - Firebase `cleanUrls` (301).
  - Cloudflare Pages (`/contact.html` → `/contact`, `/about/index.html` → `/about/`).
  - Azure `auto` (301).
- **Files.**
  - Exact pairs in 58 `_redirects` files (2.3 %), e.g. `/index.html / 301`.
  - Patterns `/*.html /:splat 301` in 11 files.
  - Firebase regex `(.*)\.html$` → `:1` (dart.cn).
  - Vercel `/:page(...).html` → `/:page`.
- **Class E for one page, O site-wide** (redirects.md 5.4).

  ```toml
  [[site.redirect]]
  from = "/index.html"
  match = "exact"
  to = "/"
  status = 301
  ```

- **The pairing.** Vercel and Firebase pair the redirect with the clean-URL rewrite of SR-5 in
  one switch.
  - If SR-5 is built, a `.html` request answered as is serves the same page under two URLs.
  - Hence the option of change 2 in section 7: one `clean_urls` switch that rewrites and
    redirects, for files that exist.

### SR-9 Exact migration redirects

- **Frequency.** This is the commonest redirect, with the most rules:
  - `_redirects` 38.3 % of files, 37,183 rules;
  - `netlify.toml` 127 files, 2,133 rules;
  - `vercel.json` 85 files, 3,411 rules;
  - `firebase.json` 26 files, 1,189 rules.
- **Class E:**

  ```toml
  [[site.redirect]]
  from = "/guide/api-vite-runtime"
  match = "exact"
  to = "/guide/api-environment"
  status = 301
  ```

- **Differences an import must handle:**
  - **The default status of the same file differs.** Netlify defaults to 301, Cloudflare to 302,
    Vercel to 308. 13.4 % of `_redirects` files omit the status (10,749 rules); the design
    requires one.
  - **Trailing slash.** Netlify matches `/old` and `/old/` alike. redirects.md does not say
    whether an exact `from = "/old"` matches `/old/` (section 7, change 9b).
  - **Case.** Netlify and Vercel match case-sensitively, and agensio in any capitalisation (SR-20).
  - **The query.** Netlify passes it on, as agensio's `keep` does. Vercel's bulk redirects drop it
    unless `preserveQueryParams`.
  - **A rule over an existing file.** Netlify skips a rule whose `from` exists as a file unless
    it carries `!` (13.2 % of files use `!`). Cloudflare and Firebase always redirect, and so does
    agensio (step 4 runs before the locations). A Netlify file imported unchanged can therefore
    redirect pages that Netlify served.
- **Meta-refresh pages.** Hugo `aliases`, jekyll-redirect-from, Docusaurus client redirects,
  Astro without an adapter, mkdocs-redirects and hexo-generator-alias write HTML pages with a
  meta refresh, served with 200. These are pages, **X** (static files).
  - The server-side form is the same exact rules.
  - jekyll-redirect-from writes `redirects.json`, Hugo has a documented `_redirects` output
    format, and Astro's adapters write the host's file. The agent can turn these into
    `[[site.redirect]]` lists and check them with `path_check`'s preview.

### SR-10 A section moved, the rest of the path kept

- **Rules.** `/a/* /b/:splat`: `_redirects` 20.3 % (3,010 rules); `netlify.toml` 99 files;
  `vercel.json` 14 files (`/jp/:path*` → `/ja/:path*`); Astro `'/blog/[...slug]':
  '/articles/[...slug]'`.
- **Class E:**

  ```toml
  [[site.redirect]]
  from = "/news"
  to = "/blog"
  status = 301
  ```

- **E≈.** A splat glued to part of a segment (`/faq/codestructure*` →
  `/faq/code-structure:splat`, 18 files, 266 rules) is two rules here: an exact `.html` one and a
  whole-segment prefix. That is by design (whole segments only).

### SR-11 A section to one page

- **Rules.** `/a/* /b`: `_redirects` 6.8 %, `netlify.toml` 34, `vercel.json` 11.
- **Class E:** `remainder = "drop"`, and `query = "drop"` where wanted.

### SR-12 The captured rest placed inside the target

- **Rules.**
  - `_redirects`, 24 files (1.0 %), 52 rules:
    - `/*.txt /:splat.md 301` (Vite and its translations);
    - `/tags/*.html /tags/:splat/ 301`;
    - `/tiers/tiered/prestige-1/*.png /prestiges/brawlers/:splat/4.png`;
    - `/react-web-core/* /web-core/:splat?framework=react`.
  - A splat not at the end of `from`: 30 files (1.2 %, 321 rules), e.g. `/*/readme.html /:splat`.
  - `vercel.json`: about 32 files (2.7 %) with a parameter inside the target or a regex, e.g.
    `/kb/guides/:path+.md` → `/kb/markdown/guides/:path+.md`.
  - `firebase.json`: 8 regex files.
- **Class N, low frequency.** The design's candidate (one `*` within one segment, redirects.md
  5.4) covers the last-segment cases (`/*.html` → `/*`, `/tags/*.html` → `/tags/*/`, `.txt` →
  `.md`). It does not cover multi-segment captures (`/*/readme.html`) or a fixed query added
  after the rest. The latter would be a prefix rule with `to = "/web-core?framework=react"`, but
  redirects.md 5.3 states the join of a remainder only for a target without a query (and 5.2 shows
  a target query on an exact rule only). Whether the remainder goes before the target's `?` is
  unstated; it should be (section 7, change 9).

### SR-13 Named placeholders (`/:lang/x`, `/:year/:month/:slug`)

- **Frequency.** `_redirects` 79 files (3.1 %, 1,780 rules); `netlify.toml` 8; `vercel.json` a
  few. The 79 files split as follows:
  - **22 files: trailing placeholders carried to the end.** These are prefix rules: **E**.
  - **26 files (461 rules, mostly MUI's docs): a placeholder in the first segment, carried.**
    For example `/:lang/api/grid-list/ /:lang/material-ui/api/image-list/`.
    - **E≈** by writing one rule per language.
    - That multiplies the rules by the number of languages; MUI's would pass the 1,000 cap.
  - **29 files: segments reordered, dropped or embedded.** For example
    `/web/:year/:month/:day/* /web/:splat` and `/base-ui/api/:component/
    /base-ui/react-:component/components-api/#:component`. **N**: no capture in the design.
- **Recommendation.** Keep it out of the first step. The one-segment `*` is the candidate if the
  language case returns.

### SR-14 Query parameters in `from`

- **Fixed values** (3 `_redirects` files): `/info/refs service=git-upload-pack
  https://github.com/...`. **E**, an exact rule with its query.
- **Captured and renamed into the path** (15 files, 0.6 %): `/store id=:id /blog/:id`; Amplify's
  `/docs?id=<my-blog-id-value>`. **N**, rare.
- **Captured under the same name:** `/search q=:q /blog?q=:q`. **E**: `from = "/search"`,
  `to = "/blog"` with the query kept.

### SR-15 Domains: `www`, old domain to new, HTTP to HTTPS

- **Rules.**
  - `https://www.probelabs.com/* https://probelabs.com/:splat 301`.
  - `https://yihui.netlify.app/* https://yihui.org/:splat 301!` (the platform's default name to
    the real one).
  - `http://blog.yoursite.com/* https://www.yoursite.com/blog/:splat 301!` (Netlify's docs).
- **Frequency.** `_redirects` 10.1 %; `netlify.toml` 76 files; `vercel.json` `has: host` in 11
  files.
- **Class E.** `canonical` and `http` for names of one site; a redirect-only site for an old
  domain (redirects.md 6.1); a host that becomes a path is a redirect-only site with a `to` that
  carries the path:

  ```toml
  [[site]]
  server_name = ["probelabs.com", "www.probelabs.com"]
  canonical = "probelabs.com"            # 308, where the file wrote 301: both permanent (E≈)
  ```

- **Related: host-specific header rules** (3.3 % of `_headers`). Most exist because Cloudflare
  Pages has no domain-level redirect. kosko sends `Refresh: 0; url=https://kosko.dev/:splat` on
  `https://kosko.pages.dev/*`. With `canonical`, agensio needs neither.

### SR-16 Proxying a path to another host (200 to an external URL)

- **Rules.**
  - `/api/* https://api.example.com/:splat 200` (Netlify's docs).
  - `/_sukka/api/* https://api.cloudflare.com/:splat 200`.
  - Plausible's `/api/event`.
- **Frequency.** `_redirects` 3.8 %, 651 rules; `netlify.toml` 57 files; `vercel.json` 37 files.
- **Class X, with a gap.** A proxy location does this, with the prefix dropped:

  ```toml
  [[site.location]]
  path = "/api/"
  upstream = "https://203.0.113.10/"                              # an IP literal: see below
  proxy = { host = "api.example.com", tls = { server_name = "api.example.com" } }
  ```

  But `parse_upstream_address` refuses a host name. Quote (`src/upstream/client.cpp`): "upstream
  host must be an IP literal (names are resolved in a later phase)".
  - Every external target in the corpus is a name (Heroku, `api.cloudflare.com`, `plausible.io`,
    workers.dev), mostly behind CDNs whose addresses change.
  - So this is **X-gap** until upstream names are resolved (section 7, change 6).

### SR-17 Rewrites to functions

- **Rules.** `/api/* /.netlify/functions/:splat 200` (70 `netlify.toml` files); Vercel `/api` (64
  files); Firebase `"function"` and `"run"` (74 files, 11.5 %).
- **Class X.** The function is an application: `app = "node"`, `"proxy"` or another preset, with
  a proxy location. Nothing static.

### SR-18 An internal rewrite of one path

- **Rules.** `/install /install.sh 200`, `/auth /index.html 200`: `_redirects` 6.6 %;
  `vercel.json` 46 files; Azure `rewrite` in 18 files.
- **Class X: an exact location whose `try_files` is only a fallback.**

  ```toml
  [[site.location]]
  path = "/install"
  match = "exact"
  try_files = ["/install.sh"]
  ```

  `/install.sh` is then sent as `application/octet-stream` (SH-8).
- **With a capture into the target file** (`/glossary/:page` → `/hubs/glossary/:page.html` on
  Vercel): X-gap today. It becomes `alias` plus the `$uri.html` step of SR-5:

  ```toml
  [[site.location]]
  path = "/glossary/"
  alias = "/var/www/site/hubs/glossary/"
  try_files = ["$uri", "$uri.html", "=404"]    # $uri.html proposed
  ```

### SR-19 Conditions: language, country, role, cookie, request header

- **Language** (`Language=`): `_redirects` 11 files (0.4 %, 86 rules).
  - Six of the sixteen tools ask the server for `Accept-Language`: Angular (nginx and Apache
    configurations), Eleventy, VitePress, Docusaurus ("best done on the server"), Gatsby
    (`createRedirect` conditions), and Next.js export (unsupported, so left to the server).
- **Country.**
  - `_redirects`: 2 files, one of them `/* /access-denied 403! Country=cu,ir,kp,...`.
  - `netlify.toml`: 6 files (Netlify's own demo; a 451 page for sanctioned countries).
  - Gatsby `createRedirect`.
- **Role and cookie.** 0 in `_redirects`. Azure `allowedRoles` in 22 files (Azure's own
  login).
- **Request header.** An `Accept: text/markdown` test that hands agents a `.md` twin: 1
  `_redirects` file (303), 4 `vercel.json` files.
- **Class O** (redirects.md 5.4: "the application's job"; headers.md 3.8).
  - **The reason does not fit static sites**, where no application exists and six generators ask
    the server.
  - What the owner does today with agensio:
    - an exact rule `from = "/"` to the default language (302);
    - the generator's language switcher, or a script in the root page;
    - geo-blocking at the firewall or a CDN, since agensio has no country data;
    - roles through `[[site.auth]]`;
    - a `Link: <...md>; rel="alternate"` field (SH-11) instead of negotiation.
  - If reopened, the smallest form is root-only: `/` by `Accept-Language` to one of a fixed list
    of prefixes.
    - It must be a 302, carry `Vary: Accept-Language`, never be cached, and honour the
      `?persistLocale` style choice.
    - Angular's own nginx example gets this wrong with a `permanent` redirect and no `Vary`.

### SR-20 Case-only redirects

- **Rules.** 13 `_redirects` files (0.5 %), 178 rules, all exact rules or placeholders. For
  example:
  - `/iOS/quickstart /ios/quickstart 301` (dyte docs);
  - `/PUWTPD /puwtpd`;
  - `/mesh/:version/policies/MeshAccessLog/` → `.../meshaccesslog/` (Kong).

  The prefix form exists too: `/docs/zh-hans/*   /docs/zh-Hans/:splat   301`
  ([airi](https://github.com/moeru-ai/airi/blob/eec7f4933c72354362aff3a8592456715e71c609/apps/stage-web/public/_redirects)).
- **Why they work elsewhere.** Netlify ("Paths are case-sensitive") and Vercel ("URLs are
  case-sensitive") match case-sensitively. These rules are how a site fixes old mixed-case links
  to a filesystem that serves names case-sensitively.
- **Class N.** agensio matches a `from` in any capitalisation and refuses `/About` to `/about` as
  a loop (redirects.md 8). The rule cannot be written, and the old link keeps answering 404,
  because the file lookup is case-sensitive.
  - Smallest change: redirect rules compare `from` case-sensitively. Every platform does, and the
    prefix form above needs it as well as exact rules. Access rules need case-folding (a refusal
    must not be dodged by spelling); a redirect has no such reason. The loop check then refuses
    only a `to` that its own `from` matches byte for byte.

### SR-21 Rule order, and how many rules

- **Order.** Every platform takes the first match in file order.
  - 34 `_redirects` files (3.4 % of those with two or more rules) put a broader splat before a
    narrower rule it covers. On the platform the narrower rule never fires; under agensio's "most
    specific decides" it does. For example `/*  /index.html  200` before `/samples
    https://github.com/stripe-samples 301` (stripe.github.io), and `/concepts/*` before
    `/concepts/overview` (keda-docs).
  - Usually the narrower rule is what the author meant. The design already makes the agent's
    texts say so (redirects.md 11.2).
- **Volume.**
  - 7 of 2,585 `_redirects` files (0.3 %) exceed 1,000 rules; 17 exceed 500.
  - Platform limits: Cloudflare 2,000 static plus 100 dynamic; Vercel 2,048 per array, bulk up to
    1,000,000.
  - **E** with the 1,000 cap for 99.7 %; the data file of redirects.md 6.3 for the rest.

### SR-22 Statuses beyond the redirects

- **Rules.**
  - `410` (1 file, `/author/* /410.html 410`): **E** (`status = 410`). The custom 410 page is
    SR-4's mechanism.
  - A 404 for one path (`/.env / 404`, 9 files): **X**, `refuse` or a `deny` location.
  - `403` and `451` by country: **O** (SR-19).
  - `303` with an `Accept` condition: **O** (redirects.md 5.4).
  - `307` (13 files) and `308` (18): **E**.

### SH-1 The security fields on every answer

- **Rules.**
  - `_headers` at `/*`: 222 files (36.4 %).
  - `netlify.toml` `for = "/*"`: 190 files.
  - `vercel.json` `/(.*)`: 114 files.
  - Azure `globalHeaders`: 42 files.
  - Every Amplify file.
- **What the tools ask.**
  - Gatsby's defaults: `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `nosniff`,
    `Referrer-Policy: same-origin`.
  - VitePress's nginx: `nosniff`, `SAMEORIGIN`, `strict-origin-when-cross-origin`.
  - Cloudflare Pages sends `nosniff` and `Referrer-Policy: strict-origin-when-cross-origin` on
    every answer by default, the same pair as agensio's `static` baseline (headers.md 4.2).
- **Field frequencies** in `_headers`:
  - `X-Content-Type-Options` 32.5 %;
  - `Referrer-Policy` 28.2 %;
  - `X-Frame-Options` 27.0 %;
  - CSP 17.9 %;
  - `Permissions-Policy` 17.5 %;
  - HSTS 10.8 %;
  - `X-XSS-Protection` 10.8 %.
- **Class E:**

  ```toml
  [[site]]
  app = "static"                      # baseline: Referrer-Policy and nosniff
  hsts = true                         # the HSTS of 10.8 % of the files

  [[site.response_headers]]
  path = "/"
  set = { "X-Frame-Options" = "DENY", "Permissions-Policy" = "camera=(), microphone=(), geolocation=()" }
  ```

  `X-XSS-Protection: 1; mode=block` (Gatsby's default and 10.8 % of the files) gets the design's
  warning. HSTS with `preload` (passkeys.dev) is **O** (redirects.md 4.6).

### SH-2 A year of `immutable` on the fingerprinted directories

- **Directories.** `/assets/` (Vite, VitePress, React Router, Docusaurus, Material), `/_next/static/`,
  `/_astro/`, `/_nuxt/`, `/_app/immutable/`, `/static/` (Gatsby).
- **Frequency.** `_headers`: 283 files (46.4 %), 410 lines. `public, max-age=31536000, immutable`
  is the commonest value of all (456 lines).
- **Class E:**

  ```toml
  [[site.response_headers]]
  path = "/assets/"
  when = "success"
  set = { "Cache-Control" = "public, max-age=31536000, immutable" }

  [[site.response_headers]]          # Nuxt: the version manifest inside the hashed directory
  path = "/_nuxt/builds/latest.json"
  match = "exact"
  set = { "Cache-Control" = "no-cache" }
  ```

  The longest rule decides per field, so the manifest is exempt. On Cloudflare the two values
  would be joined.
- **Managed sites: a small gap.** `rules.cache` renders `public, max-age=N` without `immutable`
  (`src/control/sites.cpp`). The cookbook sends `immutable` to a root additions file. The planned
  managed `response_headers` covers it; so would an `immutable` flag on `rules.cache` (section 7,
  change 8).
- **The SPA hazard of SR-2** applies here.

### SH-3 Lifetimes by file ending

- **Rules.**
  - `/*.js`, `/*.css`, `/*.woff2`, `**/*.@(js|css)`, `/(.*)\.(css|js)`.
  - `_headers`: 54 files (8.9 %) give a long lifetime by extension; 137 (22.5 %) use an
    extension glob for some field.
  - `netlify.toml`: 39 of 303 header files (12.9 %), Hugo's own docs site among them.
  - `vercel.json`: 41 files.
  - `firebase.json`: 56 files (8.7 %), the commonest header style there, as in Firebase's docs
    example.
  - Azure: 121 (template-heavy).
- **Tools.**
  - Gatsby's scheme needs it: hashed JS and CSS at the root, immutable, with `/sw.js` excepted.
  - Hugo's fingerprinted files sit beside unhashed ones; `hugo deploy` caches by regex.
  - Angular writes `chunk-HASH.js` at the root of `browser/`.
- **Extensions** in `_headers` globs, by files: `js` 55, `css` 41, `png` 27, `svg` 22, `html` 22,
  `woff2` 14.
- **Class N.** Rules match paths, prefix or exact. This corroborates `php_apps.md` change 1
  (`endings`, with exact before endings before a plain prefix at equal path):

  ```toml
  [[site.response_headers]]
  path = "/"
  endings = [".js", ".css"]                   # proposed
  when = "success"
  set = { "Cache-Control" = "public, max-age=31536000, immutable" }

  [[site.response_headers]]
  path = "/sw.js"
  match = "exact"
  set = { "Cache-Control" = "no-cache" }
  ```

- **No "hashed name" test instead.** The names of section 3.1 are too varied: dash or dot, base64url
  or hex, 8 to 64 characters, a hash before `.min.js`. The Django preset's `content_hashed()`
  would recognise two of the eleven tools.

### SH-4 `no-cache` on the HTML

- **Rules.**
  - In `_headers`: `/*` 53 lines, `/index.html` 38, `/` 18. 74 files (12.1 %) set a
    revalidate-style lifetime on an HTML path, 41 of them (6.7 %) together with a long-lived
    directory.
  - Gatsby: HTML, `page-data/` and `app-data.json` `public, max-age=0, must-revalidate`.
  - Vite: "set `Cache-Control: no-cache` on the HTML file".
  - VitePress: `default "no-cache"`.
  - Netlify and Cloudflare send `public, max-age=0, must-revalidate` on every file by default.
- **agensio's default.** No `Cache-Control` on files. A browser may then reuse a page without
  asking for a while computed from its `Last-Modified` (heuristic freshness, RFC 9111 4.2.2). After
  a deploy, that page can still reference hashed assets that no longer exist, which is Vite's
  warning.
- **Class E with one rule at `/`.** The deeper `/assets/` rule wins there:

  ```toml
  [[site.response_headers]]
  path = "/"
  set = { "Cache-Control" = "no-cache" }        # accepted with when = "always" (headers.md 2.4)
  ```

  Images and other unhashed files at the root then revalidate too, which is what Netlify and
  Cloudflare do anyway.
- **What a rule cannot say: "on HTML answers only".**
  - A `.html` ending (SH-3) misses `/about/`, served from `about/index.html`, and the SPA
    fallback. The Amplify docs' own `customHttp.yml` notes this.
  - Smallest change: a condition on what was served, either `type = "text/html"` (the answer's
    type) or the served file's ending. It is the companion of `php_apps.md` change 2
    (`when = "files"`).
  - Alternatively, `no-cache` on the HTML that agensio serves could join the `static` preset's
    baseline. It breaks no page (a revalidation costs a 304), and it is the default of the two
    largest static platforms (section 7, change 4).

### SH-5 Service worker, manifests, version files

- **Rules.** `/sw.js` (24 lines), `/service-worker.js`, `/registerSW.js`, `/manifest.webmanifest`,
  `ngsw-worker.js`, `/version.json`, Gatsby's `page-data/`, SvelteKit `/_app/version.json`, Nuxt's
  manifest.
- **Class E.** Exact rules, or a prefix for `/page-data/`.

### SH-6 CORS with a fixed value

- **Rules.**
  - `Access-Control-Allow-Origin` in `_headers`: 101 files (16.6 %). Mostly `*` on `/*` or
    `/fonts/*`, one origin on `/giscus/*`.
  - Firebase's fonts example.
  - `Access-Control-Allow-Methods` and `-Headers` in about 3.5 %.
  - Cloudflare Pages sends `*` by default.
- **Class E** (`set`, headers.md 3.3). Several origins or credentials are **O**, a typed `cors`
  later.

### SH-7 COOP and COEP for WebAssembly threads

- **Rules.** `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy:
  require-corp`: `_headers` 61 and 43 files (10.0 %, 7.0 %); `vercel.json` 28 lines; redux's
  tutorial pages on Netlify. ringbuf.js, ffmpeg-web and terraria-wasm need `SharedArrayBuffer`.
  No tool's docs ask.
- **Class E.** `set` at `/` or on the pages. Not for the baseline, since they break cross-origin
  embeds.

### SH-8 `Content-Type` where the name does not tell it

- **Frequency.**
  - `_headers`: 104 files (17.0 %), 290 lines. Most restate agensio's table (`.txt`, `.js`, `.css`,
    `.md`, `.json`, `.webmanifest`, `.wasm`); the real needs are below.
  - Azure `mimeTypes`: 37 files (13.8 %).
  - `vercel.json`: 78 lines.
  - Amplify docs: `application/linkset+json` for `/.well-known/api-catalog`.
- **The real needs.**
  - Extensionless files: `/.well-known/apple-app-site-association`, `api-catalog`,
    `openid-configuration`, the OAuth metadata, Next.js's `opengraph-image`.
  - Eleventy's warning: an extensionless permalink "will write to a file without a file
    extension. Your web browser may attempt to download the file… (unless you've done some extra
    work to set up your `Content-Type` headers correctly)".
  - Install scripts served as text (`.sh` and `.ps1` are `application/octet-stream` in agensio).
  - Feeds named `.xml` as `application/rss+xml`.
- **Class N (X-gap).** headers.md 2.5 refuses `Content-Type` and points to "the built-in type
  table (by file extension)", which no key changes (`src/mime.cpp`).
  - Smallest change: a site type table by ending and by exact path, prebuilt into the cache
    entry, so no request pays for it. It joins `php_apps.md` change 9 (a type entry with
    `Content-Encoding`).

    ```toml
    types = { ".sh" = "text/plain; charset=utf-8", "/.well-known/apple-app-site-association" = "application/json" }   # proposed
    ```

### SH-9 `X-Robots-Tag`

- **Rules.** `_headers` 51 files (8.4 %):
  - `noindex` on preview hosts (`https://:project.pages.dev/*`, which Cloudflare also adds by
    itself);
  - `noindex, follow` on legal pages and `.md` twins (iannuttall/seo).
- **Class E** for paths. A host-specific rule is **O**: rules belong to the site. Use `canonical`
  to send the other names away, or a separate staging site (headers.md 3.4).

### SH-10 `Link`

- **Rules.** `_headers` 23 files (3.8 %): sitemap, `llms.txt`, `rel="alternate"` to the `.md`
  twin, and `rel="canonical"` with `:splat` in the value. The Amplify docs carry one long `Link`
  with four links.
- **Class E** for one field value listing several links (RFC 8288 allows it). Appending at two
  levels is **O** in the first step (headers.md 3.8). A value built from the path
  (`<https://seoskill.dev/docs/:splat>`) is **O** (no variables).

### SH-11 Removing a field on some files

- **Rules.** `! Content-Security-Policy` on `/*.jpg` (Cloudflare's docs; 17 `_headers` files use
  `!`).
- **Class E** (`remove`) on a path. **N** on an ending, with SH-3.

### SH-12 Several matching rules on one answer

- **Rules.** 37 `_headers` files (6.1 %) set `Cache-Control` on `/*` and again on a narrower path.
  Cloudflare joins the values with a comma; Netlify's behaviour is not documented. Azure takes the
  route's value over the global one, and Firebase applies rules in order.
- **Class E.** The design's "per field, the longest rule decides" gives what these files mean.
  The import must not concatenate.

### SH-13 A Content-Security-Policy for static output

- **Rules.** 17.9 % of `_headers`.
- **Tools.**
  - Astro, SvelteKit and Angular put a hashed CSP in a `<meta>` tag, which cannot carry
    `frame-ancestors`, `report-uri` or `sandbox`.
  - Angular asks for those in a header that omits `script-src` and `default-src`.
  - Next.js export has no nonces.
- **Class E:**

  ```toml
  [[site.response_headers]]
  path = "/"
  set = { "Content-Security-Policy" = "frame-ancestors 'self'" }   # app = "static": set draws no warning (headers.md 7)
  ```

### SH-14 `Service-Worker-Allowed`

- **Rules.** `/* Service-Worker-Allowed: /`: 3 `_headers` files and 2 `vercel.json` files
  (0.5 %), for a worker script that sits under a directory and controls the whole site.
- **Class O** (headers.md 2.5: "reach beyond the site on a shared host… lifting a service
  worker's path limit").
  - The field only widens a worker's scope within the worker's own origin, and an agensio site
    owns its host names. The stated reason holds only where sites share a host by path, which
    agensio does not do.
  - The owner moves the worker script to `/` (the usual fix).
  - If the refusal is revisited: accept a path value on an exact rule.

### SH-15 Other fields

- **`Content-Disposition`** (inline for `.md` and `.sh`; attachment with a file name for a PDF), 3
  files: **E**.
- **`Vary: Accept`**, 1 file: **O** (a representation field, and it follows SR-19's
  negotiation).
- **`Content-Encoding: br` written by hand on `x2t.wasm.br`**, 1 file: **X** (agensio's
  pre-compressed twins do this).
- **`ETag` and `Last-Modified` with template placeholders**, 2 files: **O** (refused).
- **`Clear-Site-Data: "cache"`**, 1 file: **O** (refused).
- **The CDN fields** (`CDN-Cache-Control`, `Netlify-CDN-Cache-Control`,
  `Vercel-CDN-Cache-Control`), 2 to 12 files: **E** (not refused), but meaningless without that
  CDN in front.
- **`Basic-Auth`** (Netlify, paid) and Azure `allowedRoles`: **X** (`[[site.auth]]`).

## 6. Summary table

Frequency is the share of files of each corpus with at least one rule of the kind. "tools" counts
the sixteen generators and frameworks of section 3 whose documentation asks for it.

| id | need | evidence (frequency) | class |
|---|---|---|---|
| SR-1 | SPA fallback, 200 | `_redirects` 45.5 %; `netlify.toml` 57 %; `firebase.json` 56.5 %; `vercel.json` 13.4 %; Azure 84 %; 7 tools | X (`try_files`); X-gap on managed static sites (change 7) |
| SR-2 | assets kept out of the fallback | 39 `_redirects` files, Azure `exclude` 198, Amplify's documented regex | X (location `try_files = ["$uri", "=404"]`); `-t` check proposed for the `immutable` hazard |
| SR-3 | sub-path SPA | `_redirects` 3.3 %; Gatsby client-only routes | X (location `try_files`) |
| SR-4 | `404.html` with status 404 | 10 tools; every platform; explicit `_redirects` 3.6 %, Azure 13 % | N / X-gap (change 1) |
| SR-5 | `/x` from `x.html`, no redirect | 8 tools; every platform; `vercel` `cleanUrls` 7.2 %, `firebase` 5.9 % | N / X-gap (change 2) |
| SR-6 | `/x` from `x/index.html`, no 301 | 5 tools | E≈ (agensio 301s to `/x/`); N for no hop (change 2) |
| SR-7 | site-wide trailing-slash policy | `vercel` 6.4 %, `firebase` 3.1 %, Azure 16 files; `_redirects` 1.5 % by hand | O (redirects.md 5.4; reason weak for static) |
| SR-8 | `.html` / `/index.html` to the clean URL | `_redirects` 2.3 % exact + 0.4 % pattern; Vercel and Firebase `cleanUrls` | E per page; O site-wide (option in change 2) |
| SR-9 | exact migration redirects | `_redirects` 38.3 % (37,183 rules); `vercel` 85 files; `firebase` 26 | E (import caveats: default status, slash, case, shadowing) |
| SR-9b | meta-refresh pages from generators | Hugo, Jekyll, Docusaurus, Astro, MkDocs, Hexo, SvelteKit | X (files); E as exact rules after import |
| SR-10 | section moved, rest kept | `_redirects` 20.3 %; `netlify.toml` 99 files | E (prefix) |
| SR-10b | splat glued to part of a segment | `_redirects` 0.7 % | E≈ (two rules) |
| SR-11 | section to one page | `_redirects` 6.8 % | E (`remainder = "drop"`) |
| SR-12 | the rest placed inside the target | `_redirects` 1.0 % (+1.2 % splat mid-`from`); `vercel` ≈ 2.7 % | N (low; the one-segment `*`) |
| SR-13 | named placeholders | `_redirects` 3.1 % (of which 0.9 % prefix-equivalent) | E 0.9 %; E≈ per language 1.0 %; N 1.2 % |
| SR-14 | query in `from` | fixed 0.1 %, captured 0.6 % | E fixed, same-name capture; N renamed |
| SR-15 | `www`, old domain, HTTPS | `_redirects` 10.1 %; `netlify.toml` 76 files | E (`canonical`, `http`, redirect-only site) |
| SR-16 | proxy a path to another host | `_redirects` 3.8 %; `netlify.toml` 57; `vercel` 37 | X-gap (upstream needs an IP literal; change 6) |
| SR-17 | rewrite to functions | `netlify.toml` 70; `firebase` 11.5 %; `vercel` 64 | X (an application behind a proxy location) |
| SR-18 | internal rewrite of one path | `_redirects` 6.6 %; `vercel` 46; Azure 18 | X (exact location, `try_files` fallback); with a capture X-gap (changes 2 + `alias`) |
| SR-19 | language, country, role, header conditions | Language 0.4 %, Country 0.1 %, Role/Cookie 0 in `_redirects`; 6 tools ask for `Accept-Language` | O (reason weak for static sites) |
| SR-20 | case-only redirects | `_redirects` 0.5 % (178 rules) | N (case-sensitive `from`; change 9c) |
| SR-21 | first-match order; more than 1,000 rules | order-dependent 1.4 %; > 1,000 rules 0.3 % | E (most specific decides; the cap); data file later |
| SR-22 | 410, one-path 404, 303 | 410 1 file; 404 9 files | E (410); X (`refuse`); O (303) |
| SH-1 | security fields at `/` | `_headers` 36.4 %; `netlify.toml` 190 files; `vercel` 114; Gatsby and VitePress defaults | E (`response_headers`, `hsts`, `static` baseline) |
| SH-2 | `immutable` on hashed directories | `_headers` 46.4 %; 6 tools | E; managed gap (change 8); SPA hazard (SR-2) |
| SH-3 | lifetimes by ending | `_headers` 8.9 % (22.5 % any field); `firebase` 8.7 %; `netlify.toml` 12.9 %; Gatsby | N (change 3 = `php_apps.md` 1) |
| SH-4 | `no-cache` on HTML only | `_headers` 12.1 %; Vite, VitePress, Gatsby; Netlify and Cloudflare defaults | E at `/`; N for "HTML only" (change 4) |
| SH-5 | service worker, manifests | `/sw.js` 24 lines and others | E (exact) |
| SH-6 | CORS, one value | `_headers` 16.6 % | E; several origins O |
| SH-7 | COOP / COEP | `_headers` 10.0 % / 7.0 % | E |
| SH-8 | `Content-Type` for names without a telling extension | `_headers` 17.0 % (mostly redundant); Azure `mimeTypes` 13.8 %; Eleventy | N / X-gap (change 5) |
| SH-9 | `X-Robots-Tag` | `_headers` 8.4 % | E by path; O by host |
| SH-10 | `Link` | `_headers` 3.8 % | E one value; append and variables O |
| SH-11 | remove a field | `_headers` 2.8 % | E by path; N by ending (change 3) |
| SH-12 | several rules, one field | `_headers` 6.1 % | E (longest decides; do not concatenate on import) |
| SH-13 | CSP for static output | `_headers` 17.9 %; Astro, SvelteKit, Angular, Next.js | E |
| SH-14 | `Service-Worker-Allowed` | 0.5 % | O (reason weak: a site owns its origin) |
| SH-15 | `Content-Disposition`; CDN fields; `Vary`; `ETag`; `Basic-Auth` | ≤ 0.5 % each | E; E; O; O; X (`[[site.auth]]`) |

## 7. Design changes the evidence supports

Ordered by how common the need is. Changes 1, 2, 5 and 6 are outside the two designs (static
handler, `try_files`, type table, upstreams); they are listed because a static site cannot be
moved to agensio without them.

1. **A custom error page served with its status (`error_page`), per site and per location.**
   - **How common.** Ten of the sixteen tools generate a `404.html` and expect it with 404. Every
     platform serves it, and the corpus undercounts it: explicit rules in 3.6 % of `_redirects`
     files, 13 % of Azure configurations, 32 `netlify.toml` files.
   - **Today.** agensio has only its built-in page, and a `try_files` fallback to `/404.html`
     makes a soft 404.
   - **Smallest change.** `error_page = { 404 = "/404.html" }`: the static handler's 404 serves
     that file with status 404, and the built-in page stays when the file is missing. Per location
     for localised pages (`/fr/404.html`, Docusaurus and Hugo); `410` the same way (SR-22).
2. **`try_files` steps `$uri.html` and `$uri/index.html`** (a `$uri` with a fixed suffix).
   - **How common.**
     - Eight of the sixteen tools need `/x` served from `x.html`; it is the default output of
       Next.js export and SvelteKit.
     - Five need `/x` from `x/index.html` without a 301.
     - Every platform does both automatically.
     - Explicitly: `cleanUrls` in 7.2 % of `vercel.json` and 5.9 % of `firebase.json` files.
   - **Smallest change.** The two steps, which are the nginx lines Next.js and VitePress document.
     With `alias` they also cover the variable rewrites of SR-18.
   - **Option.** Vercel's and Firebase's single `cleanUrls` switch also 308s `x.html` to `x` for
     files that exist, so one page has one URL. That is the companion redirect redirects.md 5.4
     currently declines (`/index.html` to `/`). The evidence is 2.3 % of `_redirects` files
     writing such pairs by hand, plus every platform pairing it.
3. **An ending condition on `[[site.response_headers]]`** (`endings = [".js", ".css"]`), with
   exact before endings before a plain prefix at equal path. This is `php_apps.md` change 1,
   which this evidence corroborates.
   - **How common.**
     - Long lifetimes by extension in 8.9 % of `_headers` files; 22.5 % use an extension glob for
       some field.
     - 8.7 % of `firebase.json` files (the commonest header style there, following Firebase's
       docs).
     - 12.9 % of `netlify.toml` header files.
   - **Who needs it.** Gatsby's documented scheme (root JS and CSS immutable, `/sw.js` excepted)
     needs it, and so do Angular's root `chunk-HASH.js` and Hugo's fingerprints beside unhashed
     files.
   - **Not a "hashed name" test**: two of eleven tools' names would match agensio's existing one.
4. **"HTML answers" as a condition, or `no-cache` on HTML in the `static` baseline.**
   - **How common.**
     - 12.1 % of `_headers` files set a revalidate-style lifetime on HTML paths.
     - Vite, VitePress and Gatsby ask for it.
     - Netlify and Cloudflare send `public, max-age=0, must-revalidate` by default.
     - agensio sends no `Cache-Control`, so browsers apply heuristic freshness.
   - **Why an ending is not enough.** A `.html` ending misses `/about/` and the SPA shell, as the
     Amplify docs' own file explains.
   - **Smallest change.** Either a rule condition on the answer's type (`type = "text/html"`), the
     companion of `php_apps.md` change 2 (`when = "files"`), or `Cache-Control: no-cache` added
     by the `static` baseline to HTML answers agensio serves. The baseline option meets its bar
     ("nothing in it can break a page"); its cost is a 304 per navigation.
5. **A site type table** (`types` by ending and by exact path) instead of the refused
   `Content-Type`.
   - **How common.** 17 % of `_headers` files set `Content-Type`, mostly redundantly, and 13.8 %
     of Azure files use `mimeTypes`. The needs no extension table can meet: extensionless
     `.well-known` files (Apple app links, `api-catalog`, OAuth and OIDC metadata), Eleventy's
     extensionless permalinks, install scripts as text, feeds named `.xml`.
   - **Today.** headers.md 2.5 points to "the built-in type table", which nothing configures
     (`src/mime.cpp`); CLAUDE.md's "overridable from config" is not true of the code.
   - Joins `php_apps.md` change 9.
6. **Host names in `upstream`** (outside the designs; recorded because `/api/* https://... 200` is
   a static-site idiom).
   - **How common.** 3.8 % of `_redirects` files, 57 `netlify.toml` and 37 `vercel.json` files
     proxy a path to another host, always by name (Heroku, `api.cloudflare.com`, `plausible.io`).
   - **Today.** agensio refuses a name: "upstream host must be an IP literal (names are resolved
     in a later phase)".
7. **The SPA fallback on managed static sites.** `rules.front_controller` is PHP-only, so the
   commonest single rule of all (45.5 % of `_redirects`, 56.5 % of `firebase.json`) needs a root
   additions file on a managed `app = "static"` site.
   - **Smallest change.** Accept `rules.front_controller` naming an `.html` file there, rendered
     as the same `try_files` line, plus an exclusion for an assets directory (SR-2).
8. **`immutable` from managed rules.** `public, max-age=31536000, immutable` is the commonest
   `Cache-Control` value in the corpus (456 lines). `rules.cache` cannot produce it.
   - **Smallest change.** The planned managed `response_headers` covers it, or an `immutable`
     flag on `rules.cache`.
9. **Clarifications to redirects.md, no new feature:**
   - **a. Redirects match only the client's path.** They are never judged on a `try_files`
     target or a directory's index. 28 `_redirects` files redirect `/index.html` to `/`; judged
     on the fallback hop, that would break every SPA (SR-1).
   - **b. Whether an exact `from = "/old"` also matches `/old/`.** Netlify matches both; 33
     `_redirects` files write slash pairs explicitly.
   - **c. Redirect rules compare `from` case-sensitively** (SR-20: 0.5 % of files, 178 rules,
     impossible today; exact and prefix alike). Every platform matches paths case-sensitively.
   - **d. The agent's import texts.**
     - agensio's rules always apply, as Netlify's `!` does. A Netlify rule without `!` whose
       `from` exists as a file is skipped there, so check with `path_check` before applying.
     - The same `_redirects` line without a status is 301 on Netlify, 302 on Cloudflare and 308
       on Vercel (13.4 % of files omit it).
     - Header values a platform concatenated are one field here, with the longest rule deciding.
   - **e. A `-t` warning** when a freshness-granting rule covers a prefix that a `try_files`
     fallback to another path can answer (SR-2: the shell would be cached as an asset for a
     year).
   - **f. Where the remainder goes when `to` has its own query.** A prefix rule with
     `to = "/web-core?framework=react"` (SR-12) should put the remainder before the `?`;
     redirects.md 5.3 does not say.
10. **One `*` capture placed in the target (redirects.md 5.4's candidate): keep it as a later
    step.**
    - **How common.**
      - The rest placed inside the target: 1.0 % of `_redirects` files.
      - A splat in the middle of `from`: 1.2 %.
      - Placeholders that are not prefix-equivalent: 2.2 %, half of them one language prefix in
        the first segment.
      - About 2.7 % of `vercel.json` files.
    - **What one segment covers.** A one-segment `*` covers the commonest of these (`/*.html` →
      `/*`, `/tags/*.html` → `/tags/*/`, `.txt` → `.md`), not multi-segment captures. The
      evidence does not make it a first-step need.

Not supported by the evidence, or kept out on purpose with a weak stated reason:
- **Language and country conditions.**
  - In files: 0.4 % and 0.1 % of `_redirects`.
  - But six of the sixteen tools' docs ask the server for `Accept-Language`, and redirects.md
    5.4's reason ("the application's job") does not apply to static sites.
  - If reopened: a root-only language redirect, 302, `Vary: Accept-Language`, never cached.
- **Role and cookie conditions:** none in `_redirects`. Azure's roles map to `[[site.auth]]`.
- **Request-header conditions** (the `Accept: text/markdown` twins for agents): about 5 files. A
  `Link: rel="alternate"` field does the job without negotiation.
- **Host-specific header rules:** 3.3 %, all preview or platform names, which `canonical`
  removes.
- **A site-wide trailing-slash policy:** about 5 % of Vercel and Firebase files. agensio's default
  (a 301 to the slash for directories) is what the commonest generator layouts and GitHub Pages
  expect. redirects.md 5.4's reason is weak for static sites, but the need is small once change 2
  exists.
- **`Service-Worker-Allowed`:** 0.5 %. The refusal's stated reason (a shared host) does not hold
  where a site owns its host names; low priority.
- **Appending a second `Link` or CSP, variables in values, CORS lists:** under 4 % each, already
  deferred by headers.md 3.3 and 3.8.

## 8. Not verified

- **Netlify:**
  - whether `:splat` may sit inside `to` (real files do it and evidently work);
  - whether 410 is supported;
  - how two different matching `_headers` rules combine;
  - whether the automatic `404.html` is sent with status 404 (implied by the docs);
  - whether a `/assets/*` header rule applies to a response rewritten to `/index.html` (SR-2).
- **Cloudflare Pages:** the status of the automatic `.html` to clean redirect (Workers document 307).
- **Vercel:**
  - how several matching header rules combine;
  - the full order of headers, redirects, the filesystem and rewrites, which the docs show only as
    an image.
- **Render:** default headers, and the automatic `404.html`.
- **Azure:**
  - the status sent with a `responseOverrides` 404 rewrite;
  - default headers.
- **GitHub Pages:**
  - the 404 status and `max-age=600`, which were observed with `curl`, not documented;
  - serving `/about` from `about.html`, which VitePress's docs assert ("Netlify and GitHub Pages
    support this by default"), not GitHub's.
- **Tools:**
  - Hexo's and Angular's prerendered output layouts;
  - the file names of Next.js's static RSC payloads;
  - Nuxt's static handling of `routeRules` redirects;
  - the `Content-Type` React Router's `.data` files need;
  - SvelteKit's `/_app/version.json` and Nuxt's `/_nuxt/builds/latest.json`, which were seen on
    the live sites, not in the docs.
- **The corpus:**
  - Sourcegraph's index and limits make every count a lower bound from a sample;
  - the `_headers` line search returned 617 of at least 1,907 indexed files, so the sample may
    lean towards whatever the engine returned first;
  - the `_redirects` and `_headers` join of SR-2 covers only directories present in both samples;
  - classification is by pattern and may misfile unusual lines, for example template lines in
    Liquid-generated files.
- **agensio:** that a location with `try_files` made only of a fallback path behaves as an
  internal rewrite (SR-18) was read in `parse_try_files` and `try_files_lookup`, not run.
