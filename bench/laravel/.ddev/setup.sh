#!/usr/bin/env bash
# Creates (once) the Laravel test bed as a ddev project and adds the routes the tests use.
# Needs ddev with Docker. Idempotent: rerun after a `ddev delete` or to refresh the routes.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -f .ddev/config.yaml ]; then
  ddev config --project-type=laravel --docroot=public --project-name=agensio-laravel --php-version=8.3 \
    --disable-settings-management
fi
ddev start -y
if [ ! -f artisan ]; then
  ddev composer create-project "laravel/laravel:^12" . --no-interaction
fi
# Sessions in the cookie and the cache on files instead of the sqlite database. With the
# database driver every request writes the session table and sqlite serialises the
# writers (eight php-fpm children manage 170 req/s at 3 ms of CPU each); with the file
# driver every benchmark request leaves a session file behind and Laravel's garbage
# collection triples the CPU per request once there are tens of thousands (bench.sh, C5).
sed -i -e 's/^SESSION_DRIVER=\(database\|file\)$/SESSION_DRIVER=cookie/' -e 's/^CACHE_STORE=database$/CACHE_STORE=file/' .env
# Test routes: JSON, a POST echo (CSRF-exempt) and a file upload.
if ! grep -q 'agensio test routes' routes/web.php; then
  cat >> routes/web.php <<'PHP'

// agensio test routes (bench/laravel/.ddev/setup.sh)
Route::get('/json', fn () => response()->json(['ok' => true, 'method' => request()->method()]));
Route::post('/echo', fn (\Illuminate\Http\Request $r) => response()->json([
    'a' => $r->input('a'),
    'file' => $r->hasFile('f') ? $r->file('f')->getSize() : null,
    'ip' => $r->ip(),
    'https' => $r->secure(),
]))->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class);
Route::get('/info', fn () => response()->json([
    'uri' => request()->getRequestUri(),
    'script' => $_SERVER['SCRIPT_FILENAME'] ?? null,
    'root' => $_SERVER['DOCUMENT_ROOT'] ?? null,
]));
PHP
fi
ddev exec php artisan optimize:clear >/dev/null
echo "ready: php-fpm on 127.0.0.1:9000 (published), run: build/agensio -c bench/laravel/.ddev/agensio.toml"
