-- wrk script of the mixed rows (bench/pingora/run.sh): what a proxy in front of an application
-- sees, in fixed shares. Of every 100 requests: 60 small JSON answers (an API), 20 pages of
-- 32 KB HTML, 10 answers of 100 KB, 5 slow answers (10 ms of application time) and 5 POSTs
-- with a 2 KB body echoed back. Built once; a thread's sequence depends only on its number.
local threads = 0
function setup(thread)
  threads = threads + 1
  thread:set("id", threads)
end
local reqs = {}
function init(args)
  math.randomseed(id * 104729)
  local body = string.rep("field=value&", 171):sub(1, 2048)
  local kinds = {
    { 60, wrk.format("GET", "/json") },
    { 20, wrk.format("GET", "/page") },
    { 10, wrk.format("GET", "/big") },
    { 5, wrk.format("GET", "/slow?ms=10") },
    { 5, wrk.format("POST", "/echo", { ["Content-Type"] = "application/octet-stream" }, body) },
  }
  for _, k in ipairs(kinds) do
    for _ = 1, k[1] do reqs[#reqs + 1] = k[2] end
  end
end
function request()
  return reqs[math.random(#reqs)]
end
