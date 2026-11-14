-- wrk script of the many-origins rows (bench/pingora/run.sh): every request names one of ORIGINS
-- hosts, "o<K>.test", drawn evenly, so the proxy talks to ORIGINS different origins. The requests
-- are built once; a thread's sequence depends only on its number, so both proxies see the same.
local n = tonumber(os.getenv("ORIGINS")) or 2000
local threads = 0
function setup(thread)
  threads = threads + 1
  thread:set("id", threads)
end
local reqs = {}
function init(args)
  math.randomseed(id * 7919)
  for k = 0, n - 1 do
    reqs[k + 1] = wrk.format("GET", "/json", { Host = "o" .. k .. ".test" })
  end
end
function request()
  return reqs[math.random(n)]
end
