// The CPUs this process may run on: the affinity mask on Linux (a container's cpuset, a
// taskset), every hardware thread elsewhere. `workers = 0` means one worker per CPU here,
// so a pinned container gets the count of its cores rather than the machine's (nginx's
// worker_processes auto does the same). Read once at start.
#pragma once

#include <thread>

#ifdef __linux__
#include <sched.h>
#endif

namespace agensio {

inline unsigned available_cpus() noexcept {
#ifdef __linux__
    cpu_set_t set;
    CPU_ZERO(&set);
    if (::sched_getaffinity(0, sizeof set, &set) == 0) {
        const int n = CPU_COUNT(&set);
        if (n > 0) return static_cast<unsigned>(n);
    }
#endif
    const unsigned n = std::thread::hardware_concurrency();
    return n ? n : 1;
}

}  // namespace agensio
