#include "slug_allocator.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <unistd.h>

namespace
{

constexpr uint8_t kCxlOpRead = 0;
constexpr uint8_t kCxlOpWrite = 1;

struct __attribute__((packed)) CxlServerRequest {
	uint8_t op_type;
	uint64_t addr;
	uint64_t size;
	uint64_t timestamp;
	uint64_t value;
	uint64_t expected;
	uint8_t data[64];
};

struct __attribute__((packed)) CxlServerResponse {
	uint8_t status;
	uint64_t latency_ns;
	uint64_t old_value;
	uint8_t data[64];
};

struct SlugConfig {
	bool verbose = false;
	bool stats = true;
	bool trace_all = true;
	bool cxl_enabled = false;
	bool cxl_send_writes = true;
	std::string trace_path;
	std::string cxl_host = "127.0.0.1";
	int cxl_port = 0;
	uint64_t region_base = 0;
	uint64_t region_size = 0;
	uint64_t cxl_addr_base = 0;
};

struct ThreadState {
	uint32_t function_id = 0;
	uint32_t basic_block_id = 0;
	const char *function_name = nullptr;
	bool in_runtime = false;
	int cxl_fd = -1;

	~ThreadState()
	{
		if (cxl_fd >= 0)
			::close(cxl_fd);
	}
};

struct SlugRuntime {
	SlugConfig cfg;
	std::atomic<uint64_t> bb_entries{ 0 };
	std::atomic<uint64_t> loads{ 0 };
	std::atomic<uint64_t> stores{ 0 };
	std::atomic<uint64_t> atomics{ 0 };
	std::atomic<uint64_t> bytes_read{ 0 };
	std::atomic<uint64_t> bytes_written{ 0 };
	std::atomic<uint64_t> cxl_ops{ 0 };
	std::atomic<uint64_t> cxl_failures{ 0 };
	std::mutex io_mutex;
	FILE *trace = nullptr;
};

thread_local ThreadState tls;
SlugRuntime runtime;

uint64_t now_ns()
{
	using clock = std::chrono::steady_clock;
	return static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::nanoseconds>(
			clock::now().time_since_epoch())
			.count());
}

uint64_t thread_id()
{
#if defined(__APPLE__)
	uint64_t tid = 0;
	pthread_threadid_np(nullptr, &tid);
	return tid;
#elif defined(__linux__)
	return static_cast<uint64_t>(::syscall(SYS_gettid));
#else
	return std::hash<std::thread::id>{}(std::this_thread::get_id());
#endif
}

bool parse_bool_env(const char *name, bool fallback)
{
	const char *value = std::getenv(name);
	if (!value)
		return fallback;
	return std::strcmp(value, "1") == 0 ||
	       std::strcmp(value, "true") == 0 ||
	       std::strcmp(value, "TRUE") == 0 ||
	       std::strcmp(value, "yes") == 0 || std::strcmp(value, "YES") == 0;
}

uint64_t parse_u64_env(const char *name, uint64_t fallback)
{
	const char *value = std::getenv(name);
	if (!value || !*value)
		return fallback;
	char *end = nullptr;
	errno = 0;
	uint64_t parsed = std::strtoull(value, &end, 0);
	if (errno != 0 || end == value)
		return fallback;
	return parsed;
}

std::string parse_str_env(const char *name, const std::string &fallback)
{
	const char *value = std::getenv(name);
	return value ? std::string(value) : fallback;
}

bool in_region(uint64_t addr, uint64_t size)
{
	const auto &cfg = runtime.cfg;
	if (cfg.region_size == 0)
		return true;
	if (size == 0)
		return false;
	if (addr < cfg.region_base)
		return false;
	uint64_t end = addr + size - 1;
	if (end < addr)
		return false;
	return end < cfg.region_base + cfg.region_size;
}

const char *kind_name(uint32_t kind)
{
	switch (kind) {
	case SLUG_ACCESS_LOAD:
		return "load";
	case SLUG_ACCESS_STORE:
		return "store";
	case SLUG_ACCESS_ATOMIC:
		return "atomic";
	case SLUG_ACCESS_MEMCPY_READ:
		return "memcpy_read";
	case SLUG_ACCESS_MEMCPY_WRITE:
		return "memcpy_write";
	case SLUG_ACCESS_MEMSET:
		return "memset";
	default:
		return "unknown";
	}
}

bool is_read_kind(uint32_t kind)
{
	return kind == SLUG_ACCESS_LOAD || kind == SLUG_ACCESS_ATOMIC ||
	       kind == SLUG_ACCESS_MEMCPY_READ;
}

bool is_write_kind(uint32_t kind)
{
	return kind == SLUG_ACCESS_STORE || kind == SLUG_ACCESS_ATOMIC ||
	       kind == SLUG_ACCESS_MEMCPY_WRITE || kind == SLUG_ACCESS_MEMSET;
}

uint64_t translate_cxl_addr(uint64_t addr)
{
	const auto &cfg = runtime.cfg;
	if (cfg.region_size == 0)
		return addr;
	return cfg.cxl_addr_base + (addr - cfg.region_base);
}

bool connect_cxl_for_thread()
{
	if (!runtime.cfg.cxl_enabled)
		return false;
	if (tls.cxl_fd >= 0)
		return true;

	int fd = ::socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		runtime.cxl_failures++;
		return false;
	}

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(static_cast<uint16_t>(runtime.cfg.cxl_port));
	if (::inet_pton(AF_INET, runtime.cfg.cxl_host.c_str(),
			&addr.sin_addr) != 1) {
		::close(fd);
		runtime.cxl_failures++;
		return false;
	}

	if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) !=
	    0) {
		::close(fd);
		runtime.cxl_failures++;
		return false;
	}

	tls.cxl_fd = fd;
	if (runtime.cfg.verbose) {
		std::fprintf(stderr,
			     "[SlugAllocator] thread %" PRIu64
			     " connected to CXLMemSim %s:%d\n",
			     thread_id(),
			     runtime.cfg.cxl_host.c_str(),
			     runtime.cfg.cxl_port);
	}
	return true;
}

bool send_all(int fd, const void *buf, size_t len)
{
	const auto *ptr = static_cast<const uint8_t *>(buf);
	while (len > 0) {
		ssize_t sent = ::send(fd, ptr, len, 0);
		if (sent <= 0)
			return false;
		ptr += sent;
		len -= static_cast<size_t>(sent);
	}
	return true;
}

bool recv_all(int fd, void *buf, size_t len)
{
	auto *ptr = static_cast<uint8_t *>(buf);
	while (len > 0) {
		ssize_t got = ::recv(fd, ptr, len, MSG_WAITALL);
		if (got <= 0)
			return false;
		ptr += got;
		len -= static_cast<size_t>(got);
	}
	return true;
}

void close_thread_cxl()
{
	if (tls.cxl_fd >= 0) {
		::close(tls.cxl_fd);
		tls.cxl_fd = -1;
	}
}

void send_cxl_access(uint64_t addr, uint64_t size, uint32_t kind)
{
	if (!runtime.cfg.cxl_enabled || size == 0)
		return;

	uint64_t remaining = size;
	uint64_t current = translate_cxl_addr(addr);
	uint64_t source_offset = 0;

	while (remaining > 0) {
		uint64_t offset = current & 63ULL;
		uint64_t chunk = 64 - offset;
		if (chunk > remaining)
			chunk = remaining;

		CxlServerRequest req{};
		req.op_type = is_write_kind(kind) && !is_read_kind(kind) ?
				      kCxlOpWrite :
				      kCxlOpRead;
		req.addr = current;
		req.size = chunk;
		req.timestamp = now_ns();

		if (req.op_type == kCxlOpWrite && runtime.cfg.cxl_send_writes) {
			const void *src = reinterpret_cast<const void *>(
				addr + source_offset);
			std::memcpy(req.data, src, static_cast<size_t>(chunk));
		}

		CxlServerResponse resp{};
		if (!connect_cxl_for_thread() ||
		    !send_all(tls.cxl_fd, &req, sizeof(req)) ||
		    !recv_all(tls.cxl_fd, &resp, sizeof(resp)) ||
		    resp.status != 0) {
			runtime.cxl_failures++;
			close_thread_cxl();
			return;
		}

		runtime.cxl_ops++;
		remaining -= chunk;
		current += chunk;
		source_offset += chunk;
	}
}

void load_config()
{
	runtime.cfg.verbose = parse_bool_env("SLUG_VERBOSE", false);
	runtime.cfg.stats = parse_bool_env("SLUG_STATS", true);
	runtime.cfg.trace_all = parse_bool_env("SLUG_TRACE_ALL", true);
	runtime.cfg.trace_path = parse_str_env("SLUG_TRACE", "");
	runtime.cfg.region_base = parse_u64_env(
		"SLUG_REGION_BASE", parse_u64_env("PGAS_BASE_ADDR", 0));
	runtime.cfg.region_size = parse_u64_env("SLUG_REGION_SIZE",
						parse_u64_env("PGAS_SIZE", 0));
	runtime.cfg.cxl_host = parse_str_env(
		"SLUG_CXL_HOST", parse_str_env("CXL_MEMSIM_HOST", "127.0.0.1"));
	runtime.cfg.cxl_port = static_cast<int>(parse_u64_env(
		"SLUG_CXL_PORT", parse_u64_env("CXL_MEMSIM_PORT", 0)));
	runtime.cfg.cxl_enabled = runtime.cfg.cxl_port > 0;
	runtime.cfg.cxl_send_writes =
		parse_bool_env("SLUG_CXL_SEND_WRITES", true);
	runtime.cfg.cxl_addr_base = parse_u64_env("SLUG_CXL_ADDR_BASE", 0);

	if (!runtime.cfg.trace_path.empty()) {
		runtime.trace = std::fopen(runtime.cfg.trace_path.c_str(), "w");
		if (runtime.trace) {
			std::fprintf(
				runtime.trace,
				"timestamp_ns,thread_id,function_id,basic_block_id,"
				"function,kind,addr,size\n");
		} else {
			std::fprintf(
				stderr,
				"[SlugAllocator] failed to open trace %s: %s\n",
				runtime.cfg.trace_path.c_str(),
				std::strerror(errno));
		}
	}

	if (runtime.cfg.verbose) {
		std::fprintf(stderr,
			     "[SlugAllocator] region=0x%" PRIx64 "+%" PRIu64
			     " trace=%s cxl=%s:%d\n",
			     runtime.cfg.region_base, runtime.cfg.region_size,
			     runtime.cfg.trace_path.empty() ?
				     "(off)" :
				     runtime.cfg.trace_path.c_str(),
			     runtime.cfg.cxl_enabled ?
				     runtime.cfg.cxl_host.c_str() :
				     "(off)",
			     runtime.cfg.cxl_port);
	}
}

void print_stats()
{
	if (!runtime.cfg.stats)
		return;
	std::fprintf(stderr, "\n=== SlugAllocator Statistics ===\n");
	std::fprintf(stderr, "BB entries:        %" PRIu64 "\n",
		     runtime.bb_entries.load());
	std::fprintf(stderr, "Loads:             %" PRIu64 "\n",
		     runtime.loads.load());
	std::fprintf(stderr, "Stores:            %" PRIu64 "\n",
		     runtime.stores.load());
	std::fprintf(stderr, "Atomics:           %" PRIu64 "\n",
		     runtime.atomics.load());
	std::fprintf(stderr, "Bytes read:        %" PRIu64 "\n",
		     runtime.bytes_read.load());
	std::fprintf(stderr, "Bytes written:     %" PRIu64 "\n",
		     runtime.bytes_written.load());
	std::fprintf(stderr, "CXLMemSim ops:     %" PRIu64 "\n",
		     runtime.cxl_ops.load());
	std::fprintf(stderr, "CXLMemSim failures:%" PRIu64 "\n",
		     runtime.cxl_failures.load());
	std::fprintf(stderr, "================================\n\n");
}

struct RuntimeLifecycle {
	RuntimeLifecycle()
	{
		load_config();
	}
	~RuntimeLifecycle()
	{
		__slug_flush();
		print_stats();
		close_thread_cxl();
		std::lock_guard<std::mutex> lock(runtime.io_mutex);
		if (runtime.trace) {
			std::fclose(runtime.trace);
			runtime.trace = nullptr;
		}
	}
};

RuntimeLifecycle lifecycle;

} // namespace

extern "C" void __slug_bb_enter(uint32_t function_id, uint32_t basic_block_id,
				uint32_t load_count, uint32_t store_count,
				const char *function_name)
{
	if (tls.in_runtime)
		return;
	tls.function_id = function_id;
	tls.basic_block_id = basic_block_id;
	tls.function_name = function_name;
	runtime.bb_entries++;
	(void)load_count;
	(void)store_count;
}

extern "C" void __slug_mem_access(const void *addr, uint64_t size,
				  uint32_t kind, uint32_t function_id,
				  uint32_t basic_block_id)
{
	if (tls.in_runtime || addr == nullptr || size == 0)
		return;

	tls.in_runtime = true;

	uint64_t address = reinterpret_cast<uint64_t>(addr);
	bool selected = in_region(address, size);

	if (selected || runtime.cfg.trace_all) {
		if (is_read_kind(kind)) {
			runtime.loads++;
			runtime.bytes_read += size;
		}
		if (is_write_kind(kind)) {
			runtime.stores++;
			runtime.bytes_written += size;
		}
		if (kind == SLUG_ACCESS_ATOMIC)
			runtime.atomics++;
	}

	if (runtime.trace && (selected || runtime.cfg.trace_all)) {
		std::lock_guard<std::mutex> lock(runtime.io_mutex);
		std::fprintf(runtime.trace,
			     "%" PRIu64 ",%" PRIu64 ",%u,%u,%s,%s,0x%" PRIx64
			     ",%" PRIu64 "\n",
			     now_ns(), thread_id(), function_id, basic_block_id,
			     tls.function_name ? tls.function_name : "",
			     kind_name(kind), address, size);
	}

	if (selected)
		send_cxl_access(address, size, kind);

	tls.in_runtime = false;
}

extern "C" void __slug_flush(void)
{
	std::lock_guard<std::mutex> lock(runtime.io_mutex);
	if (runtime.trace)
		std::fflush(runtime.trace);
}
