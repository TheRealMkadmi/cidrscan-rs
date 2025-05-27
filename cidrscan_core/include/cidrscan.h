#define FNV_OFFSET 14695981039346656037ull

#define FNV_PRIME 1099511628211

#define CACHE_LINE 64

#define TAG_MAX_LEN 32

#define DEFAULT_CAPACITY 1048576

#define HEADER_MAGIC 4848481594215973198

#define HEADER_VERSION 2

typedef enum ErrorCode {
  Success = 0,
  CapacityExceeded = 1,
  ZeroCapacity = 2,
  InvalidPrefix = 3,
  BranchHasChildren = 4,
  InvalidHandle = 5,
  Utf8Error = 6,
  LockInitFailed = 7,
  ShmemOpenFailed = 8,
  ResizeFailed = 9,
  FlushFailed = 10,
  TagTooLong = 11,
  NotFound = 12,
  Unknown = 255,
} ErrorCode;

/**
 * PatriciaTree struct (core handle)
 */
typedef struct PatriciaTree PatriciaTree;

/**
 * Signature for external collectors.
 */
typedef void (*StatsCallback)(const char *name, unsigned long long value);

typedef struct PatriciaTree *PatriciaHandle;

/**
 * C-ABI view of a successful lookup.
 */
typedef struct PatriciaMatchT {
  uint64_t key_high;
  uint64_t key_low;
  uint8_t plen;
  char tag[TAG_MAX_LEN];
} PatriciaMatchT;

enum ErrorCode patricia_last_error(void);

const char *patricia_strerror(enum ErrorCode code);

/**
 * Register a callback from C/other languages.
 */
void cidrscan_register_stats_callback(StatsCallback cb);

/**
 * Open or create a shared-memory arena and return an opaque handle.
 *
 * * `name_utf8` – logical name (process-wide); will be hashed to an OS-specific
 *                 identifier, so any UTF-8 string is fine.
 * * `capacity`  – maximum number of prefixes (nodes).
 *
 * Returns **NULL** on error – consult `cidr_last_error()`.
 */
PatriciaHandle cidr_open(const char *name_utf8, uintptr_t capacity);

/**
 * Close the handle (idempotent).  NULL is ignored.
 */
void cidr_close(PatriciaHandle h);

enum ErrorCode cidr_insert(PatriciaHandle h,
                           const char *cidr_utf8,
                           uint64_t ttl,
                           const char *tag_utf8);

enum ErrorCode cidr_delete(PatriciaHandle h, const char *cidr_utf8);

bool cidr_lookup(PatriciaHandle h, const char *addr_utf8);

enum ErrorCode cidr_lookup_full(PatriciaHandle h,
                                const char *addr_utf8,
                                struct PatriciaMatchT *out);

uint64_t cidr_available_capacity(PatriciaHandle h);

enum ErrorCode cidr_flush(PatriciaHandle h);

enum ErrorCode cidr_clear(PatriciaHandle h);

enum ErrorCode cidr_resize(PatriciaHandle h, uintptr_t new_capacity);

enum ErrorCode cidr_last_error(void);

const char *cidr_strerror(enum ErrorCode code);
