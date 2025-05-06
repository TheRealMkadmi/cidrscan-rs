#define FNV_OFFSET 14695981039346656037ull

#define FNV_PRIME 1099511628211

#define CACHE_LINE 64

#define TAG_MAX_LEN 32

#define DEFAULT_CAPACITY 1048576

#define HEADER_MAGIC 4848481594215973198

#define HEADER_VERSION 1

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
 * Signature for external collectors.
 */
typedef void (*StatsCallback)(const char *name, unsigned long long value);

typedef struct patricia_match_t {
  uint64_t key_high;
  uint64_t key_low;
  uint8_t plen;
  char tag[TAG_MAX_LEN];
} patricia_match_t;

enum ErrorCode patricia_last_error(void);

const char *patricia_strerror(enum ErrorCode code);

/**
 * Register a callback from C/other languages.
 */
void cidrscan_register_stats_callback(StatsCallback cb);

enum ErrorCode patricia_open(const uint8_t *name,
                             uintptr_t name_len,
                             uintptr_t capacity,
                             int32_t *out_handle);

enum ErrorCode patricia_close(int32_t handle);

enum ErrorCode patricia_insert(int32_t handle,
                               uint64_t key_high,
                               uint64_t key_low,
                               uint8_t prefix_len,
                               uint64_t ttl);

bool patricia_lookup(int32_t handle, uint64_t key_high, uint64_t key_low);

enum ErrorCode patricia_delete(int32_t handle,
                               uint64_t key_high,
                               uint64_t key_low,
                               uint8_t prefix_len);

enum ErrorCode patricia_destroy(int32_t handle);

/**
 * Insert an IPv4 prefix into the Patricia tree.
 *
 * # Safety
 * - The handle must be valid.
 * - `addr` is a 32-bit IPv4 address in host byte order.
 * - `prefix_len` is the prefix length (0-32).
 * - `ttl` is the time-to-live in seconds.
 *
 * Returns `ErrorCode::Success` on success, or an error code on failure.
 */
enum ErrorCode patricia_insert_v4(int32_t handle, uint32_t addr, uint8_t prefix_len, uint64_t ttl);

/**
 * Lookup an IPv4 address in the Patricia tree.
 *
 * # Safety
 * - The handle must be valid.
 * - `addr` is a 32-bit IPv4 address in host byte order.
 *
 * Returns `true` if found, `false` otherwise.
 */
bool patricia_lookup_v4(int32_t handle, uint32_t addr);

/**
 * Delete an IPv4 prefix from the Patricia tree.
 *
 * # Safety
 * - The handle must be valid.
 * - `addr` is a 32-bit IPv4 address in host byte order.
 * - `prefix_len` is the prefix length (0-32).
 *
 * Returns `ErrorCode::Success` on success, or an error code on failure.
 */
enum ErrorCode patricia_delete_v4(int32_t handle, uint32_t addr, uint8_t prefix_len);

/**
 * Flushes pending epoch callbacks for the Patricia tree.
 *
 * # Safety
 * - The handle must be valid.
 *
 * Returns `ErrorCode::Success` on success, or an error code on failure.
 */
enum ErrorCode patricia_flush(int32_t handle);

/**
 * Clears all prefixes from the Patricia tree.
 *
 * # Safety
 * - The handle must be valid.
 *
 * Returns `ErrorCode::Success` on success, or an error code on failure.
 */
enum ErrorCode patricia_clear(int32_t handle);

/**
 * Resizes the Patricia tree arena to a new capacity.
 *
 * # Safety
 * - The handle must be valid.
 * - `new_capacity` must be greater than the current capacity.
 *
 * Returns `ErrorCode::Success` on success, or an error code on failure.
 * Resizes the Patricia tree arena to a new capacity.
 *
 * # Safety
 * - The handle must be valid.
 * - `new_capacity` must be greater than the current capacity.
 *
 * Returns `ErrorCode::Success` on success, `ErrorCode::InvalidHandle` if handle is invalid,
 * `ErrorCode::ResizeFailed` if the tree is in use by multiple handles, or other mapped errors on failure.
 */
enum ErrorCode patricia_resize(int32_t handle,
                               uintptr_t new_capacity);

enum ErrorCode patricia_insert_tag(int32_t handle,
                                   uint64_t key_high,
                                   uint64_t key_low,
                                   uint8_t prefix_len,
                                   uint64_t ttl,
                                   const char *tag);

enum ErrorCode patricia_lookup_full(int32_t handle,
                                    uint64_t key_high,
                                    uint64_t key_low,
                                    struct patricia_match_t *out);
