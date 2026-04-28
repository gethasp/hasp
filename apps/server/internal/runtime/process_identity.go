package runtime

// realProcessIdentity returns a stable token identifying the process at pid.
// The token must change when the kernel reuses pid for an unrelated process
// (different start time → different identity). When the platform cannot
// produce a token, the function returns "" and a nil error so callers fall
// back to advisory ancestry-only checks. SessionStore stores this hook in
// its own field (set via NewSessionStore) so tests can override per-store
// without a global mutex.
