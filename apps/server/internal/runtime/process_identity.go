package runtime

// realProcessIdentity returns a stale-binding token for the process at pid.
// The token must change when the kernel reuses pid for an unrelated process
// (different start time -> different identity). It is not an authorization
// capability: when the platform cannot produce a token, process binding must
// fail closed instead of falling back to PID ancestry alone. SessionStore
// stores this hook in its own field (set via NewSessionStore) so tests can
// override per-store without a global mutex.
