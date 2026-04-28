//go:build hasp_test_fastkdf

package store

// argon2id tuning parameters under hasp_test_fastkdf. Memory drops to the
// argon2 floor (8 KiB at p=1) and time to 1 so the test suite can call
// Init/Open hundreds of times without burning minutes on KDF work — production
// builds always use the values in argon2id_params_default.go.
const (
	passwordArgon2Time        uint32 = 1
	passwordArgon2MemoryKiB   uint32 = 8
	passwordArgon2Parallelism uint8  = 1
)
