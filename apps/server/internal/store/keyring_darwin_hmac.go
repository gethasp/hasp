//go:build darwin && cgo && !hasp_test_fastkdf

package store

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include "hasp_security_shim_darwin.h"
*/
import "C"

import (
	"context"
	"encoding/base64"
	"fmt"
	"unsafe"
)

func init() {
	// Route DarwinKeyring.Set through the in-process Security API in cgo builds,
	// so the value is never a `security -w <value>` process argument (hasp-4rqu).
	nativeKeychainSet = func(service, account, value string) error {
		return DarwinKeyring{}.setNative(service, account, value)
	}
}

// setNative stores value (verbatim — matching the `security` CLI, which stored
// the raw string) as a generic-password item via the legacy file-keychain API,
// with an ACL trusting /usr/bin/security so the existing CLI Get/Delete still
// work. No designated requirement (the convenience device key has none).
func (DarwinKeyring) setNative(service string, account string, value string) error {
	serviceC := C.CString(service)
	accountC := C.CString(account)
	defer C.free(unsafe.Pointer(serviceC))
	defer C.free(unsafe.Pointer(accountC))

	valueBytes := []byte(value)
	var valuePtr *C.uchar
	if len(valueBytes) > 0 {
		valuePtr = (*C.uchar)(C.CBytes(valueBytes))
		defer C.free(unsafe.Pointer(valuePtr))
	}

	status := C.HASPKeychainAddTrustingCLI(serviceC, accountC, valuePtr, C.CFIndex(len(valueBytes)))
	if status != C.errSecSuccess { //nolint:gocritic // cgo constants can trigger dupSubExpr falsely here.
		return fmt.Errorf("%w: native keychain write failed: OSStatus %d", ErrKeyringUnavailable, int(status))
	}
	return nil
}

func (DarwinKeyring) SetWithDesignatedRequirements(_ context.Context, service string, account string, value string, requirements []string) error {
	if len(requirements) != 2 {
		return fmt.Errorf("%w: expected exactly two designated requirements", ErrKeyringUnavailable)
	}
	serviceC := C.CString(service)
	accountC := C.CString(account)
	valueBytes, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		C.free(unsafe.Pointer(serviceC))
		C.free(unsafe.Pointer(accountC))
		return fmt.Errorf("%w: decode native keychain value: %v", ErrKeyringUnavailable, err)
	}
	valueC := (*C.uchar)(C.CBytes(valueBytes))
	appReqC := C.CString(requirements[0])
	daemonReqC := C.CString(requirements[1])
	defer C.free(unsafe.Pointer(serviceC))
	defer C.free(unsafe.Pointer(accountC))
	defer C.free(unsafe.Pointer(valueC))
	defer C.free(unsafe.Pointer(appReqC))
	defer C.free(unsafe.Pointer(daemonReqC))

	status := C.HASPKeychainAddWithRequirements(serviceC, accountC, valueC, C.CFIndex(len(valueBytes)), appReqC, daemonReqC)
	if status != C.errSecSuccess { //nolint:gocritic // cgo constants can trigger dupSubExpr falsely here.
		return fmt.Errorf("%w: create HTTP HMAC keychain item with designated requirements failed: OSStatus %d", ErrKeyringUnavailable, int(status))
	}
	return nil
}

func (DarwinKeyring) GetNative(service string, account string) (string, error) {
	serviceC := C.CString(service)
	accountC := C.CString(account)
	defer C.free(unsafe.Pointer(serviceC))
	defer C.free(unsafe.Pointer(accountC))

	var out *C.uchar
	var outLength C.CFIndex
	status := C.HASPKeychainCopy(serviceC, accountC, &out, &outLength) //nolint:gocritic // cgo expands Security constants into duplicate subexpressions.
	if int(status) != int(C.errSecSuccess) {
		err := fmt.Errorf("%w: native keychain read failed: OSStatus %d", ErrKeyringUnavailable, int(status))
		if int(status) == int(C.errSecItemNotFound) {
			return "", KeyringItemNotFoundError{Err: err}
		}
		return "", fmt.Errorf("%w: native keychain read failed: OSStatus %d", ErrKeyringUnavailable, int(status))
	}
	defer C.HASPSecurityFree(unsafe.Pointer(out))
	return base64.StdEncoding.EncodeToString(C.GoBytes(unsafe.Pointer(out), C.int(outLength))), nil
}

func (DarwinKeyring) DeleteNative(service string, account string) error {
	serviceC := C.CString(service)
	accountC := C.CString(account)
	defer C.free(unsafe.Pointer(serviceC))
	defer C.free(unsafe.Pointer(accountC))

	status := C.HASPKeychainDelete(serviceC, accountC)
	if status != C.errSecSuccess {
		return fmt.Errorf("%w: native keychain delete failed: OSStatus %d", ErrKeyringUnavailable, int(status))
	}
	return nil
}
