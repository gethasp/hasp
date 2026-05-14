//go:build darwin && cgo && !hasp_no_attestation && !hasp_test_fastkdf

package httpapi

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

static OSStatus hasp_verify_pid_requirement(int pid, const char *requirementText) {
	CFNumberRef pidNumber = NULL;
	CFDictionaryRef attributes = NULL;
	SecCodeRef code = NULL;
	CFStringRef requirementString = NULL;
	SecRequirementRef requirement = NULL;
	OSStatus status = errSecSuccess;

	pidNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
	if (pidNumber == NULL) {
		return errSecAllocate;
	}
	const void *keys[] = { kSecGuestAttributePid };
	const void *values[] = { pidNumber };
	attributes = CFDictionaryCreate(
		kCFAllocatorDefault,
		keys,
		values,
		1,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (attributes == NULL) {
		CFRelease(pidNumber);
		return errSecAllocate;
	}

	status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
	if (status != errSecSuccess) {
		CFRelease(attributes);
		CFRelease(pidNumber);
		return status;
	}

	requirementString = CFStringCreateWithCString(kCFAllocatorDefault, requirementText, kCFStringEncodingUTF8);
	if (requirementString == NULL) {
		CFRelease(code);
		CFRelease(attributes);
		CFRelease(pidNumber);
		return errSecAllocate;
	}

	status = SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirement);
	if (status == errSecSuccess) {
		status = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
	}

	if (requirement != NULL) {
		CFRelease(requirement);
	}
	CFRelease(requirementString);
	CFRelease(code);
	CFRelease(attributes);
	CFRelease(pidNumber);
	return status;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func verifyPIDDesignatedRequirement(pid int, requirement string) error {
	req := C.CString(requirement)
	defer C.free(unsafe.Pointer(req))
	status := C.hasp_verify_pid_requirement(C.int(pid), req)
	if status != C.errSecSuccess {
		return fmt.Errorf("%w: codesign validation failed for pid %d: OSStatus %d", ErrAttestationRejected, pid, int32(status))
	}
	return nil
}
