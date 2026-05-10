//go:build darwin && cgo

package store

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

OSStatus SecTrustedApplicationCreateFromRequirement(const char *description, SecRequirementRef requirement, SecTrustedApplicationRef *app);

static CFStringRef hasp_cfstring(const char *value) {
	return CFStringCreateWithCString(NULL, value, kCFStringEncodingUTF8);
}

static OSStatus hasp_default_keychain(SecKeychainRef *keychain) {
	return SecKeychainCopyDefault(keychain);
}

static OSStatus hasp_delete_generic_password(const char *service, const char *account) {
	CFStringRef serviceRef = hasp_cfstring(service);
	CFStringRef accountRef = hasp_cfstring(account);
	SecKeychainRef keychain = NULL;
	CFArrayRef searchList = NULL;
	if (serviceRef == NULL || accountRef == NULL) {
		if (serviceRef != NULL) CFRelease(serviceRef);
		if (accountRef != NULL) CFRelease(accountRef);
		return errSecParam;
	}
	OSStatus status = hasp_default_keychain(&keychain);
	if (status != errSecSuccess) {
		CFRelease(serviceRef);
		CFRelease(accountRef);
		return status;
	}
	const void *searchValues[] = { keychain };
	searchList = CFArrayCreate(NULL, searchValues, 1, &kCFTypeArrayCallBacks);
	if (searchList == NULL) {
		CFRelease(keychain);
		CFRelease(serviceRef);
		CFRelease(accountRef);
		return errSecParam;
	}
	const void *keys[] = {
		kSecClass,
		kSecAttrService,
		kSecAttrAccount,
		kSecMatchSearchList
	};
	const void *values[] = {
		kSecClassGenericPassword,
		serviceRef,
		accountRef,
		searchList
	};
	CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	status = query == NULL ? errSecParam : SecItemDelete(query);
	if (query != NULL) CFRelease(query);
	CFRelease(searchList);
	CFRelease(keychain);
	CFRelease(serviceRef);
	CFRelease(accountRef);
	if (status == errSecItemNotFound) return errSecSuccess;
	return status;
}

static OSStatus hasp_get_generic_password_native(const char *service, const char *account, unsigned char **out, CFIndex *outLength) {
	*out = NULL;
	*outLength = 0;
	CFStringRef serviceRef = hasp_cfstring(service);
	CFStringRef accountRef = hasp_cfstring(account);
	SecKeychainRef keychain = NULL;
	CFArrayRef searchList = NULL;
	if (serviceRef == NULL || accountRef == NULL) {
		if (serviceRef != NULL) CFRelease(serviceRef);
		if (accountRef != NULL) CFRelease(accountRef);
		return errSecParam;
	}
	OSStatus status = hasp_default_keychain(&keychain);
	if (status != errSecSuccess) {
		CFRelease(serviceRef);
		CFRelease(accountRef);
		return status;
	}
	const void *searchValues[] = { keychain };
	searchList = CFArrayCreate(NULL, searchValues, 1, &kCFTypeArrayCallBacks);
	if (searchList == NULL) {
		CFRelease(keychain);
		CFRelease(serviceRef);
		CFRelease(accountRef);
		return errSecParam;
	}
	const void *keys[] = {
		kSecClass,
		kSecAttrService,
		kSecAttrAccount,
		kSecMatchSearchList,
		kSecUseAuthenticationUI,
		kSecReturnData
	};
	const void *values[] = {
		kSecClassGenericPassword,
		serviceRef,
		accountRef,
		searchList,
		kSecUseAuthenticationUIFail,
		kCFBooleanTrue
	};
		CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values, 6, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		CFTypeRef result = NULL;
		Boolean interactionWasAllowed = false;
		if (query == NULL) {
			status = errSecParam;
		} else {
			(void)SecKeychainGetUserInteractionAllowed(&interactionWasAllowed);
			(void)SecKeychainSetUserInteractionAllowed(false);
			status = SecItemCopyMatching(query, &result);
			(void)SecKeychainSetUserInteractionAllowed(interactionWasAllowed);
		}
		if (status == errSecSuccess && result != NULL && CFGetTypeID(result) == CFDataGetTypeID()) {
			CFDataRef data = (CFDataRef)result;
			CFIndex length = CFDataGetLength(data);
			unsigned char *buffer = (unsigned char *)malloc((size_t)length);
			if (buffer == NULL && length > 0) {
				status = errSecAllocate;
			} else {
				memcpy(buffer, CFDataGetBytePtr(data), (size_t)length);
				*out = buffer;
				*outLength = length;
			}
		}
	if (result != NULL) CFRelease(result);
	if (query != NULL) CFRelease(query);
	CFRelease(searchList);
	CFRelease(keychain);
	CFRelease(serviceRef);
	CFRelease(accountRef);
	return status;
}

static OSStatus hasp_add_generic_password_with_requirements(const char *service, const char *account, const unsigned char *password, CFIndex passwordLength, const char *appRequirement, const char *daemonRequirement) {
	OSStatus status = errSecSuccess;
	CFStringRef serviceRef = NULL;
	CFStringRef accountRef = NULL;
	CFDataRef passwordData = NULL;
	CFStringRef appReqString = NULL;
	CFStringRef daemonReqString = NULL;
	SecRequirementRef appReq = NULL;
	SecRequirementRef daemonReq = NULL;
	SecTrustedApplicationRef appTrust = NULL;
	SecTrustedApplicationRef daemonTrust = NULL;
	CFArrayRef trustedList = NULL;
	SecAccessRef access = NULL;
	CFArrayRef aclList = NULL;
	SecACLRef readACL = NULL;
	CFDictionaryRef query = NULL;
	CFDictionaryRef attributes = NULL;

	serviceRef = hasp_cfstring(service);
	accountRef = hasp_cfstring(account);
	appReqString = hasp_cfstring(appRequirement);
	daemonReqString = hasp_cfstring(daemonRequirement);
	passwordData = CFDataCreate(NULL, password, passwordLength);
	if (serviceRef == NULL || accountRef == NULL || appReqString == NULL || daemonReqString == NULL || passwordData == NULL) {
		status = errSecParam;
		goto done;
	}

	status = SecRequirementCreateWithString(appReqString, kSecCSDefaultFlags, &appReq);
	if (status != errSecSuccess) goto done;
	status = SecRequirementCreateWithString(daemonReqString, kSecCSDefaultFlags, &daemonReq);
	if (status != errSecSuccess) goto done;
	status = SecTrustedApplicationCreateFromRequirement("HASP.app", appReq, &appTrust);
	if (status != errSecSuccess) goto done;
	status = SecTrustedApplicationCreateFromRequirement("HASP daemon", daemonReq, &daemonTrust);
	if (status != errSecSuccess) goto done;

	const void *trustedApps[] = { appTrust, daemonTrust };
	trustedList = CFArrayCreate(NULL, trustedApps, 2, &kCFTypeArrayCallBacks);
	if (trustedList == NULL) {
		status = errSecParam;
		goto done;
	}
	status = SecAccessCreate(CFSTR("HASP HTTP HMAC key"), trustedList, &access);
	if (status != errSecSuccess) goto done;
	status = SecAccessCopyACLList(access, &aclList);
	if (status != errSecSuccess) goto done;
	CFIndex aclCount = CFArrayGetCount(aclList);
	SecKeychainPromptSelector promptSelector = 0;
	for (CFIndex i = 0; i < aclCount; i++) {
		SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(aclList, i);
		status = SecACLRemove(acl);
		if (status != errSecSuccess) goto done;
	}
	status = SecACLCreateWithSimpleContents(access, trustedList, CFSTR("HASP HTTP HMAC key"), promptSelector, &readACL);
	if (status != errSecSuccess) goto done;

	const void *keys[] = {
		kSecClass,
		kSecAttrService,
		kSecAttrAccount
	};
	const void *values[] = {
		kSecClassGenericPassword,
		serviceRef,
		accountRef
	};
	query = CFDictionaryCreate(NULL, keys, values, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (query == NULL) {
		status = errSecParam;
		goto done;
	}
	const void *attributeKeys[] = {
		kSecAttrAccessible,
		kSecAttrAccess,
		kSecValueData
	};
	const void *attributeValues[] = {
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		access,
		passwordData
	};
	attributes = CFDictionaryCreate(NULL, attributeKeys, attributeValues, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (attributes == NULL) {
		status = errSecParam;
		goto done;
	}
	status = SecItemUpdate(query, attributes);
	if (status == errSecItemNotFound) {
		const void *addKeys[] = {
			kSecClass,
			kSecAttrService,
			kSecAttrAccount,
			kSecAttrAccessible,
			kSecAttrAccess,
			kSecValueData
		};
		const void *addValues[] = {
			kSecClassGenericPassword,
			serviceRef,
			accountRef,
			kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
			access,
			passwordData
		};
		CFRelease(query);
		query = CFDictionaryCreate(NULL, addKeys, addValues, 6, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		status = query == NULL ? errSecParam : SecItemAdd(query, NULL);
	}

done:
	if (attributes != NULL) CFRelease(attributes);
	if (query != NULL) CFRelease(query);
	if (readACL != NULL) CFRelease(readACL);
	if (aclList != NULL) CFRelease(aclList);
	if (access != NULL) CFRelease(access);
	if (trustedList != NULL) CFRelease(trustedList);
	if (appTrust != NULL) CFRelease(appTrust);
	if (daemonTrust != NULL) CFRelease(daemonTrust);
	if (appReq != NULL) CFRelease(appReq);
	if (daemonReq != NULL) CFRelease(daemonReq);
	if (passwordData != NULL) CFRelease(passwordData);
	if (appReqString != NULL) CFRelease(appReqString);
	if (daemonReqString != NULL) CFRelease(daemonReqString);
	if (serviceRef != NULL) CFRelease(serviceRef);
	if (accountRef != NULL) CFRelease(accountRef);
	return status;
}
*/
import "C"

import (
	"context"
	"encoding/base64"
	"fmt"
	"unsafe"
)

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

	status := C.hasp_add_generic_password_with_requirements(serviceC, accountC, valueC, C.CFIndex(len(valueBytes)), appReqC, daemonReqC)
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
	status := C.hasp_get_generic_password_native(serviceC, accountC, &out, &outLength) //nolint:gocritic // cgo expands Security constants into duplicate subexpressions.
	if int(status) != int(C.errSecSuccess) {
		err := fmt.Errorf("%w: native keychain read failed: OSStatus %d", ErrKeyringUnavailable, int(status))
		if int(status) == int(C.errSecItemNotFound) {
			return "", KeyringItemNotFoundError{Err: err}
		}
		return "", fmt.Errorf("%w: native keychain read failed: OSStatus %d", ErrKeyringUnavailable, int(status))
	}
	defer C.free(unsafe.Pointer(out))
	return base64.StdEncoding.EncodeToString(C.GoBytes(unsafe.Pointer(out), C.int(outLength))), nil
}

func (DarwinKeyring) DeleteNative(service string, account string) error {
	serviceC := C.CString(service)
	accountC := C.CString(account)
	defer C.free(unsafe.Pointer(serviceC))
	defer C.free(unsafe.Pointer(accountC))

	status := C.hasp_delete_generic_password(serviceC, accountC)
	if status != C.errSecSuccess {
		return fmt.Errorf("%w: native keychain delete failed: OSStatus %d", ErrKeyringUnavailable, int(status))
	}
	return nil
}
