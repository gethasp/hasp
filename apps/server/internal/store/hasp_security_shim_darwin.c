#include "hasp_security_shim_darwin.h"

#include <stdlib.h>
#include <string.h>

OSStatus SecTrustedApplicationCreateFromRequirement(
  const char *description,
  SecRequirementRef requirement,
  SecTrustedApplicationRef *app
);

static CFStringRef hasp_cfstring(const char *value) {
  return CFStringCreateWithCString(NULL, value, kCFStringEncodingUTF8);
}

static OSStatus hasp_default_keychain(SecKeychainRef *keychain) {
  return SecKeychainCopyDefault(keychain);
}

OSStatus HASPKeychainDelete(const char *service, const char *account) {
  CFStringRef serviceRef = hasp_cfstring(service);
  CFStringRef accountRef = hasp_cfstring(account);
  SecKeychainRef keychain = NULL;
  CFArrayRef searchList = NULL;
  CFDictionaryRef query = NULL;

  if (serviceRef == NULL || accountRef == NULL) {
    if (serviceRef != NULL) CFRelease(serviceRef);
    if (accountRef != NULL) CFRelease(accountRef);
    return errSecParam;
  }

  OSStatus status = hasp_default_keychain(&keychain);
  if (status != errSecSuccess) goto done;

  const void *searchValues[] = { keychain };
  searchList = CFArrayCreate(NULL, searchValues, 1, &kCFTypeArrayCallBacks);
  if (searchList == NULL) {
    status = errSecParam;
    goto done;
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
  query = CFDictionaryCreate(
    NULL,
    keys,
    values,
    4,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks
  );
  status = query == NULL ? errSecParam : SecItemDelete(query);
  if (status == errSecItemNotFound) status = errSecSuccess;

done:
  if (query != NULL) CFRelease(query);
  if (searchList != NULL) CFRelease(searchList);
  if (keychain != NULL) CFRelease(keychain);
  CFRelease(serviceRef);
  CFRelease(accountRef);
  return status;
}

OSStatus HASPKeychainCopy(
  const char *service,
  const char *account,
  unsigned char **outBytes,
  CFIndex *outLength
) {
  *outBytes = NULL;
  *outLength = 0;

  CFStringRef serviceRef = hasp_cfstring(service);
  CFStringRef accountRef = hasp_cfstring(account);
  SecKeychainRef keychain = NULL;
  CFArrayRef searchList = NULL;
  CFDictionaryRef query = NULL;
  CFTypeRef result = NULL;

  if (serviceRef == NULL || accountRef == NULL) {
    if (serviceRef != NULL) CFRelease(serviceRef);
    if (accountRef != NULL) CFRelease(accountRef);
    return errSecParam;
  }

  OSStatus status = hasp_default_keychain(&keychain);
  if (status != errSecSuccess) goto done;

  const void *searchValues[] = { keychain };
  searchList = CFArrayCreate(NULL, searchValues, 1, &kCFTypeArrayCallBacks);
  if (searchList == NULL) {
    status = errSecParam;
    goto done;
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
  query = CFDictionaryCreate(
    NULL,
    keys,
    values,
    6,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks
  );
  if (query == NULL) {
    status = errSecParam;
  } else {
    Boolean interactionWasAllowed = false;
    (void)SecKeychainGetUserInteractionAllowed(&interactionWasAllowed);
    (void)SecKeychainSetUserInteractionAllowed(false);
    status = SecItemCopyMatching(query, &result);
    (void)SecKeychainSetUserInteractionAllowed(interactionWasAllowed);
  }
  if (status == errSecSuccess && result != NULL && CFGetTypeID(result) == CFDataGetTypeID()) {
    CFDataRef data = (CFDataRef)result;
    CFIndex length = CFDataGetLength(data);
    unsigned char *buffer = malloc((size_t)length);
    if (buffer == NULL && length > 0) {
      status = errSecAllocate;
      goto done;
    }
    if (length > 0) memcpy(buffer, CFDataGetBytePtr(data), (size_t)length);
    *outBytes = buffer;
    *outLength = length;
  }

done:
  if (result != NULL) CFRelease(result);
  if (query != NULL) CFRelease(query);
  if (searchList != NULL) CFRelease(searchList);
  if (keychain != NULL) CFRelease(keychain);
  CFRelease(serviceRef);
  CFRelease(accountRef);
  return status;
}

OSStatus HASPKeychainAddWithRequirements(
  const char *service,
  const char *account,
  const unsigned char *bytes,
  CFIndex length,
  const char *appRequirement,
  const char *daemonRequirement
) {
  CFStringRef serviceRef = NULL;
  CFStringRef accountRef = NULL;
  CFDataRef valueData = NULL;
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
  valueData = CFDataCreate(NULL, bytes, length);
  if (
    serviceRef == NULL || accountRef == NULL || appReqString == NULL || daemonReqString == NULL
    || valueData == NULL
  ) {
    return errSecParam;
  }

  OSStatus status = SecRequirementCreateWithString(appReqString, kSecCSDefaultFlags, &appReq);
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
  status = SecACLCreateWithSimpleContents(
    access,
    trustedList,
    CFSTR("HASP HTTP HMAC key"),
    promptSelector,
    &readACL
  );
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
  query = CFDictionaryCreate(
    NULL,
    keys,
    values,
    3,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks
  );
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
    valueData
  };
  attributes = CFDictionaryCreate(
    NULL,
    attributeKeys,
    attributeValues,
    3,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks
  );
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
      valueData
    };
    CFRelease(query);
    query = CFDictionaryCreate(
      NULL,
      addKeys,
      addValues,
      6,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks
    );
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
  if (valueData != NULL) CFRelease(valueData);
  if (appReqString != NULL) CFRelease(appReqString);
  if (daemonReqString != NULL) CFRelease(daemonReqString);
  if (serviceRef != NULL) CFRelease(serviceRef);
  if (accountRef != NULL) CFRelease(accountRef);
  return status;
}

OSStatus HASPRequirementCheckSelf(const char *requirement) {
  CFStringRef requirementString = hasp_cfstring(requirement);
  SecRequirementRef requirementRef = NULL;
  SecCodeRef selfCode = NULL;
  if (requirementString == NULL) return errSecParam;

  OSStatus status = SecRequirementCreateWithString(
    requirementString,
    kSecCSDefaultFlags,
    &requirementRef
  );
  if (status != errSecSuccess) goto done;
  status = SecCodeCopySelf(kSecCSDefaultFlags, &selfCode);
  if (status != errSecSuccess) goto done;
  status = SecCodeCheckValidity(selfCode, kSecCSDefaultFlags, requirementRef);

done:
  if (selfCode != NULL) CFRelease(selfCode);
  if (requirementRef != NULL) CFRelease(requirementRef);
  CFRelease(requirementString);
  return status;
}

void HASPSecurityFree(void *pointer) {
  free(pointer);
}
