#ifndef HASP_SECURITY_SHIM_H
#define HASP_SECURITY_SHIM_H

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

OSStatus HASPKeychainAddWithRequirements(
  const char *service,
  const char *account,
  const unsigned char *bytes,
  CFIndex length,
  const char *appRequirement,
  const char *daemonRequirement
);

OSStatus HASPKeychainAddTrustingCLI(
  const char *service,
  const char *account,
  const unsigned char *bytes,
  CFIndex length
);

OSStatus HASPKeychainCopy(
  const char *service,
  const char *account,
  unsigned char **outBytes,
  CFIndex *outLength
);

OSStatus HASPKeychainDelete(const char *service, const char *account);
OSStatus HASPRequirementCheckSelf(const char *requirement);
void HASPSecurityFree(void *pointer);

#endif
