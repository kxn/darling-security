/*
 * Copyright (c) 2007-2024 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * SecPolicy.c - Implementation of various X.509 certificate trust policies
 */


/* Selected upstream function bodies from Apple Security db15acbe6a7f257a859ad9a3bb86097bfe0679d9.
 * Uses the existing SecPolicyCreate object factory; no private object layout.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecPolicy.h>
#include <stdbool.h>
#include <sys/cdefs.h>

extern SecPolicyRef SecPolicyCreate(CFStringRef, CFStringRef, CFDictionaryRef);
CF_EXPORT __attribute__((visibility("default")))
SecPolicyRef SecPolicyCreateAppleExternalDeveloperOptionalExpiry(bool checkExpiry) CF_RETURNS_RETAINED;
extern const CFStringRef kSecAttrKeyTypeEC;
extern const CFStringRef kSecAttrKeyTypeRSA;
extern const CFStringRef kSecPolicyAppleExternalDeveloper;
extern const CFStringRef kSecPolicyCheckAnchorApple;
extern const CFStringRef kSecPolicyCheckBasicCertificateProcessing;
extern const CFStringRef kSecPolicyCheckBasicConstraints;
extern const CFStringRef kSecPolicyCheckBlackListedLeaf;
extern const CFStringRef kSecPolicyCheckChainLength;
extern const CFStringRef kSecPolicyCheckCriticalExtensions;
extern const CFStringRef kSecPolicyCheckExtendedKeyUsage;
extern const CFStringRef kSecPolicyCheckGrayListedLeaf;
extern const CFStringRef kSecPolicyCheckIdLinkage;
extern const CFStringRef kSecPolicyCheckIntermediateMarkerOid;
extern const CFStringRef kSecPolicyCheckKeySize;
extern const CFStringRef kSecPolicyCheckLeafMarkerOid;
extern const CFStringRef kSecPolicyCheckNonEmptySubject;
extern const CFStringRef kSecPolicyCheckRevocation;
extern const CFStringRef kSecPolicyCheckRevocationAny;
extern const CFStringRef kSecPolicyCheckTemporalValidity;
extern const CFStringRef kSecPolicyCheckUnparseableExtension;
extern const CFStringRef kSecPolicyCheckWeakKeySize;
extern const CFStringRef kSecPolicyCheckWeakSignature;
static const CFStringRef kSecPolicyCheckDuplicateExtension = CFSTR("DuplicateExtension");
static CFStringRef kSecPolicyNameExternalDeveloper = CFSTR("Developer");

#ifndef require
#define require(test, label) do { if (!(test)) goto label; } while (0)
#endif
#ifndef CFReleaseSafe
#define CFReleaseSafe(value) do { if (value) CFRelease(value); } while (0)
#endif
#ifndef CFReleaseNull
#define CFReleaseNull(value) do { CFReleaseSafe(value); (value) = NULL; } while (0)
#endif

static inline CFNumberRef CFNumberCreateWithCFIndex(CFAllocatorRef allocator, CFIndex value)
{
    return CFNumberCreate(allocator, kCFNumberCFIndexType, &value);
}

static inline CFMutableDictionaryRef CFDictionaryCreateMutableForCFTypes(CFAllocatorRef allocator)
{
    return CFDictionaryCreateMutable(allocator, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

static void add_element(CFMutableDictionaryRef options, CFStringRef key,
    CFTypeRef value) {
    CFTypeRef old_value = CFDictionaryGetValue(options, key);
    if (old_value) {
        CFMutableArrayRef array;
        if (CFGetTypeID(old_value) == CFArrayGetTypeID()) {
            array = (CFMutableArrayRef)old_value;
        } else {
            array = CFArrayCreateMutable(kCFAllocatorDefault, 0,
                                       &kCFTypeArrayCallBacks);
            CFArrayAppendValue(array, old_value);
            CFDictionarySetValue(options, key, array);
            CFRelease(array);
        }
        CFArrayAppendValue(array, value);
    } else {
        CFDictionaryAddValue(options, key, value);
    }
}

static void add_eku_string(CFMutableDictionaryRef options, CFStringRef ekuOid) {
    if (ekuOid) {
        add_element(options, kSecPolicyCheckExtendedKeyUsage, ekuOid);
    }
}

static void add_leaf_marker_value_string(CFMutableDictionaryRef options, CFStringRef markerOid, CFStringRef string_value) {
    if (NULL == string_value) {
        add_element(options, kSecPolicyCheckLeafMarkerOid, markerOid);
    } else {
        CFDictionaryRef policyData = NULL;
        const void *key[1]   = { markerOid };
        const void *value[1] = { string_value };
        policyData = CFDictionaryCreate(kCFAllocatorDefault,
                                        key, value, 1,
                                        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        add_element(options, kSecPolicyCheckLeafMarkerOid, policyData);

        CFReleaseNull(policyData);
    }
}

static void add_leaf_marker_string(CFMutableDictionaryRef options, CFStringRef markerOid) {
    add_leaf_marker_value_string(options, markerOid, NULL);
}

static void SecPolicyAddBasicCertOptions(CFMutableDictionaryRef options)
{
    //CFDictionaryAddValue(options, kSecPolicyCheckBasicCertificateProcessing, kCFBooleanTrue);
        // Happens automatically in SecPVCPathChecks
    CFDictionaryAddValue(options, kSecPolicyCheckCriticalExtensions, kCFBooleanTrue);
    CFDictionaryAddValue(options, kSecPolicyCheckUnparseableExtension, kCFBooleanTrue);
    CFDictionaryAddValue(options, kSecPolicyCheckDuplicateExtension, kCFBooleanTrue);
    CFDictionaryAddValue(options, kSecPolicyCheckIdLinkage, kCFBooleanTrue);
    CFDictionaryAddValue(options, kSecPolicyCheckBasicConstraints, kCFBooleanTrue);
    CFDictionaryAddValue(options, kSecPolicyCheckNonEmptySubject, kCFBooleanTrue);
    CFDictionaryAddValue(options, kSecPolicyCheckWeakKeySize, kCFBooleanTrue);
    CFDictionaryAddValue(options, kSecPolicyCheckWeakSignature, kCFBooleanTrue);
}

static void SecPolicyAddBasicX509Options(CFMutableDictionaryRef options)
{
    SecPolicyAddBasicCertOptions(options);
    CFDictionaryAddValue(options, kSecPolicyCheckTemporalValidity, kCFBooleanTrue);

	// Make sure that black and gray leaf checks are performed for basic X509 chain building
    CFDictionaryAddValue(options, kSecPolicyCheckBlackListedLeaf,  kCFBooleanTrue);
    CFDictionaryAddValue(options, kSecPolicyCheckGrayListedLeaf,   kCFBooleanTrue);
}

static bool SecPolicyAddChainLengthOptions(CFMutableDictionaryRef options, CFIndex length)
{
    bool result = false;
    CFNumberRef lengthAsCF = NULL;

    require(lengthAsCF = CFNumberCreate(kCFAllocatorDefault,
                                         kCFNumberCFIndexType, &length), errOut);
    CFDictionaryAddValue(options, kSecPolicyCheckChainLength, lengthAsCF);

    result = true;

errOut:
	CFReleaseSafe(lengthAsCF);
    return result;
}

static bool SecPolicyAddStrongKeySizeOptions(CFMutableDictionaryRef options) {
    bool success = false;
    CFDictionaryRef keySizes = NULL;
    CFNumberRef rsaSize = NULL, ecSize = NULL;

    /* RSA key sizes are 2048-bit or larger. EC key sizes are P-256 or larger. */
    require(rsaSize = CFNumberCreateWithCFIndex(NULL, 2048), errOut);
    require(ecSize = CFNumberCreateWithCFIndex(NULL, 256), errOut);
    const void *keys[] = { kSecAttrKeyTypeRSA, kSecAttrKeyTypeEC };
    const void *values[] = { rsaSize, ecSize };
    require(keySizes = CFDictionaryCreate(NULL, keys, values, 2,
                                          &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks), errOut);
    add_element(options, kSecPolicyCheckKeySize, keySizes);

    success = true;

errOut:
    CFReleaseSafe(keySizes);
    CFReleaseSafe(rsaSize);
    CFReleaseSafe(ecSize);
    return success;
}

static bool SecPolicyAddAppleAnchorOptions(CFMutableDictionaryRef options, CFStringRef __unused policyName)
{
    CFMutableDictionaryRef appleAnchorOptions = NULL;
    appleAnchorOptions = CFDictionaryCreateMutableForCFTypes(NULL);
    if (!appleAnchorOptions) {
        return false;
    }

    /* Currently no Apple Anchor options */
    add_element(options, kSecPolicyCheckAnchorApple, appleAnchorOptions);
    CFReleaseSafe(appleAnchorOptions);
    return true;
}

SecPolicyRef SecPolicyCreateAppleExternalDeveloperOptionalExpiry(bool checkExpiry) {
    CFMutableDictionaryRef options = NULL;
    SecPolicyRef result = NULL;

    require(options = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                                &kCFTypeDictionaryKeyCallBacks,
                                                &kCFTypeDictionaryValueCallBacks), errOut);

    if (checkExpiry) {
        SecPolicyAddBasicX509Options(options);
    } else {
        SecPolicyAddBasicCertOptions(options);
    }

    /* Anchored to the Apple Roots */
    require(SecPolicyAddAppleAnchorOptions(options, kSecPolicyNameExternalDeveloper), errOut);

    /* Exactly 3 certs in the chain */
    require(SecPolicyAddChainLengthOptions(options, 3), errOut);

    /* Intermediate marker OIDs */
    add_element(options, kSecPolicyCheckIntermediateMarkerOid,
                CFSTR("1.2.840.113635.100.6.2.1")); // WWDR Intermediate OID
    add_element(options, kSecPolicyCheckIntermediateMarkerOid,
                CFSTR("1.2.840.113635.100.6.2.6")); // "Developer ID" Intermediate OID

    /* Leaf marker OIDs */
    add_leaf_marker_string(options, CFSTR("1.2.840.113635.100.6.1.2"));  // "iPhone Developer" leaf OID
    add_leaf_marker_string(options, CFSTR("1.2.840.113635.100.6.1.4"));  // "iPhone Distribution" leaf OID
    add_leaf_marker_string(options, CFSTR("1.2.840.113635.100.6.1.5"));  // "Safari Developer" leaf OID
    add_leaf_marker_string(options, CFSTR("1.2.840.113635.100.6.1.7"));  // "3rd Party Mac Developer Application" leaf OID
    add_leaf_marker_string(options, CFSTR("1.2.840.113635.100.6.1.8"));  // "3rd Party Mac Developer Installer" leaf OID
    add_leaf_marker_string(options, CFSTR("1.2.840.113635.100.6.1.12")); // "Mac Developer" leaf OID
    add_leaf_marker_string(options, CFSTR("1.2.840.113635.100.6.1.13")); // "Developer ID Application" leaf OID
    add_leaf_marker_string(options, CFSTR("1.2.840.113635.100.6.1.14")); // "Developer ID Installer" leaf OID
    add_leaf_marker_string(options, CFSTR("1.2.840.113635.100.6.1.35")); // "Swift Package Registry" leaf OID

    /* Restrict EKUs */
    add_eku_string(options, CFSTR("1.3.6.1.5.5.7.3.3"));       // CodeSigning EKU
    add_eku_string(options, CFSTR("1.2.840.113635.100.4.8"));  // "Safari Developer" EKU
    add_eku_string(options, CFSTR("1.2.840.113635.100.4.9"));  // "3rd Party Mac Developer Installer" EKU
    add_eku_string(options, CFSTR("1.2.840.113635.100.4.13")); // "Developer ID Installer" EKU

    /* Check revocation using any available method */
    add_element(options, kSecPolicyCheckRevocation, kSecPolicyCheckRevocationAny);

    /* RSA key sizes are 2048-bit or larger. EC key sizes are P-256 or larger. */
    require(SecPolicyAddStrongKeySizeOptions(options), errOut);

    /* Check for weak hashes */
    // require(SecPolicyRemoveWeakHashOptions(options), errOut); // the current WWDR CA cert is signed with SHA1
    require(result = SecPolicyCreate(kSecPolicyAppleExternalDeveloper,
                                     kSecPolicyNameExternalDeveloper,
                                     options), errOut);

errOut:
    CFReleaseSafe(options);
    return result;
}
