/*
 * Copyright (c) 2006-2014 Apple Inc. All Rights Reserved.
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

#pragma once
#import <CoreFoundation/CoreFoundation.h>
#import "SecItemFetchOutOfBandValues.h"

void SecItemUnsetCurrentItemsAcrossAllDevices(CFStringRef accessGroup,
                                              CFArrayRef identifiers,
                                              CFStringRef viewHint,
                                              void (^complete)(CFErrorRef error));
void SecItemFetchCurrentItemOutOfBand(NSArray<CKKSCurrentItemQuery*>* currentItemQueries, bool forceFetch, void (^complete)(NSArray<CKKSCurrentItemQueryResult*>* currentItems, NSError* error));
void SecItemFetchPCSIdentityOutOfBand(NSArray<CKKSPCSIdentityQuery*>* pcsIdentityQueries, bool forceFetch, void (^complete)(NSArray<CKKSPCSIdentityQueryResult*>* pcsIdentities, NSError* error));

@interface SecItemCurrentItemData: NSObject
- (instancetype)init NS_UNAVAILABLE;
@property (strong, readonly, nonnull) NSData *persistentRef;
@property (strong, readonly, nullable) NSDate *currentItemPointerModificationTime;
@end

void
SecItemFetchCurrentItemDataAcrossAllDevices(NSString *accessGroup,
                                            NSString *identifier,
                                            NSString *viewHint,
                                            BOOL fetchCloudValue,
                                            void (^complete)(SecItemCurrentItemData * _Nullable persistentRef, NSError * _Nullable error));
