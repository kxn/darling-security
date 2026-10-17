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

// Client functions from Apple Security db15acbe; server operations remain in securityd.
#import "SecItemCloudRPC.h"
#import <ipc/securityd_client.h>
#import <os/activity.h>

void SecItemUnsetCurrentItemsAcrossAllDevices(CFStringRef accessGroup,
                                              CFArrayRef identifiers,
                                              CFStringRef viewHint,
                                              void (^complete)(CFErrorRef error))
{
    os_activity_t activity = os_activity_create("SecItemUnsetCurrentItemsAcrossAllDevices", OS_ACTIVITY_CURRENT, OS_ACTIVITY_FLAG_DEFAULT);
    os_activity_scope(activity);

    @autoreleasepool {
        id<SecuritydXPCProtocol> rpc = SecuritydXPCProxyObject(false, ^(NSError *error) {
            complete((__bridge CFErrorRef) error);
        });
        [rpc secItemUnsetCurrentItemsAcrossAllDevices:(__bridge NSString*)accessGroup
                                          identifiers:(__bridge NSArray<NSString*>*)identifiers
                                             viewHint:(__bridge NSString*)viewHint
                                             complete:^(NSError* operror) {
            complete((__bridge CFErrorRef) operror);
        }];
    }
}

void SecItemFetchCurrentItemOutOfBand(NSArray<CKKSCurrentItemQuery*>* currentItemQueries, bool forceFetch, void (^complete)(NSArray<CKKSCurrentItemQueryResult*>* currentItems, NSError* error)) {
    os_activity_t activity = os_activity_create("fetchCurrentItemOutOfBand", OS_ACTIVITY_CURRENT, OS_ACTIVITY_FLAG_DEFAULT);
    os_activity_scope(activity);

    @autoreleasepool {
        id<SecuritydXPCProtocol> rpc = SecuritydXPCProxyObject(false, ^(NSError *error) {
            complete(nil, error);
        });

        [rpc secItemFetchCurrentItemOutOfBand:currentItemQueries
                                   forceFetch:forceFetch
                                     complete:^(NSArray* currentItems, NSError* operror) {
            complete(currentItems, operror);
        }];
    }
}

void SecItemFetchPCSIdentityOutOfBand(NSArray<CKKSPCSIdentityQuery*>* pcsIdentityQueries, bool forceFetch, void (^complete)(NSArray<CKKSPCSIdentityQueryResult*>* pcsIdentities, NSError* error)) {
    os_activity_t activity = os_activity_create("fetchPCSIdentityOutOfBand", OS_ACTIVITY_CURRENT, OS_ACTIVITY_FLAG_DEFAULT);
    os_activity_scope(activity);

    @autoreleasepool {
        id<SecuritydXPCProtocol> rpc = SecuritydXPCProxyObject(false, ^(NSError *error) {
            complete(nil, error);
        });
        
        [rpc secItemFetchPCSIdentityByKeyOutOfBand:pcsIdentityQueries
                                        forceFetch:forceFetch
                                          complete:^(NSArray* pcsIdentities, NSError* operror) {
            complete(pcsIdentities, operror);
        }];
    }
}

@interface SecItemCurrentItemData ()
- (instancetype)initWithPersistentRef:(NSData *)persistentRef;
@property (strong, readwrite, nonnull) NSData *persistentRef;
@property (strong, readwrite, nullable) NSDate *currentItemPointerModificationTime;
@end

@implementation SecItemCurrentItemData
- (instancetype)initWithPersistentRef:(NSData *)persistentRef {
    if ((self = [super init]) == nil) {
        return nil;
    }
    self.persistentRef = persistentRef;
    return self;
}
@end

void
SecItemFetchCurrentItemDataAcrossAllDevices(NSString *accessGroup,
                                            NSString *identifier,
                                            NSString *viewHint,
                                            BOOL fetchCloudValue,
                                            void (^complete)(SecItemCurrentItemData * _Nullable persistentRef, NSError * _Nullable error))
{
    os_activity_t activity = os_activity_create("SecItemFetchCurrentItemDataAcrossAllDevices", OS_ACTIVITY_CURRENT, OS_ACTIVITY_FLAG_DEFAULT);
    os_activity_scope(activity);

    @autoreleasepool {
        id<SecuritydXPCProtocol> rpc = SecuritydXPCProxyObject(false, ^(NSError *error) {
            complete(nil, error);
        });
        [rpc secItemFetchCurrentItemAcrossAllDevices:accessGroup
                                          identifier:identifier
                                            viewHint:viewHint
                                     fetchCloudValue:fetchCloudValue
                                            complete: ^(NSData* persistentRef, NSDate * _Nullable cipModificationTime, NSError* operror) {
            SecItemCurrentItemData *cip = nil;
            if (persistentRef) {
                cip = [[SecItemCurrentItemData alloc] initWithPersistentRef:persistentRef];
                cip.currentItemPointerModificationTime = cipModificationTime;
            }
            complete(cip, operror);
        }];
    }
}
