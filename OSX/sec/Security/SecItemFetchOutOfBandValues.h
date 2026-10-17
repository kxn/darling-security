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
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface CKKSCurrentItemQuery : NSObject <NSSecureCoding>
@property (nullable, strong) NSString* identifier;
@property (nullable, strong) NSString* accessGroup;
@property (nullable, strong) NSString* zoneID;

- (instancetype)initWithIdentifier:(NSString*)identifier accessGroup:(NSString*)accessGroup zoneID:(NSString*)zoneID;
@end

@interface CKKSCurrentItemQueryResult : NSObject <NSSecureCoding>
@property (nullable, strong) NSString* identifier;
@property (nullable, strong) NSString* accessGroup;
@property (nullable, strong) NSString* zoneID;
@property (nullable, strong) NSDictionary* decryptedRecord;

- (instancetype)initWithIdentifier:(NSString*)identifier accessGroup:(NSString*)accessGroup zoneID:(NSString*)zoneID decryptedRecord:(NSDictionary*)decryptedRecord;
@end

@interface CKKSPCSIdentityQuery : NSObject <NSSecureCoding>
@property (nullable, strong) NSNumber* serviceNumber;
@property (nullable, strong) NSString* accessGroup;
@property (nullable, strong) NSString* publicKey; // public key as a base-64 encoded string
@property (nullable, strong) NSString* zoneID;

- (instancetype)initWithServiceNumber:(NSNumber*)serviceNumber accessGroup:(NSString*)accessGroup publicKey:(NSString*)publicKey zoneID:(NSString*)zoneID;
@end

@interface CKKSPCSIdentityQueryResult : NSObject <NSSecureCoding>
@property (nullable, strong) NSNumber* serviceNumber;
@property (nullable, strong) NSString* publicKey; // public key as a base-64 encoded string
@property (nullable, strong) NSString* zoneID;
@property (nullable, strong) NSDictionary* decryptedRecord;

- (instancetype)initWithServiceNumber:(NSNumber*)serviceNumber publicKey:(NSString*)publicKey zoneID:(NSString*)zoneID decryptedRecord:(NSDictionary*)decryptedRecord;
@end
NS_ASSUME_NONNULL_END
