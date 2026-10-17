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
// Unchanged Apple value-class bodies from db15acbe6a7f257a859ad9a3bb86097bfe0679d9; RPC entry points are separate.
#import "SecItemFetchOutOfBandValues.h"
@implementation CKKSCurrentItemQuery
- (instancetype)initWithIdentifier:(NSString*)identifier
                       accessGroup:(NSString*)accessGroup
                            zoneID:(NSString*)zoneID
{
    if (self = [super init]) {
        _identifier = identifier;
        _accessGroup = accessGroup;
        _zoneID = zoneID;
    }
    return self;
}

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (NSString*)description {
    return [NSString stringWithFormat:@"<CKKSCurrentItemQuery(%@-%@): %@>",
            self.zoneID,
            self.accessGroup,
            self.identifier];
}

- (void)encodeWithCoder:(nonnull NSCoder *)coder {
    [coder encodeObject:self.identifier forKey:@"identifier"];
    [coder encodeObject:self.accessGroup forKey:@"accessGroup"];
    [coder encodeObject:self.zoneID forKey:@"zoneID"];
}

- (nullable instancetype)initWithCoder:(nonnull NSCoder *)coder {

    if ((self = [super init])) {
        _identifier = [coder decodeObjectOfClass:[NSString class] forKey:@"identifier"];
        _accessGroup = [coder decodeObjectOfClass:[NSString class] forKey:@"accessGroup"];
        _zoneID = [coder decodeObjectOfClass:[NSString class] forKey:@"zoneID"];
    }
    return self;
}

@end

@implementation CKKSCurrentItemQueryResult
- (instancetype)initWithIdentifier:(NSString*)identifier
                       accessGroup:(NSString*)accessGroup
                            zoneID:(NSString*)zoneID
                   decryptedRecord:(NSDictionary*)decryptedRecord
{
    if (self = [super init]) {
        _identifier = identifier;
        _accessGroup = accessGroup;
        _zoneID = zoneID;
        _decryptedRecord = decryptedRecord;
    }
    return self;
}

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (NSString*)description {
    return [NSString stringWithFormat:@"<CKKSCurrentItemQueryResult(%@-%@): %@>",
            self.zoneID,
            self.accessGroup,
            self.identifier];
}

- (void)encodeWithCoder:(nonnull NSCoder *)coder {
    [coder encodeObject:self.identifier forKey:@"identifier"];
    [coder encodeObject:self.accessGroup forKey:@"accessGroup"];
    [coder encodeObject:self.zoneID forKey:@"zoneID"];
    [coder encodeObject:self.decryptedRecord forKey:@"decryptedRecord"];
}

- (nullable instancetype)initWithCoder:(nonnull NSCoder *)coder {

    if ((self = [super init])) {
        _identifier = [coder decodeObjectOfClass:[NSString class] forKey:@"identifier"];
        _accessGroup = [coder decodeObjectOfClass:[NSString class] forKey:@"accessGroup"];
        _zoneID = [coder decodeObjectOfClass:[NSString class] forKey:@"zoneID"];

        NSSet *allowedClasses = [NSSet setWithArray:@[[NSString class], [NSNumber class], [NSData class], [NSDate class], [NSDictionary class]]];
        _decryptedRecord = [coder decodeObjectOfClasses:allowedClasses forKey:@"decryptedRecord"];

    }
    return self;
}

@end

@implementation CKKSPCSIdentityQuery
- (instancetype)initWithServiceNumber:(NSNumber*)serviceNumber
                          accessGroup:(NSString*)accessGroup
                            publicKey:(NSString*)publicKey
                               zoneID:(NSString*)zoneID
{
    if (self = [super init]) {
        _serviceNumber = serviceNumber;
        _accessGroup = accessGroup;
        _publicKey = publicKey;
        _zoneID = zoneID;
    }
    return self;
}

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (NSString*)description {
    return [NSString stringWithFormat:@"<CKKSPCSIdentityQuery(%@): %@>",
            self.zoneID,
            self.serviceNumber];
}

- (void)encodeWithCoder:(nonnull NSCoder *)coder {
    [coder encodeObject:self.serviceNumber forKey:@"serviceNumber"];
    [coder encodeObject:self.accessGroup forKey:@"accessGroup"];
    [coder encodeObject:self.zoneID forKey:@"zoneID"];
    [coder encodeObject:self.publicKey forKey:@"publicKey"];
}

- (nullable instancetype)initWithCoder:(nonnull NSCoder *)coder {

    if ((self = [super init])) {
        _serviceNumber = [coder decodeObjectOfClass:[NSNumber class] forKey:@"serviceNumber"];
        _accessGroup = [coder decodeObjectOfClass:[NSString class] forKey:@"accessGroup"];
        _zoneID = [coder decodeObjectOfClass:[NSString class] forKey:@"zoneID"];
        _publicKey = [coder decodeObjectOfClass:[NSString class] forKey:@"publicKey"];
    }
    return self;
}

@end

@implementation CKKSPCSIdentityQueryResult
- (instancetype)initWithServiceNumber:(NSNumber*)serviceNumber
                            publicKey:(NSString*)publicKey
                               zoneID:(NSString*)zoneID
                      decryptedRecord:(NSDictionary*)decryptedRecord
{
    if (self = [super init]) {
        _serviceNumber = serviceNumber;
        _publicKey = publicKey;
        _zoneID = zoneID;
        _decryptedRecord = decryptedRecord;
    }
    return self;
}

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (NSString*)description {
    return [NSString stringWithFormat:@"<CKKSPCSIdentityQueryResult(%@): %@>",
            self.zoneID,
            self.serviceNumber];
}

- (void)encodeWithCoder:(nonnull NSCoder *)coder {
    [coder encodeObject:self.serviceNumber forKey:@"serviceNumber"];
    [coder encodeObject:self.zoneID forKey:@"zoneID"];
    [coder encodeObject:self.publicKey forKey:@"publicKey"];
    [coder encodeObject:self.decryptedRecord forKey:@"decryptedRecord"];
    
}

- (nullable instancetype)initWithCoder:(nonnull NSCoder *)coder {

    if ((self = [super init])) {
        _serviceNumber = [coder decodeObjectOfClass:[NSNumber class] forKey:@"serviceNumber"];
        _zoneID = [coder decodeObjectOfClass:[NSString class] forKey:@"zoneID"];
        _publicKey = [coder decodeObjectOfClass:[NSString class] forKey:@"publicKey"];

        NSSet *allowedClasses = [NSSet setWithArray:@[[NSString class], [NSNumber class], [NSData class], [NSDate class], [NSDictionary class]]];
        _decryptedRecord = [coder decodeObjectOfClasses:allowedClasses forKey:@"decryptedRecord"];

    }
    return self;
}

@end
