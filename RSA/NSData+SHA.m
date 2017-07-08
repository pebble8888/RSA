//
//  NSData+SHA.m
//  RSA
//
//  Created by pebble8888 on 2017/05/31.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

#import "NSData+SHA.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation NSData (NSData_CryptRSA)
+ (uint16_t)sha1Length {
    return CC_SHA1_DIGEST_LENGTH;
}
+ (uint16_t)sha256Length {
    return CC_SHA256_DIGEST_LENGTH;
}
+ (uint16_t)sha512Length {
    return CC_SHA512_DIGEST_LENGTH;
}
- (nonnull NSData*)cryptRSA_SHA1 {
    uint16_t buflen = CC_SHA1_DIGEST_LENGTH;
    uint8_t buf[buflen];
    CC_SHA1(self.bytes, (CC_LONG)self.length, buf); 
    return [NSData dataWithBytes:buf length:buflen];
}

- (nonnull NSData*)cryptRSA_SHA256 {
    uint16_t buflen = CC_SHA256_DIGEST_LENGTH;
    uint8_t buf[buflen];
    CC_SHA256(self.bytes, (CC_LONG)self.length, buf); 
    return [NSData dataWithBytes:buf length:buflen];
}

- (nonnull NSData*)cryptRSA_SHA512 {
    uint16_t buflen = CC_SHA512_DIGEST_LENGTH;
    uint8_t buf[buflen];
    CC_SHA512(self.bytes, (CC_LONG)self.length, buf); 
    return [NSData dataWithBytes:buf length:buflen];
}
@end
