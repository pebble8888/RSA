//
//  NSData+SHA.h
//  RSA
//
//  Created by pebble8888 on 2017/05/31.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (NSData_CryptRSA)
+ (uint16_t)sha1Length;
+ (uint16_t)sha256Length;
+ (uint16_t)sha512Length;
- (nonnull NSData*)cryptRSA_SHA1;
- (nonnull NSData*)cryptRSA_SHA256;
- (nonnull NSData*)cryptRSA_SHA512;
@end
