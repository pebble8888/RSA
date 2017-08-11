//
//  BigInt+RSA.swift
//  RSA
//
//  Created by pebble8888 on 2017/08/11.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation
import BigInt

extension BigInt {
    // RFC 3447 PKCS #1
    // convert bignary Integer format to BigInt
    // leftmost bit is sign
    public init(data:Data){
        self.abs = 0
        self.negative = false
        // big endian
        var i:Int = 0
        let ary = [UInt8](data)
        let count:Int = ary.count
        for d in ary {
            let v:BigUInt = BigUInt(d) << (8 * (count - i - 1))
            self.abs += v
            i += 1
        }
        // leftmost bit is sign
        if count > 0 && ((ary[0] & UInt8(0x80)) != 0) {
            let v:BigUInt = BigUInt(1) << (8 * count)
            self -= BigInt(v)
        }
    }
}
