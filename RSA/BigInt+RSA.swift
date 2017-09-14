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
        self.magnitude = 0
        self.sign = .minus
        // big endian
        var i:Int = 0
        let ary = [UInt8](data)
        let count:Int = ary.count
        for d in ary {
            let v:BigUInt = BigUInt(d) << (8 * (count - i - 1))
            self.magnitude += v
            i += 1
        }
        // leftmost bit is sign
        if count > 0 && ((ary[0] & UInt8(0x80)) != 0) {
            let v:BigUInt = BigUInt(1) << (8 * count)
            self -= BigInt(v)
        }
    }
}

fileprivate let smallPrimes:[UInt8] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]

extension BigUInt {
    // we think only positive for simplicity
    private static func randomPositiveOdd(withExactWidth width:UInt) -> BigUInt {
        let v = BigUInt.randomInteger(withExactWidth: Int(width))
        // odd number
        return v | 1
    }
    
    public static func generatePrime(withExactWidth width:UInt) -> BigUInt {
        while true {
            // create random odd
            let p = randomPositiveOdd(withExactWidth: width)
            let delta_max = 1 << 20 // 1048576
            
            delta_loop:
            for delta in Swift.stride(from: 0, to: delta_max, by: 2) {
                let target = p + BigUInt(delta)
                // check by fermet test for small primes
                if target.isSmallPrimeFermet() {
                    let miller_rabin_repeat_count = 20
                    for _ in 0..<miller_rabin_repeat_count {
                        // 2 <= a <= target-1
                        let base_minus_3 = BigUInt.randomInteger(lessThan: target-3)
                        let base = base_minus_3 + 3
                        // check by miller rabin test
                        if target.isStrongProbablePrime(base) {
                            // we must check width because width of (p + delta) might
                            // be more width
                            if UInt(target.bitWidth) == width {
                                return target
                            } else {
                                // over width
                                break delta_loop
                            }
                        }
                    }
                }
            }
        }
    }
    
    // fermat test for smallprimes
    private func isSmallPrimeFermet() -> Bool {
        for i in smallPrimes {
            if (self % BigUInt(i)) == 0 {
                // composite
                return false
            }
        }
        // prime
        return true
    }
}
