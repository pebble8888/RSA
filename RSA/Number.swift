//
//  Number.swift
//  RSA
//
//  Created by pebble8888 on 2017/08/14.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation
import BigInt

func isOdd(_ x:BigUInt) -> Bool {
    return (x % 2) == 1
}

func isEven(_ x:BigUInt) -> Bool {
    return !isOdd(x)
}

func isPrime(_ x:BigUInt) -> Bool {
    if x == 2 { return true }
    if x < 2 || isEven(x) { return false }
    var i:BigUInt = 3
    while i * i <= x {
        if x % i == 0 {
            return false
        }
        i = i.advanced(by: 2)
    }
    return true
}

func expmod(_ b:BigUInt, _ e:BigUInt, _ p:BigUInt) -> BigUInt {
    if e == 0 { return 1 }
    let s = expmod(b, e/2, p)
    let r = (s * s) % p
    if isOdd(e) {
        return (r * b) % p
    } else {
        return r
    }
}
