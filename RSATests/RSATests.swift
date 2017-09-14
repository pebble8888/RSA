//
//  RSATests.swift
//  RSATests
//
//  Created by pebble8888 on 2017/05/31.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import XCTest
@testable import RSA
@testable import BigInt

class RSATests: XCTestCase {
    
    let bundle = Bundle(for: RSATests.self)
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func test_private_decrypt() throws {
        guard let path = bundle.path(forResource:"private-key", ofType:"pem") else {
            return XCTFail()
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        let privateKey = try PrivateRSAKey(pemEncoded: str)
        print("\(privateKey)")
    }
    
    func test_gen_prime() {
        for _ in 0..<10 {
            let a = BigUInt.generatePrime(withExactWidth: 9)
            print("\(a)")
        }
    }
    
    func test_gen_privateKey() throws {
        let key = try PrivateRSAKey(bitWidth: 16)
        print("\(key)")
    }
    
    func test_PKCS1_OAEP_MGF() {
        guard let enc = try? ENCODE_PKCS1_OAEP_MGF(
                              keylen: 2048/8, 
                              msg: [0, 1, 2, 3],
                              label: [4, 5, 6, 7], 
                              labelhash: SHA512(), mgfhash: SHA512()) else {
            XCTAssertTrue(false)
            return
        }
        print("\(enc.hexDescription())")
        
        guard let dec = try? DECODE_PKCS1_OAEP_MGF(
                              keylen: 2048/8,
                              keymod: 512,
                              encoded_msg: enc,
                              label: [4, 5, 6, 7],
                              labelhash: SHA512(),
                              mgfhash: SHA512()) else {
            XCTAssertTrue(false)
            return
        }
        print("\(dec.hexDescription())")
        
        XCTAssert(dec == [0, 1, 2, 3])
    }
    
    
}
