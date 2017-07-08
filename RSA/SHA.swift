//
//  SHA.swift
//  RSA
//
//  Created by pebble8888 on 2017/05/31.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation

protocol MDHashable {
    func hash(_ v:[UInt8]) -> [UInt8]
    func length() -> UInt
}

struct SHA512 : MDHashable {
    func hash(_ v:[UInt8]) -> [UInt8] {
        let data:NSData = Data(bytes: v) as NSData
        let outdata:Data = data.cryptRSA_SHA512() as Data
        return [UInt8](outdata)
    }
    func length() -> UInt {
        return UInt(NSData.sha512Length()) 
    }
}
