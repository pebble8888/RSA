//
//  PrivateRSAKey.swift
//  SwiftyRSA
//
//  Created by Lois Di Qual on 5/17/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import Foundation

public class PrivateRSAKey: RSAKey {
    
    /// Reference to the key within the keychain
    //public let reference: SecKey
    
    /// Original data of the private key.
    /// Note that it does not contain PEM headers and holds data as bytes, not as a base 64 string.
    public let originalData: Data?
    
    //let tag: String?
    
    /// Returns a PEM representation of the private key.
    ///
    /// - Returns: Data of the key, PEM-encoded
    /// - Throws: SwiftyRSAError
    public func pemString() throws -> String {
        let data = try self.data()
        let pem = SwiftyRSA.format(keyData: data, withPemType: "RSA PRIVATE KEY")
        return pem
    }

    
    /// Creates a private key with a RSA public key data.
    ///
    /// - Parameter data: Private key data
    /// - Throws: SwiftyRSAError
    required public init(data: Data) throws {
        self.originalData = data
        //let tag = UUID().uuidString
        //self.tag = tag
        
        print("\(data.hexDescription())")
        // ASNパースした結果
        let dataWithoutHeader = try SwiftyRSA.stripKeyHeader(keyData: data)
        //print("\(dataWithoutHeader.hexDescription())")
        // TODO:
        //reference = try SwiftyRSA.addKey(dataWithoutHeader, isPublic: false, tag: tag)
    }
 
}

