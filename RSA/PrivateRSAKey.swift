//
//  PrivateRSAKey.swift
//  SwiftyRSA
//
//  Created by Lois Di Qual on 5/17/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import Foundation
import BigInt

public enum RSAError: Error {
    case invalidPrivateKey(message:String)
}

public class PrivateRSAKey: RSAKey, CustomStringConvertible {
    
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

    required public init(data: Data) throws {
        self.originalData = data
        
        //print("data:\n\(data.hexDescription())\n")
        //let dataWithoutHeader = try SwiftyRSA.stripKeyHeader(keyData: data)
        //print("dataWithoutHeader:\n\(dataWithoutHeader.hexDescription())\n")
        
        let node = try Asn1Parser.parse(data: data)
        //print("\(node)")
        if case .sequence(let nodes) = node {
            var i = nodes.makeIterator()
            guard let v1 = i.next() else {
                throw RSAError.invalidPrivateKey(message: "have not enough data")
            }
            if case .integer(let v) = v1 { rsaVersion = BigInt(data:v) }
            guard let v2 = i.next() else {
                throw RSAError.invalidPrivateKey(message: "have not enough data")
            }
            if case .integer(let v) = v2 { modulus = BigInt(data:v) }
            guard let v3 = i.next() else {
                throw RSAError.invalidPrivateKey(message: "have not enough data")
            }
            if case .integer(let v) = v3 { exponentE = BigInt(data:v) }
            guard let v4 = i.next() else {
                throw RSAError.invalidPrivateKey(message: "have not enough data")
            }
            if case .integer(let v) = v4 { exponentD = BigInt(data:v) }
            guard let v5 = i.next() else {
                throw RSAError.invalidPrivateKey(message: "have not enough data")
            }
            if case .integer(let v) = v5 { primeP = BigInt(data:v) }
            guard let v6 = i.next() else {
                throw RSAError.invalidPrivateKey(message: "have not enough data")
            }
            if case .integer(let v) = v6 { dModPMinus1 = BigInt(data:v) }
            guard let v7 = i.next() else {
                throw RSAError.invalidPrivateKey(message: "have not enough data")
            }
            if case .integer(let v) = v7 { dModQMinus1 = BigInt(data:v) }
            guard let v8 = i.next() else {
                throw RSAError.invalidPrivateKey(message: "have not enough data")
            }
            if case .integer(let v) = v8 { inverseOfQModP = BigInt(data:v) }
        } else {
            throw RSAError.invalidPrivateKey(message: "root is not sequence")
        }
    }
    
    private var rsaVersion:BigInt?
    private var modulus:BigInt?
    private var exponentE:BigInt?
    private var exponentD:BigInt?
    private var primeP:BigInt?
    private var primeQ:BigInt?
    private var dModPMinus1:BigInt?
    private var dModQMinus1:BigInt?
    private var inverseOfQModP:BigInt?
    
    public var description: String
    {
        var s:String = ""
        if let v = rsaVersion { s += "rsaVersion:\(v)\n" }
        if let v = modulus { s += "modulus:\(v)\n" }
        if let v = exponentE { s += "exponentE:\(v)\n" }
        if let v = exponentD { s += "exponentD:\(v)\n" }
        if let v = primeP { s += "primeP:\(v)\n" }
        if let v = primeQ { s += "primeQ:\(v)\n" }
        if let v = dModPMinus1 { s += "dModPMinus1:\(v)\n" }
        if let v = dModQMinus1 { s += "dModQMinus1:\(v)\n" }
        return s
    }
    
}

