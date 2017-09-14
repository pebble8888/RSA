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
    case tooSmallBitWidth
}

public class PrivateRSAKey: RSAKey, CustomStringConvertible {
    
    /// Original data of the private key.
    /// Note that it does not contain PEM headers and holds data as bytes, not as a base 64 string.
    public var originalData: Data?
    
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
        if let v = inverseOfQModP { s += "inverseOfQModP:\(v)\n" }
        return s
    }
    
    public init(bitWidth:UInt) throws {
        if (bitWidth < 16){
            throw RSAError.tooSmallBitWidth
        }
        let e = BigUInt(65537) // 65537 = 0x10001 is prime
        
        let bitWidthP = (bitWidth + 1)/2
        let bitWidthQ = bitWidth - bitWidthP
        
        repeat {
            // gcd(p-1,e) == 1
            var p:BigUInt
            repeat {
                p = BigUInt.generatePrime(withExactWidth: bitWidthP)
                let r = (p-1).greatestCommonDivisor(with: e)
                if r == 1 {
                    break
                }
            } while true
            
            // p != q
            var q:BigUInt
            repeat {
                q = BigUInt.generatePrime(withExactWidth: bitWidthQ)
            } while p == q
            
            // gcd(q-1,e) == 1
            repeat {
                let r = (q-1).greatestCommonDivisor(with: e)
                if r == 1 {
                    break
                }
            } while true
            
            // p > q
            if p < q {
                let t = p
                p = q
                q = t
            }
            
            // n = p * q
            let n = p * q
            
            // d = e ^ -1 mod (p-1)*(q-1)
            let m = (p-1)*(q-1)
            guard let d = e.inverse(m) else {
                continue
            }
            
            // d mod (p-1)
            let dp1 = d % (p-1)
            
            // d mod (q-1)
            let dq1 = d % (q-1)
            
            // q ^ -1 mod p
            guard let invQP = q.inverse(p) else {
                continue
            }
            
            // success
            self.rsaVersion = 0
            self.modulus = BigInt(n)
            self.exponentE = BigInt(e)
            self.exponentD = BigInt(d)
            self.primeP = BigInt(p)
            self.primeQ = BigInt(q)
            self.dModPMinus1 = BigInt(dp1)
            self.dModQMinus1 = BigInt(dq1)
            self.inverseOfQModP = BigInt(invQP)
            break
        } while true
    }
    
}

