//
//  RFC3447.swift
//
//  Created by pebble8888 on 2017/05/31.
//  Copyright © 2017年 pebble8888. All rights reserved.
// 
// RFC3447
//

import Foundation
import BigInt

// TODO:鍵ファイルをASNパースしてRSA鍵情報を取り出すところが未着手
//      -> privatekeyについては完了
// RSAメッセージを暗号化する処理は実装済み
func aa() {
    
    let a:BigInt = 0
}



enum CryptRSA_DECODE_PKCS1_OAEP_MGF_Error : Error {
    case decodeError
}

func DECODE_PKCS1_OAEP_MGF(keylen:UInt, // RSAキーの長さ　バイト数
                            keymod:UInt, // RSAキーの法
                            encoded_msg:[UInt8], // ?
                            label:[UInt8], // ?
                            labelhash:MDHashable,
                            mgfhash:MDHashable) throws -> [UInt8]
{
    // tlen : 
    // flen :メッセージ長
    let hlen = labelhash.length()
    if encoded_msg.count <= 0 || keylen <= 0 {
        throw CryptRSA_DECODE_PKCS1_OAEP_MGF_Error.decodeError
    }
    if keymod < UInt(encoded_msg.count) || keymod < 2 * hlen + 2 {
        throw CryptRSA_DECODE_PKCS1_OAEP_MGF_Error.decodeError
    }
    let hash:[UInt8] = labelhash.hash(label)
    let Y:UInt8 = encoded_msg[0]
    let maskedSeed:[UInt8] = Array(encoded_msg[1..<1+Int(hlen)])
    let maskedDB:[UInt8] = Array(encoded_msg[1 + Int(hlen)..<encoded_msg.count])
    let seedMask:[UInt8] = try PKCS1_MGF(mgfSeed: maskedDB, maskLen: hlen, hash: mgfhash)
    let seed:[UInt8] = zip(maskedSeed, seedMask).map{$0 ^ $1}
    let dbMask:[UInt8] = try PKCS1_MGF(mgfSeed: seed, maskLen: keymod - hlen, hash: mgfhash)
    let db:[UInt8] = zip(maskedDB, dbMask).map{$0 ^ $1}
    let hashDash:[UInt8] = Array(db[0..<Int(hlen)])
    var msg:[UInt8]?
    for i in 0..<db.count {
        if db[Int(hlen)+i] != 0 {
            if db[Int(hlen)+i] == 1 { 
                msg = Array(db[Int(hlen)+i+1..<db.count])
            }
            break
        }
    }
    guard let l_msg = msg, hash == Array(hashDash), Y == 0 else {
        throw CryptRSA_DECODE_PKCS1_OAEP_MGF_Error.decodeError
    }
    return l_msg
}
                            
enum CryptRSA_ENCODE_PKCS1_OAEP_MGF : Error {
    case dataTooLargeForKeySize
    case keySizeTooSmall
}

func ENCODE_PKCS1_OAEP_MGF(keylen:UInt, // RSAキーの長さ バイト数
                         msg:[UInt8],
                         label:[UInt8],
                         labelhash:MDHashable,
                         mgfhash:MDHashable) throws -> [UInt8]
{
    let hlen = labelhash.length()
    if msg.count > Int(keylen) - 2 * Int(hlen) - 2 {
        throw CryptRSA_ENCODE_PKCS1_OAEP_MGF.dataTooLargeForKeySize
    }
    if keylen < 2 * hlen + 2 {
        throw CryptRSA_ENCODE_PKCS1_OAEP_MGF.keySizeTooSmall
    }
    // hLen
    var db:[UInt8] = labelhash.hash(label)
    // PS
    let ps:[UInt8] = [UInt8](repeating:0, count:Int(keylen) - msg.count - 2 * Int(hlen) - 2)
    db.append(contentsOf: ps)
    // 0x01
    db.append(UInt8(0x01))
    // M
    db.append(contentsOf:msg)
    //
    let seed:[UInt8] = random(hlen)
    // e. MGF
    let dbmask:[UInt8] = try PKCS1_MGF(mgfSeed: seed, maskLen: UInt(Int(keylen) - Int(hlen) - 1), hash: mgfhash)
    // f. xor
    let db_xor:[UInt8] = zip(db, dbmask).map{$0 ^ $1}
    // g. MGF
    let seedmask:[UInt8] = try PKCS1_MGF(mgfSeed: db_xor, maskLen: hlen, hash: mgfhash)
    // h. seed xor
    let seed_xor:[UInt8] = zip(seed, seedmask).map{$0 ^ $1}
    
    var r:[UInt8] = [0]
    r.append(contentsOf: seed_xor)
    r.append(contentsOf: db_xor)
    return r
}

// TODO:[UInt8]に対する+演算子

func random(_ len:UInt) -> [UInt8]
{
    // TODO:arc4random_uniform is not swift function
    return (0..<len).map{ _ in UInt8(arc4random_uniform(256)) }
}

enum CryptRSA_MGF1_Error : Error {
    case maskTooLong
}

// @param maskLen: 出力サイズ
func PKCS1_MGF(mgfSeed:Array<UInt8>, maskLen:UInt, hash:MDHashable) throws -> [UInt8] {
    let hLen:UInt = hash.length()
    let v:UInt = pow(2, 32)
    if maskLen > v * hLen {
        throw CryptRSA_MGF1_Error.maskTooLong
    }
    var t:[UInt8] = []
    for counter in 0 ..< UInt(ceil(Double(maskLen)/Double(hLen))) {
        var v:[UInt8] = [UInt8](mgfSeed)
        v.append(contentsOf: try I2OSP(counter, 4))
        t.append(contentsOf:hash.hash(v))
    }
    return Array(t[0..<Int(maskLen)])
}

enum CryptRSA_I2OSP_Error : Error {
    case integerTooLarge
}

func I2OSP(_ x:UInt, _ xLen:UInt) throws -> [UInt8] {
    if x >= pow(256, xLen) {
        throw CryptRSA_I2OSP_Error.integerTooLarge
    }
    return (0..<xLen).map{UInt8(x >> (8 * $0)) & UInt8(255)}
}

// overflow crash
func pow(_ base: UInt, _ power: UInt) -> UInt {
    if power == 0 {
        return 1
    }
    var result = base
    var remain = power - 1
    while remain > 0 {
        result *= base
        remain -= 1
    }
    return result
}
