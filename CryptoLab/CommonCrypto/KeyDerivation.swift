//
//  KeyDerivation.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import CommonCrypto
import Foundation

public extension Crypto
{
	enum PBKDF {
		public enum Algorithm: Int {
			case pbkdf2 = 2		// kCCPBKDF2
		}

		public enum PseudoRandomAlgorithm: Int {
			case sha1 = 1		// kCCPRFHmacAlgSHA1
			case sha224			// kCCPRFHmacAlgSHA224
			case sha256			// kCCPRFHmacAlgSHA256
			case sha384			// kCCPRFHmacAlgSHA384
			case sha512			// kCCPRFHmacAlgSHA512
		}

		public static func keyDerivation(algorithm: Algorithm = .pbkdf2, password: UnsafePointer<Int8>?, passwordLength: Int, salt: UnsafePointer<UInt8>?, saltLength: Int, pseudoRandomAlgorithm: PseudoRandomAlgorithm, rounds: Int, derivedKey: UnsafeMutablePointer<UInt8>?, derivedKeyLength: Int) -> Status {
			let status = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(algorithm.rawValue), password, passwordLength, salt, saltLength, CCPseudoRandomAlgorithm(pseudoRandomAlgorithm.rawValue), UInt32(rounds),
											  derivedKey, derivedKeyLength)
			return Status(rawValue: Int(status)) ?? .unspecifiedError
		}

		public static func calibrate(algorithm: Algorithm = .pbkdf2, passwordLength: Int, saltLength: Int, pseudoRandomAlgorithm: PseudoRandomAlgorithm, derivedKeyLength: Int, milliseconds: Int) -> Int {
			return Int(CCCalibratePBKDF(CCPBKDFAlgorithm(algorithm.rawValue), passwordLength, saltLength, CCPseudoRandomAlgorithm(pseudoRandomAlgorithm.rawValue), derivedKeyLength, UInt32(milliseconds)))
		}
	}
}

// MARK: - Convenience extensions

public extension Crypto.PBKDF
{
	static func deriveKey(algorithm: Algorithm = .pbkdf2, password: String, salt: Data, pseudoRandomAlgorithm: PseudoRandomAlgorithm, iterations: Int, desiredKeyLength: Int) throws -> Data {
		guard let result = NSMutableData(length: desiredKeyLength) else { throw Crypto.Status.memoryFailure }
		let status = self.keyDerivation(algorithm: algorithm, password: password, passwordLength: strlen(password), salt: (salt as NSData).bytes.assumingMemoryBound(to: UInt8.self), saltLength: salt.count, pseudoRandomAlgorithm: pseudoRandomAlgorithm, rounds: iterations, derivedKey: result.mutableBytes.assumingMemoryBound(to: UInt8.self), derivedKeyLength: desiredKeyLength)
		guard case status = Crypto.Status.success else { throw status }
		return result as Data
	}

	static func iterationsForDesiredTime(algorithm: Algorithm = .pbkdf2, passwordLength: Int, saltLength: Int, pseudoRandomAlgorithm: PseudoRandomAlgorithm, desiredKeyLength: Int, desiredTime: TimeInterval) -> Int {
		return self.calibrate(algorithm: algorithm, passwordLength: passwordLength, saltLength: saltLength, pseudoRandomAlgorithm: pseudoRandomAlgorithm, derivedKeyLength: desiredKeyLength, milliseconds: Int(round(desiredTime*1000.0)))
	}
}
