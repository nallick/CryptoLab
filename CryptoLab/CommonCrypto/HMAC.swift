//
//  HMAC.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import CommonCrypto
import Foundation

public extension Crypto
{
	class HMAC {
		public let algorithm: Algorithm
		private let context = UnsafeMutablePointer<CCHmacContext>.allocate(capacity: 1)

		public enum Algorithm: Int {
			case sha1		// kCCHmacAlgSHA1
			case md5		// kCCHmacAlgMD5
			case sha256		// kCCHmacAlgSHA256
			case sha384		// kCCHmacAlgSHA384
			case sha512		// kCCHmacAlgSHA512
			case sha224		// kCCHmacAlgSHA224

			var byteCount: Int {
				switch self {
					case .md5: return Int(CC_MD5_DIGEST_LENGTH)
					case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
					case .sha224: return Int(CC_SHA224_DIGEST_LENGTH)
					case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
					case .sha384: return Int(CC_SHA384_DIGEST_LENGTH)
					case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
				}
			}
		}

		public init(algorithm: Algorithm, key: UnsafeRawPointer, keyLength: Int) {
			self.algorithm = algorithm
			CCHmacInit(self.context, CCHmacAlgorithm(algorithm.rawValue), key, keyLength)
		}

		public func update(data: UnsafeRawPointer, dataLength: Int) {
			CCHmacUpdate(self.context, data, dataLength)
		}

		public func final(_ dataOut: UnsafeMutableRawPointer) {
			CCHmacFinal(self.context, dataOut)
		}

		public static func generate(algorithm: Algorithm, key: UnsafeRawPointer, keyLength: Int, data: UnsafeRawPointer, dataLength: Int, dataOut: UnsafeMutableRawPointer) {
			CCHmac(CCHmacAlgorithm(algorithm.rawValue), key, keyLength, data, dataLength, dataOut)
		}

		deinit {
			self.context.deallocate()
		}
	}
}

// MARK: - Convenience extensions

public extension Crypto.HMAC
{
	convenience init(algorithm: Algorithm, key: Data) {
		self.init(algorithm: algorithm, key: (key as NSData).bytes, keyLength: key.count)
	}

	func update(data: Data) {
		self.update(data: (data as NSData).bytes, dataLength: data.count)
	}

	func final() throws -> Data {
		guard let result = NSMutableData(length: self.algorithm.byteCount) else { throw Crypto.Status.memoryFailure }
		self.final(result.mutableBytes)
		return result as Data
	}

	static func generate(algorithm: Algorithm, key: Data, data: Data) throws -> Data {
		guard let result = NSMutableData(length: algorithm.byteCount) else { throw Crypto.Status.memoryFailure }
		self.generate(algorithm: algorithm, key: (key as NSData).bytes, keyLength: key.count, data: (data as NSData).bytes, dataLength: data.count, dataOut: result.mutableBytes)
		return result as Data
	}
}
