//
//  Digest.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import CommonCrypto
import Foundation

public extension Crypto
{
	class Digest {
		public let algorithm: Algorithm
		private var builder: DigestBuilderType

		public enum Algorithm {
			case md2, md4, md5, sha1, sha224, sha256, sha384, sha512

			var byteCount: Int {
				switch self {
					case .md2: return Int(CC_MD2_DIGEST_LENGTH)
					case .md4: return Int(CC_MD4_DIGEST_LENGTH)
					case .md5: return Int(CC_MD5_DIGEST_LENGTH)
					case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
					case .sha224: return Int(CC_SHA224_DIGEST_LENGTH)
					case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
					case .sha384: return Int(CC_SHA384_DIGEST_LENGTH)
					case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
				}
			}

			func generate(data: UnsafeRawPointer?, dataLength: Int, dataOut: UnsafeMutablePointer<UInt8>) {
				_ = self.generateFunction(data, UInt32(dataLength), dataOut)
			}

			private var generateFunction: (UnsafeRawPointer?, CC_LONG, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>? {
				switch self {
					case .md2: return CC_MD2
					case .md4: return CC_MD4
					case .md5: return CC_MD5
					case .sha1: return CC_SHA1
					case .sha224: return CC_SHA224
					case .sha256: return CC_SHA256
					case .sha384: return CC_SHA384
					case .sha512: return CC_SHA512
				}
			}

			fileprivate var builder: DigestBuilderType {
				switch self {
					case .md2: return DigestBuilder(CC_MD2_Init, CC_MD2_Update, CC_MD2_Final)
					case .md4: return DigestBuilder(CC_MD4_Init, CC_MD4_Update, CC_MD4_Final)
					case .md5: return DigestBuilder(CC_MD5_Init, CC_MD5_Update, CC_MD5_Final)
					case .sha1: return DigestBuilder(CC_SHA1_Init, CC_SHA1_Update, CC_SHA1_Final)
					case .sha224: return DigestBuilder(CC_SHA224_Init, CC_SHA224_Update, CC_SHA224_Final)
					case .sha256: return DigestBuilder(CC_SHA256_Init, CC_SHA256_Update, CC_SHA256_Final)
					case .sha384: return DigestBuilder(CC_SHA384_Init, CC_SHA384_Update, CC_SHA384_Final)
					case .sha512: return DigestBuilder(CC_SHA512_Init, CC_SHA512_Update, CC_SHA512_Final)
				}
			}
		}

		public init(algorithm: Algorithm) {
			self.algorithm = algorithm
			self.builder = algorithm.builder
		}

		public func update(data: UnsafeRawPointer, dataLength: Int) {
			self.builder.update(data, dataLength)
		}

		public func final(_ dataOut: UnsafeMutablePointer<UInt8>) {
			self.builder.build(dataOut)
		}

		public static func generate(algorithm: Algorithm, data: UnsafeRawPointer?, dataLength: Int, dataOut: UnsafeMutablePointer<UInt8>) {
			algorithm.generate(data: data, dataLength: dataLength, dataOut: dataOut)
		}
	}

	fileprivate class DigestBuilder<Context>: DigestBuilderType {
		private let context = UnsafeMutablePointer<Context>.allocate(capacity: 1)

		private let update: (UnsafeMutablePointer<Context>?, UnsafeRawPointer?, CC_LONG) -> Int32
		private let final: (UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<Context>?) -> Int32

		init(_ initialize: (UnsafeMutablePointer<Context>?) -> Int32, _ update: @escaping (UnsafeMutablePointer<Context>?, UnsafeRawPointer?, CC_LONG) -> Int32, _ final: @escaping (UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<Context>?) -> Int32) {
			self.update = update
			self.final = final
			_ = initialize(self.context)
		}

		func update(_ data: UnsafeRawPointer, _ dataLength: Int) {
			_ = self.update(self.context, data, CC_LONG(dataLength))
		}

		func build(_ dataOut: UnsafeMutablePointer<UInt8>) {
			_ = self.final(dataOut, self.context)
		}

		deinit {
			self.context.deallocate()
		}
	}
}

fileprivate protocol DigestBuilderType
{
	func update(_ data: UnsafeRawPointer, _ dataLength: Int)
	func build(_ dataOut: UnsafeMutablePointer<UInt8>)
}

// MARK: - Convenience extensions

public extension Crypto.Digest.Algorithm
{
	func generate(from data: Data) -> Data {
		guard let result = NSMutableData(length: self.byteCount) else { fatalError("\(Crypto.Status.memoryFailure)") }
		self.generate(data: (data as NSData).bytes, dataLength: data.count, dataOut: result.mutableBytes.assumingMemoryBound(to: UInt8.self))
		return result as Data
	}
}

public extension Crypto.Digest
{
	func update(data: Data) {
		self.update(data: (data as NSData).bytes, dataLength: data.count)
	}

	func final() -> Data {
		guard let result = NSMutableData(length: self.algorithm.byteCount) else { fatalError("\(Crypto.Status.memoryFailure)") }
		self.final(result.mutableBytes.assumingMemoryBound(to: UInt8.self))
		return result as Data
	}

	static func generate(algorithm: Algorithm, from data: Data) -> Data {
		return algorithm.generate(from: data)
	}
}

public extension Data
{
	func digest(using algorithm: Crypto.Digest.Algorithm) -> Data {
		return algorithm.generate(from: self)
	}
}
