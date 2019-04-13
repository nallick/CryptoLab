//
//  SymmetricKeyWrap.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import CommonCrypto
import Foundation

public extension Crypto
{
	enum SymmetricKey {
		public enum WrappingAlgorithm: Int {
			case aes = 1		// kCCWRAPAES
		}

		public static func wrap(algorithm: WrappingAlgorithm = .aes, initializationVector: UnsafePointer<UInt8>? = CCrfc3394_iv, initializationVectorLength: Int = CCrfc3394_ivLen, keyEncryptionKey: UnsafePointer<UInt8>?, keyEncryptionKeyLength: Int, rawKey: UnsafePointer<UInt8>?, rawKeyLength: Int, wrappedKey: UnsafeMutablePointer<UInt8>?, wrappedKeyLength: inout Int) -> Status {
			let status = CCSymmetricKeyWrap(CCWrappingAlgorithm(algorithm.rawValue), initializationVector, initializationVectorLength, keyEncryptionKey, keyEncryptionKeyLength, rawKey, rawKeyLength, wrappedKey, &wrappedKeyLength)
			return Status(rawValue: Int(status)) ?? .unspecifiedError
		}

		public static func unwrap(algorithm: WrappingAlgorithm = .aes, initializationVector: UnsafePointer<UInt8>? = CCrfc3394_iv, initializationVectorLength: Int = CCrfc3394_ivLen, keyEncryptionKey: UnsafePointer<UInt8>?, keyEncryptionKeyLength: Int, wrappedKey: UnsafePointer<UInt8>?, wrappedKeyLength: Int, rawKey: UnsafeMutablePointer<UInt8>?, rawKeyLength: inout Int) -> Status {
			let status = CCSymmetricKeyUnwrap(CCWrappingAlgorithm(algorithm.rawValue), initializationVector, initializationVectorLength, keyEncryptionKey, keyEncryptionKeyLength, wrappedKey, wrappedKeyLength, rawKey, &rawKeyLength)
			return Status(rawValue: Int(status)) ?? .unspecifiedError
		}

		public static func wrappedSize(algorithm: WrappingAlgorithm = .aes, rawKeyLength: Int) -> Int {
			return CCSymmetricWrappedSize(CCWrappingAlgorithm(algorithm.rawValue), rawKeyLength)
		}

		public static func unwrappedSize(algorithm: WrappingAlgorithm = .aes, wrappedKeyLength: Int) -> Int {
			return CCSymmetricUnwrappedSize(CCWrappingAlgorithm(algorithm.rawValue), wrappedKeyLength)
		}
	}
}

// MARK: - Convenience extensions

public extension Crypto.SymmetricKey
{
	static func wrap(algorithm: WrappingAlgorithm = .aes, initializationVector: Data? = nil, keyEncryptionKey: Data, rawKey: Data) throws -> Data {
		var wrappedKeyLength = self.wrappedSize(algorithm: algorithm, rawKeyLength: rawKey.count)
		guard let wrappedKey = NSMutableData(length: wrappedKeyLength) else { throw Crypto.Status.memoryFailure }
		let initializationVectorPtr = (initializationVector as NSData?)?.bytes.assumingMemoryBound(to: UInt8.self) ?? CCrfc3394_iv
		let initializationVectorLength = initializationVector?.count ?? CCrfc3394_ivLen
		let keyEncryptionKeyPtr = (keyEncryptionKey as NSData).bytes.assumingMemoryBound(to: UInt8.self)
		let rawKeyPtr = (rawKey as NSData).bytes.assumingMemoryBound(to: UInt8.self)
		let status = self.wrap(algorithm: algorithm, initializationVector: initializationVectorPtr, initializationVectorLength: initializationVectorLength, keyEncryptionKey: keyEncryptionKeyPtr, keyEncryptionKeyLength: keyEncryptionKey.count, rawKey: rawKeyPtr, rawKeyLength: rawKey.count, wrappedKey: wrappedKey.mutableBytes.assumingMemoryBound(to: UInt8.self), wrappedKeyLength: &wrappedKeyLength)
		guard case status = Crypto.Status.success else { throw status }
		wrappedKey.length = wrappedKeyLength
		return wrappedKey as Data
	}

	static func unwrap(algorithm: WrappingAlgorithm = .aes, initializationVector: Data? = nil, keyEncryptionKey: Data, wrappedKey: Data) throws -> Data {
		var unwrappedKeyLength = self.unwrappedSize(algorithm: algorithm, wrappedKeyLength: wrappedKey.count)
		guard let unwrappedKey = NSMutableData(length: unwrappedKeyLength) else { throw Crypto.Status.memoryFailure }
		let initializationVectorPtr = (initializationVector as NSData?)?.bytes.assumingMemoryBound(to: UInt8.self) ?? CCrfc3394_iv
		let initializationVectorLength = initializationVector?.count ?? CCrfc3394_ivLen
		let keyEncryptionKeyPtr = (keyEncryptionKey as NSData).bytes.assumingMemoryBound(to: UInt8.self)
		let wrappedKeyPtr = (wrappedKey as NSData).bytes.assumingMemoryBound(to: UInt8.self)
		let status = self.unwrap(algorithm: algorithm, initializationVector: initializationVectorPtr, initializationVectorLength: initializationVectorLength, keyEncryptionKey: keyEncryptionKeyPtr, keyEncryptionKeyLength: keyEncryptionKey.count, wrappedKey: wrappedKeyPtr, wrappedKeyLength: wrappedKey.count, rawKey: unwrappedKey.mutableBytes.assumingMemoryBound(to: UInt8.self), rawKeyLength: &unwrappedKeyLength)
		guard case status = Crypto.Status.success else { throw status }
		unwrappedKey.length = unwrappedKeyLength
		return wrappedKey as Data
	}
}
