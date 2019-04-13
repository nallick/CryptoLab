//
//  SecKeyExtensions.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import Foundation

@nonobjc public extension SecKey
{
	func encrypt(_ data: CFData, algorithm: SecKeyAlgorithm) throws -> CFData {
		var error: Unmanaged<CFError>?
		if let result = SecKeyCreateEncryptedData(self, algorithm, data, &error) {
			return result
		}

		throw error?.takeRetainedValue() ?? Crypto.Status.unspecifiedError
	}

	func decrypt(_ data: CFData, algorithm: SecKeyAlgorithm) throws -> CFData {
		var error: Unmanaged<CFError>?
		if let result = SecKeyCreateDecryptedData(self, algorithm, data, &error) {
			return result
		}

		throw error?.takeRetainedValue() ?? Crypto.Status.unspecifiedError
	}
}

// MARK: - Convenience extensions

@nonobjc public extension SecKey
{
	func encrypt(_ data: Data, algorithm: SecKeyAlgorithm) throws -> Data {
		return try self.encrypt(data as CFData, algorithm: algorithm) as Data
	}

	func decrypt(_ data: Data, algorithm: SecKeyAlgorithm) throws -> Data {
		return try self.decrypt(data as CFData, algorithm: algorithm) as Data
	}
}

public extension Data
{
	func encrypt(algorithm: SecKeyAlgorithm, key: SecKey) throws -> Data {
		return try key.encrypt(self, algorithm: algorithm)
	}

	func decrypt(algorithm: SecKeyAlgorithm, key: SecKey) throws -> Data {
		return try key.decrypt(self, algorithm: algorithm)
	}
}
