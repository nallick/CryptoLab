//
//  SecKeyExtensions.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import Foundation

@nonobjc public extension SecKey
{
	func sign(_ data: CFData, algorithm: SecKeyAlgorithm) throws -> CFData {
		var error: Unmanaged<CFError>?
		if let result = SecKeyCreateSignature(self, algorithm, data, &error) {
			return result
		}

		throw error?.takeRetainedValue() ?? Crypto.Status.unspecifiedError
	}

	func verify(_ data: CFData, with signature: CFData, algorithm: SecKeyAlgorithm) throws -> Bool {
		var error: Unmanaged<CFError>?
		let result = SecKeyVerifySignature(self, algorithm, data, signature, &error)
		if let error = error {
			throw error.takeRetainedValue()
		}

		return result
	}
}

// MARK: - Convenience extensions

@nonobjc public extension SecKey
{
	func sign(_ data: Data, algorithm: SecKeyAlgorithm) throws -> Data {
		return try self.sign(data as CFData, algorithm: algorithm) as Data
	}

	func verify(_ data: Data, with signature: Data, algorithm: SecKeyAlgorithm) throws -> Bool {
		return try self.verify(data as CFData, with: signature as CFData, algorithm: algorithm)
	}
}

public extension Data
{
	func sign(algorithm: SecKeyAlgorithm, key: SecKey) throws -> Data {
		return try key.sign(self, algorithm: algorithm)
	}

	func verify(algorithm: SecKeyAlgorithm, key: SecKey, with signature: Data) throws -> Bool {
		return try key.verify(self, with: signature, algorithm: algorithm)
	}
}
