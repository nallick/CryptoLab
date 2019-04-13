//
//  PasswordEncryptedKey.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import Foundation

public struct PasswordEncryptedKey: Codable
{
	private let iterations: Int
	private let encryptedKey: Data
	private let passwordVerification: Data
	private let initializationVector: Data
	private let salt: Data

	public static let keyByteCount = 256/8
	public static let saltByteCount = 128/8

	public init(key: Data, password: String, iterations: Int, encryptedMessage: Data) throws {
		guard iterations > 0 else { throw Crypto.Status.paramError }

		self.iterations = iterations
		self.salt = try Crypto.Random.generate(count: PasswordEncryptedKey.saltByteCount)
		self.initializationVector = try Crypto.Random.generate(count: PasswordEncryptedKey.keyByteCount)

		let derivedKey = try PasswordEncryptedKey.deriveKey(password: password, iterations: iterations, salt: self.salt)
		self.passwordVerification = derivedKey.passwordVerification
		self.encryptedKey = try key.encrypt(algorithm: .aes, key: derivedKey.keyWrapKey, initializationVector: self.initializationVector)
	}

	public func decrypt(password: String) throws -> Data {
		let derivedKey = try PasswordEncryptedKey.deriveKey(password: password, iterations: self.iterations, salt: self.salt)
		guard derivedKey.passwordVerification == self.passwordVerification else { throw Crypto.Status.invalidKey }
		return try self.encryptedKey.decrypt(algorithm: .aes, key: derivedKey.keyWrapKey, initializationVector: self.initializationVector)
	}

	public static func iterationsForDesiredTime(passwordLength: Int, desiredTime: TimeInterval) -> Int {
		return Crypto.PBKDF.iterationsForDesiredTime(passwordLength: passwordLength, saltLength: self.saltByteCount, pseudoRandomAlgorithm: .sha512, desiredKeyLength: self.keyByteCount*2, desiredTime: desiredTime)
	}

	private static func deriveKey(password: String, iterations: Int, salt: Data) throws -> (keyWrapKey: Data, passwordVerification: Data) {
		let derivedKeyByteCount = PasswordEncryptedKey.keyByteCount*2
		let derivedKey = try Crypto.PBKDF.deriveKey(password: password, salt: salt, pseudoRandomAlgorithm: .sha512, iterations: iterations, desiredKeyLength: derivedKeyByteCount)
		let keyWrapKey = derivedKey[0 ..< PasswordEncryptedKey.keyByteCount]
		let passwordVerification = derivedKey[PasswordEncryptedKey.keyByteCount ..< derivedKeyByteCount]
		return (keyWrapKey: keyWrapKey, passwordVerification: passwordVerification)
	}
}
