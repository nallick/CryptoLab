//
//  PasswordEncryptedMessage.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import Foundation

public struct PasswordEncryptedMessage: Codable
{
	private let encryptedMessage: Data
	private let initializationVector: Data
	private let messageAuthentication: Data
	private let encryptedKey: PasswordEncryptedKey

	public static let keyByteCount = 256/8

	public init(message: String, encoding: String.Encoding = .utf8, password: String, iterations: Int) throws {
		guard let messageData = message.data(using: encoding) else { throw Crypto.Status.memoryFailure }
		let key = try Crypto.Random.generate(count: PasswordEncryptedMessage.keyByteCount)
		let initializationVector = try Crypto.Random.generate(count: PasswordEncryptedMessage.keyByteCount)
		let encryptedMessage = try messageData.encrypt(algorithm: .aes, options: .pkcs7Padding, key: key, initializationVector: initializationVector)
		let messageAuthentication = try Crypto.HMAC.generate(algorithm: .sha256, key: key, data: encryptedMessage)
		try self.init(password: password, iterations: iterations, key: key, encryptedMessage: encryptedMessage, initializationVector: initializationVector, messageAuthentication: messageAuthentication)
	}

	public init(changePassword message: PasswordEncryptedMessage, from oldPassword: String, to newPassword: String, iterations: Int) throws {
		let key = try message.encryptedKey.decrypt(password: oldPassword)
		try self.init(password: newPassword, iterations: iterations, key: key, encryptedMessage: message.encryptedMessage, initializationVector: message.initializationVector, messageAuthentication: message.messageAuthentication)
	}

	private init(password: String, iterations: Int, key: Data, encryptedMessage: Data, initializationVector: Data, messageAuthentication: Data) throws {
		self.encryptedKey = try PasswordEncryptedKey(key: key, password: password, iterations: iterations, encryptedMessage: encryptedMessage)
		self.initializationVector = initializationVector
		self.messageAuthentication = messageAuthentication
		self.encryptedMessage = encryptedMessage
	}

	public func key(from password: String) throws -> Data {
		return try self.encryptedKey.decrypt(password: password)
	}

	public func authenticate(password: String) throws -> Bool {
		return try self.authenticate(key: self.key(from: password))
	}

	public func authenticate(key: Data) throws -> Bool {
		let authentication = try Crypto.HMAC.generate(algorithm: .sha256, key: key, data: self.encryptedMessage)
		return (authentication == self.messageAuthentication)
	}

	public func decrypt(password: String) throws -> Data {
		return try self.decrypt(key: self.key(from: password))
	}

	public func decrypt(key: Data) throws -> Data {
		return try self.encryptedMessage.decrypt(algorithm: .aes, options: .pkcs7Padding, key: key, initializationVector: self.initializationVector)
	}
}
