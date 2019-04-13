//
//  CryptoLabTests.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import CryptoLab
import XCTest

class CryptoLabTests: XCTestCase
{
	let password = "password"
	let originalMessage = "Now is the time for all good men to come to the aid of their country."

	func testDecryptedMessageEqualsEncryptedMessage() throws {
		let encryptedMessage = try PasswordEncryptedMessage(message: originalMessage, password: password, iterations: 1)

		let decryptedData = try encryptedMessage.decrypt(password: password)
		let decryptedMessage = String(data: decryptedData, encoding: .utf8)

		XCTAssertEqual(decryptedMessage, originalMessage, "Decrypted message should equal original message")
	}

	func testDecryptionWithInvalidPasswordFails() throws {
		let encryptedMessage = try PasswordEncryptedMessage(message: originalMessage, password: password, iterations: 1)

		let decryptedData = try? encryptedMessage.decrypt(password: "invalid" + password)

		XCTAssertNil(decryptedData, "Decryption should fail")
	}

	func testDecryptedMessageWithChangedPasswordEqualsEncryptedMessage() throws {
		let changedPassword = "CHANGED PASSWORD"
		let encryptedMessage = try PasswordEncryptedMessage(message: originalMessage, password: password, iterations: 1)
		let updatedMessage = try PasswordEncryptedMessage(changePassword: encryptedMessage, from: password, to: changedPassword, iterations: 1)

		let decryptedData = try updatedMessage.decrypt(password: changedPassword)
		let decryptedMessage = String(data: decryptedData, encoding: .utf8)

		XCTAssertEqual(decryptedMessage, originalMessage, "Decrypted message should equal original message")
	}

	func testCodedAndDecodedMessageAuthenticatesAndDecryptsSuccessfully() throws {
		let encryptedMessage = try PasswordEncryptedMessage(message: originalMessage, password: password, iterations: 1)
		let encodedMessage = try JSONEncoder().encode(encryptedMessage)

		let decodedMessage = try JSONDecoder().decode(PasswordEncryptedMessage.self, from: encodedMessage)
		let decodedKey = try decodedMessage.key(from: password)
		let isValid = try decodedMessage.authenticate(key: decodedKey)
		let decryptedData = try decodedMessage.decrypt(key: decodedKey)
		let decryptedMessage = String(data: decryptedData, encoding: .utf8)

		XCTAssertTrue(isValid == true, "Authentication should succeed")
		XCTAssertEqual(decryptedMessage, originalMessage, "Decrypted message should equal original message")
	}

	func testAuthenicationSucceedsWithValidPassword() throws {
		let encryptedMessage = try PasswordEncryptedMessage(message: originalMessage, password: password, iterations: 1)

		let isValid = try encryptedMessage.authenticate(password: password)

		XCTAssertTrue(isValid, "Authentication should succeed")
	}

	func testAuthenicationFailsWithInvalidPassword() throws {
		let encryptedMessage = try PasswordEncryptedMessage(message: originalMessage, password: password, iterations: 1)

		let isValid = (try? encryptedMessage.authenticate(password: "invalid" + password)) ?? false

		XCTAssertFalse(isValid, "Authentication should fail")
	}

	func testAuthenicationFailsWithAlteredMessage() throws {
		let encryptedMessage = try PasswordEncryptedMessage(message: originalMessage, password: password, iterations: 1)
		let originalJsonData = try JSONEncoder().encode(encryptedMessage)
		var jsonDictionary = try JSONSerialization.jsonObject(with: originalJsonData) as! [String: Any]
		let encryptedMessageBase64 = jsonDictionary["encryptedMessage"] as! String

		var alteredData = Data(base64Encoded: encryptedMessageBase64)!
		alteredData[0] = ~alteredData[0]
		jsonDictionary["encryptedMessage"] = alteredData.base64EncodedString()
		let alteredJsonData = try JSONSerialization.data(withJSONObject:jsonDictionary)
		let alteredMessage = try JSONDecoder().decode(PasswordEncryptedMessage.self, from: alteredJsonData)

		let isValid = (try? alteredMessage.authenticate(password: password)) ?? false

		XCTAssertFalse(isValid, "Authentication should fail")
	}

	func testAsymetricRSAEncryption() throws {
		let privateKey = try SecKey.randomKey(keyType: .rsa, keyBitSize: 2048)
		let publicKey = privateKey.publicKey!
		let originalMessage = "Now is the time for all good men to come to the aid of their country."
		let originalData = originalMessage.data(using: .utf8)!

		let encryptedData = try originalData.encrypt(algorithm: .rsaEncryptionOAEPSHA512AESGCM, key: publicKey)
		let decryptedData = try encryptedData.decrypt(algorithm: .rsaEncryptionOAEPSHA512AESGCM, key: privateKey)

		XCTAssertEqual(decryptedData, originalData, "Decrypted data should equal original")
	}

	func testImportedPrivateKeyShouldDecryptMessageFromExportedKey() throws {
		let originalKey = try SecKey.randomKey(keyType: .rsa, keyBitSize: 2048)
		let publicKey = originalKey.publicKey!
		let originalMessage = "Now is the time for all good men to come to the aid of their country."
		let originalData = originalMessage.data(using: .utf8)!
		let encryptedData = try originalData.encrypt(algorithm: .rsaEncryptionOAEPSHA512AESGCM, key: publicKey)

		let originalKeyData = try originalKey.externalRepresentation()
		let restoredKey = try SecKey.importRandomKey(keyData: originalKeyData, keyType: .rsa, keyClass: .private)
		let decryptedData = try encryptedData.decrypt(algorithm: .rsaEncryptionOAEPSHA512AESGCM, key: restoredKey)

		XCTAssertEqual(decryptedData, originalData, "Decrypted data should equal original")
	}

	func testImportedPublicKeyShouldEncryptMessageForOriginalKey() throws {
		let privateKey = try SecKey.randomKey(keyType: .rsa, keyBitSize: 2048)
		let originalMessage = "Now is the time for all good men to come to the aid of their country."
		let originalData = originalMessage.data(using: .utf8)!

		let originalKey = privateKey.publicKey!
		let originalKeyData = try originalKey.externalRepresentation()
		let restoredKey = try SecKey.importRandomKey(keyData: originalKeyData, keyType: .rsa, keyClass: .public)
		let encryptedData = try originalData.encrypt(algorithm: .rsaEncryptionOAEPSHA512AESGCM, key: restoredKey)
		let decryptedData = try encryptedData.decrypt(algorithm: .rsaEncryptionOAEPSHA512AESGCM, key: privateKey)

		XCTAssertEqual(decryptedData, originalData, "Decrypted data should equal original")
	}
}
