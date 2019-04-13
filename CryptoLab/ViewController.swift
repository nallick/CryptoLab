//
//  ViewController.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import Cocoa

class ViewController: NSViewController
{
	@IBOutlet var plainTextField: NSTextField!
	@IBOutlet var passwordField: NSTextField!
	@IBOutlet var cypherLabel: NSTextField!
	@IBOutlet var resultLabel: NSTextField!

	private let passwordDelay: TimeInterval = 0.25
	private let encoder = JSONEncoder()
	private let decoder = JSONDecoder()
	private var encryptedMessageAsJson: Data?

	private var cypherTextAsBase64: String {
		guard let jsonData = self.encryptedMessageAsJson,
			let jsonDictionary = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
			let cypherText = jsonDictionary["encryptedMessage"] as? String
			else { return "" }
		return cypherText
	}

	@IBAction func encrypt(_ sender: AnyObject) {
		let plainText = self.plainTextField.stringValue
		let password = self.passwordField.stringValue
		guard plainText.count > 0 && password.count > 0 else {
			self.resultLabel.stringValue = "Please provide both plain text and a password."
			return
		}

		do {
			let iterations = PasswordEncryptedKey.iterationsForDesiredTime(passwordLength: password.count, desiredTime: self.passwordDelay)
			let encryptedMessage = try PasswordEncryptedMessage(message: plainText, password: password, iterations: iterations)
			self.encryptedMessageAsJson = try self.encoder.encode(encryptedMessage)
			self.cypherLabel.stringValue = self.cypherTextAsBase64
			self.resultLabel.stringValue = ""
		} catch {
			self.resultLabel.stringValue = "Error: \(error)"
		}
	}

	@IBAction func decrypt(_ sender: AnyObject) {
		guard let encryptedMessageAsJson = self.encryptedMessageAsJson else {
			self.resultLabel.stringValue = "Please encrypt a message first."
			return
		}

		do {
			let password = self.passwordField.stringValue
			let encryptedMessage = try self.decoder.decode(PasswordEncryptedMessage.self, from: encryptedMessageAsJson)
			let decryptedMessage = try encryptedMessage.decrypt(password: password)
			self.resultLabel.stringValue = String(data: decryptedMessage, encoding: .utf8) ?? ""
		} catch {
			self.resultLabel.stringValue = "Error: \(error)"
		}
	}

	@IBAction func authenticate(_ sender: AnyObject) {
		guard let encryptedMessageAsJson = self.encryptedMessageAsJson else {
			self.resultLabel.stringValue = "Please encrypt a message first."
			return
		}

		do {
			let password = self.passwordField.stringValue
			let encryptedMessage = try self.decoder.decode(PasswordEncryptedMessage.self, from: encryptedMessageAsJson)
			let isValid = try encryptedMessage.authenticate(password: password)
			self.resultLabel.stringValue = isValid ? "Message is valid with current password." : "Message is invalid with current password."
		} catch {
			self.resultLabel.stringValue = "Error: \(error)"
		}
	}
}
