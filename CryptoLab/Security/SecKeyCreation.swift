//
//  SecKeyExtensions.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import Foundation

@nonobjc public extension SecKey
{
	typealias RandomKeyAttributes = [CFString: NSObject]

	enum KeyType {
		case rsa, ec, ecSecPrimeRandom		// use ecSecPrimeRandom rather than ec if available

		#if os(macOS)
		case aes, des, dsa, rc2, rc4, cast, tripleDES
		#endif

		var rawValue: CFString {
			switch self {
				case .rsa: return kSecAttrKeyTypeRSA
				case .ec: return kSecAttrKeyTypeEC
				case .ecSecPrimeRandom: return kSecAttrKeyTypeECSECPrimeRandom

				#if os(macOS)
				case .aes: return kSecAttrKeyTypeAES
				case .des: return kSecAttrKeyTypeDES
				case .dsa: return kSecAttrKeyTypeDSA
				case .rc2: return kSecAttrKeyTypeRC2
				case .rc4: return kSecAttrKeyTypeRC4
				case .cast: return kSecAttrKeyTypeCAST
				case .tripleDES: return kSecAttrKeyType3DES
				#endif
			}
		}
	}

	enum KeyClass {
		case `public`, `private`, symmetric

		var rawValue: CFString {
			switch self {
				case .public: return kSecAttrKeyClassPublic
				case .private: return kSecAttrKeyClassPrivate
				case .symmetric: return kSecAttrKeyClassSymmetric
			}
		}
	}

	var publicKey: SecKey? {
		return SecKeyCopyPublicKey(self)
	}

	func externalRepresentation() throws -> Data {
		var error: Unmanaged<CFError>?
		if let result = SecKeyCopyExternalRepresentation(self, &error) {
			return result as Data
		}

		throw error?.takeRetainedValue() ?? Crypto.Status.unspecifiedError
	}

	static func importRandomKey(keyData: CFData, keyType: CFString, keyClass: CFString, attributes: RandomKeyAttributes = [:]) throws -> SecKey {
		let keyAttributes: RandomKeyAttributes = [
			kSecAttrKeyType: keyType,
			kSecAttrKeyClass: keyClass
		]

		var error: Unmanaged<CFError>?
		if let result = SecKeyCreateWithData(keyData, keyAttributes.merging(attributes) { _, attr in attr } as CFDictionary, &error) {
			return result
		}

		throw error?.takeRetainedValue() ?? Crypto.Status.unspecifiedError
	}

	static func randomKey(keyType: CFString, keyBitSize: Int, attributeTokenId: CFString? = nil, commonAttributes: RandomKeyAttributes = [:], publicKeyAttributes: RandomKeyAttributes = [:], privateKeyAttributes: RandomKeyAttributes = [:]) throws -> SecKey {
		var keyAttributes: RandomKeyAttributes = [
			kSecAttrKeyType: keyType,
			kSecAttrKeySizeInBits: keyBitSize as NSObject,
			kSecPublicKeyAttrs: publicKeyAttributes as NSObject,
			kSecPrivateKeyAttrs: privateKeyAttributes as NSObject,
		]

		if let attributeTokenId = attributeTokenId { keyAttributes[kSecAttrTokenID] = attributeTokenId }

		var error: Unmanaged<CFError>?
		if let result = SecKeyCreateRandomKey(keyAttributes.merging(commonAttributes) { _, attr in attr } as CFDictionary, &error) {
			return result
		}

		throw error?.takeRetainedValue() ?? Crypto.Status.unspecifiedError
	}

	static func randomKeyAttributes(label: CFString? = nil, applicationTag: CFString? = nil, effectiveKeySize: Int? = nil, saveToDefaultKeychain: Bool? = nil, canEncrypt: Bool? = nil, canDecrypt: Bool? = nil, canDerive: Bool? = nil, canSign: Bool? = nil, canVerify: Bool? = nil, canWrap: Bool? = nil, canUnwrap: Bool? = nil) -> RandomKeyAttributes {
		var result: RandomKeyAttributes = [:]
		if let label = label { result[kSecAttrLabel] = label }
		if let applicationTag = applicationTag { result[kSecAttrApplicationTag] = applicationTag }
		if let effectiveKeySize = effectiveKeySize { result[kSecAttrEffectiveKeySize] = effectiveKeySize as NSObject }
		if let saveToDefaultKeychain = saveToDefaultKeychain { result[kSecAttrIsPermanent] = saveToDefaultKeychain as NSObject }
		if let canEncrypt = canEncrypt { result[kSecAttrCanEncrypt] = canEncrypt as NSObject }
		if let canDecrypt = canDecrypt { result[kSecAttrCanDecrypt] = canDecrypt as NSObject }
		if let canDerive = canDerive { result[kSecAttrCanDerive] = canDerive as NSObject }
		if let canSign = canSign { result[kSecAttrCanSign] = canSign as NSObject }
		if let canVerify = canVerify { result[kSecAttrCanVerify] = canVerify as NSObject }
		if let canWrap = canWrap { result[kSecAttrCanWrap] = canWrap as NSObject }
		if let canUnwrap = canUnwrap { result[kSecAttrCanUnwrap] = canUnwrap as NSObject }
		return result
	}
}

// MARK: - Convenience extensions

@nonobjc public extension SecKey
{
	static func importRandomKey(keyData: Data, keyType: KeyType, keyClass: KeyClass, attributes: RandomKeyAttributes = [:]) throws -> SecKey {
		return try self.importRandomKey(keyData: keyData as CFData, keyType: keyType.rawValue, keyClass: keyClass.rawValue, attributes: attributes)
	}

	static func randomKey(keyType: KeyType, keyBitSize: Int, attributeTokenId: String? = nil, commonAttributes: RandomKeyAttributes = [:], publicKeyAttributes: RandomKeyAttributes = [:], privateKeyAttributes: RandomKeyAttributes = [:]) throws -> SecKey {
		return try self.randomKey(keyType: keyType.rawValue, keyBitSize: keyBitSize, attributeTokenId: attributeTokenId as CFString?, commonAttributes: commonAttributes, publicKeyAttributes: publicKeyAttributes, privateKeyAttributes: privateKeyAttributes)
	}

	static func randomKeyAttributes(label: String? = nil, applicationTag: String? = nil, effectiveKeySize: Int? = nil, saveToDefaultKeychain: Bool? = nil, canEncrypt: Bool? = nil, canDecrypt: Bool? = nil, canDerive: Bool? = nil, canSign: Bool? = nil, canVerify: Bool? = nil, canWrap: Bool? = nil, canUnwrap: Bool? = nil) -> RandomKeyAttributes {
		return self.randomKeyAttributes(label: label as CFString?, applicationTag: applicationTag as CFString?, effectiveKeySize: effectiveKeySize, saveToDefaultKeychain: saveToDefaultKeychain, canEncrypt: canEncrypt, canDecrypt: canDecrypt, canDerive: canDerive, canSign: canSign, canVerify: canVerify, canWrap: canWrap, canUnwrap: canUnwrap)
	}
}
