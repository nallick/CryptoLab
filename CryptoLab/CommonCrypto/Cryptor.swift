//
//  Cryptor.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import CommonCrypto
import Foundation

public extension Crypto
{
	typealias CryptorStatus = Status

	enum Operation: Int {
		case encrypt = 0	// kCCEncrypt
		case decrypt		// kCCDecrypt
	}

	enum Algorithm: Int {
		case aes = 0		// kCCAlgorithmAES
		case des			// kCCAlgorithmDES
		case tripleDES		// kCCAlgorithm3DES
		case cast			// kCCAlgorithmCAST
		case rc4			// kCCAlgorithmRC4
		case rc2			// kCCAlgorithmRC2
		case blowfish		// kCCAlgorithmBlowfish

		var blockSize: Int {
			switch self {
				case .aes: return BlockSize.aes128
				case .des: return BlockSize.des
				case .tripleDES: return BlockSize.tripleDES
				case .cast: return BlockSize.cast
				case .rc4: return 0		// unknown
				case .rc2: return BlockSize.rc2
				case .blowfish: return BlockSize.blowfish
			}
		}
	}

	enum Mode: Int {
		case ecb = 1		// kCCModeECB
		case cbc			// kCCModeCBC
		case cfb			// kCCModeCFB
		case ctr			// kCCModeCTR
		case f8				// kCCModeF8
		case lrw			// kCCModeLRW
		case ofb			// kCCModeOFB
		case xts			// kCCModeXTS
		case rc4			// kCCModeRC4
		case cfb8			// kCCModeCFB8
	}

	enum Padding: Int {
		case none = 0		// ccNoPadding
		case pkcs7			// ccPKCS7Padding
	}

	struct Options: OptionSet {
		static let pkcs7Padding = Options(rawValue: kCCOptionPKCS7Padding)
		static let ecbMode = Options(rawValue: kCCOptionECBMode)

		public let rawValue: Int
		public init(rawValue: Int) { self.rawValue = rawValue }
	}

	struct ModeOptions: OptionSet {
		static let ctrLE = ModeOptions(rawValue: kCCModeOptionCTR_LE)	// Deprecated
		static let ctrBE = ModeOptions(rawValue: kCCModeOptionCTR_BE)

		public let rawValue: Int
		public init(rawValue: Int) { self.rawValue = rawValue }
	}

	struct KeySize {
		static let aes128 = kCCKeySizeAES128
		static let aes192 = kCCKeySizeAES192
		static let aes256 = kCCKeySizeAES256
		static let des = kCCKeySizeDES
		static let tripleDES = kCCKeySize3DES
		static let minCAST = kCCKeySizeMinCAST
		static let maxCAST = kCCKeySizeMaxCAST
		static let minRC4 = kCCKeySizeMinRC4
		static let maxRC4 = kCCKeySizeMaxRC4
		static let minRC2 = kCCKeySizeMinRC2
		static let maxRC2 = kCCKeySizeMaxRC2
		static let minBlowfish = kCCKeySizeMinBlowfish
		static let maxBlowfish = kCCKeySizeMaxBlowfish
	}

	struct BlockSize {
		static let aes128 = kCCBlockSizeAES128
		static let des = kCCBlockSizeDES
		static let tripleDES = kCCBlockSize3DES
		static let cast = kCCBlockSizeCAST
		static let rc2 = kCCBlockSizeRC2
		static let blowfish = kCCBlockSizeBlowfish
	}

	struct ContextSize {
		static let aes128 = kCCContextSizeAES128
		static let des = kCCContextSizeDES
		static let tripleDES = kCCContextSize3DES
		static let cast = kCCContextSizeCAST
		static let rc4 = kCCContextSizeRC4
	}

	static func crypt(operation: Operation, algorithm: Algorithm, options: Options = [], key: UnsafeRawPointer?, keyLength: Int, initializationVector: UnsafeRawPointer? = nil, dataIn: UnsafeRawPointer?, dataInLength: Int, dataOut: UnsafeMutableRawPointer?, dataOutAvailable: Int, dataOutMoved: inout Int = 0) -> CryptorStatus {
		let status = CCCrypt(CCOperation(operation.rawValue), CCAlgorithm(algorithm.rawValue), CCOptions(options.rawValue), key, keyLength, initializationVector, dataIn, dataInLength, dataOut, dataOutAvailable, &dataOutMoved)
		return CryptorStatus(rawValue: Int(status)) ?? .unspecifiedError
	}

	final class Cryptor {
		private let cryptor: CCCryptorRef

		init(operation: Operation, algorithm: Algorithm, options: Options = [], key: UnsafeRawPointer?, keyLength: Int, initializationVector: UnsafeRawPointer? = nil) throws {
			var createResult: OpaquePointer?
			let status = CCCryptorCreate(CCOperation(operation.rawValue), CCAlgorithm(algorithm.rawValue), CCOptions(options.rawValue), key, keyLength, initializationVector, &createResult)
			guard status == kCCSuccess else { throw CryptorStatus(rawValue: Int(status)) ?? .unspecifiedError }
			guard let cryptor = createResult else { throw CryptorStatus.unspecifiedError }
			self.cryptor = cryptor
		}

		init(operation: Operation, algorithm: Algorithm, options: Options = [], key: UnsafeRawPointer?, keyLength: Int, initializationVector: UnsafeRawPointer? = nil, data: UnsafeRawPointer?, dataLength: Int, dataUsed: inout Int = 0) throws {
			var createResult: OpaquePointer?
			let status = CCCryptorCreateFromData(CCOperation(operation.rawValue), CCAlgorithm(algorithm.rawValue), CCOptions(options.rawValue), key, keyLength, initializationVector, data, dataLength, &createResult, &dataUsed)
			guard status == kCCSuccess else { throw CryptorStatus(rawValue: Int(status)) ?? .unspecifiedError }
			guard let cryptor = createResult else { throw CryptorStatus.unspecifiedError }
			self.cryptor = cryptor
		}

		init(operation: Operation, mode: Mode, algorithm: Algorithm, padding: Padding = .none, initializationVector: UnsafeRawPointer? = nil, key: UnsafeRawPointer?, keyLength: Int, tweak: UnsafeRawPointer?, tweakLength: Int, numRounds: Int = 0, options: ModeOptions = []) throws {
			var createResult: OpaquePointer?
			let status = CCCryptorCreateWithMode(CCOperation(operation.rawValue), CCMode(mode.rawValue), CCAlgorithm(algorithm.rawValue), CCPadding(padding.rawValue), initializationVector, key, keyLength, tweak, tweakLength, Int32(numRounds), CCModeOptions(options.rawValue), &createResult)
			guard status == kCCSuccess else { throw CryptorStatus(rawValue: Int(status)) ?? .unspecifiedError }
			guard let cryptor = createResult else { throw CryptorStatus.unspecifiedError }
			self.cryptor = cryptor
		}

		func update(dataIn: UnsafeRawPointer?, dataInLength: Int, dataOut: UnsafeMutableRawPointer?, dataOutAvailable: Int, dataOutMoved: inout Int = 0) -> CryptorStatus {
			let status = CCCryptorUpdate(self.cryptor, dataIn, dataInLength, dataOut, dataOutAvailable, &dataOutMoved)
			return CryptorStatus(rawValue: Int(status)) ?? .unspecifiedError
		}

		func final(dataOut: UnsafeMutableRawPointer?, dataOutAvailable: Int, dataOutMoved: inout Int = 0) -> CryptorStatus {
			let status = CCCryptorFinal(self.cryptor, dataOut, dataOutAvailable, &dataOutMoved)
			return CryptorStatus(rawValue: Int(status)) ?? .unspecifiedError
		}

		func outputLength(for inputLength: Int, final: Bool) -> Int {
			return CCCryptorGetOutputLength(self.cryptor, inputLength, final)
		}

		func reset(initializationVector: UnsafeRawPointer? = nil) -> CryptorStatus {
			let status = CCCryptorReset(self.cryptor, initializationVector)
			return CryptorStatus(rawValue: Int(status)) ?? .unspecifiedError
		}

		deinit {
			let status = CCCryptorRelease(self.cryptor)
			assert(status == kCCSuccess)
		}
	}
}

// MARK: - Convenience extensions

public extension Crypto
{
	static func crypt(operation: Operation, algorithm: Algorithm, options: Options = [], key: Data, initializationVector: Data? = nil, data: Data) throws -> Data {
		guard let dataOut = NSMutableData(length: data.count + algorithm.blockSize) else { throw CryptorStatus.memoryFailure }
		var dataOutMoved = 0
		var status = self.crypt(operation: operation, algorithm: algorithm, options: options, key: (key as NSData).bytes, keyLength: key.count, initializationVector: (initializationVector as NSData?)?.bytes, dataIn: (data as NSData).bytes, dataInLength: data.count, dataOut: dataOut.mutableBytes, dataOutAvailable: dataOut.count, dataOutMoved: &dataOutMoved)
		if case status = CryptorStatus.bufferTooSmall {
			dataOut.length = dataOutMoved
			status = self.crypt(operation: operation, algorithm: algorithm, options: options, key: (key as NSData).bytes, keyLength: key.count, initializationVector: (initializationVector as NSData?)?.bytes, dataIn: (data as NSData).bytes, dataInLength: data.count, dataOut: dataOut.mutableBytes, dataOutAvailable: dataOut.count, dataOutMoved: &dataOutMoved)
		}
		guard case status = CryptorStatus.success else { throw status }
		dataOut.length = dataOutMoved
		return dataOut as Data
	}
}

public extension Crypto.Cryptor
{
	convenience init(operation: Crypto.Operation, algorithm: Crypto.Algorithm, options: Crypto.Options = [], key: Data, initializationVector: Data? = nil) throws {
		try self.init(operation: operation, algorithm: algorithm, options: options, key: (key as NSData).bytes, keyLength: key.count, initializationVector: (initializationVector as NSData?)?.bytes)
	}

	convenience init(operation: Crypto.Operation, algorithm: Crypto.Algorithm, options: Crypto.Options = [], key: Data, initializationVector: Data? = nil, data: Data, dataUsed: inout Int = 0) throws {
		try self.init(operation: operation, algorithm: algorithm, options: options, key: (key as NSData).bytes, keyLength: key.count, initializationVector: (initializationVector as NSData?)?.bytes, data: (data as NSData).bytes, dataLength: data.count, dataUsed: &dataUsed)
	}

	convenience init(operation: Crypto.Operation, mode: Crypto.Mode, algorithm: Crypto.Algorithm, padding: Crypto.Padding = .none, initializationVector: Data? = nil, key: Data, tweak: Data, numRounds: Int = 0, options: Crypto.ModeOptions = []) throws {
		try self.init(operation: operation, mode: mode, algorithm: algorithm, padding: padding, initializationVector: (initializationVector as NSData?)?.bytes, key: (key as NSData).bytes, keyLength: key.count, tweak: (tweak as NSData).bytes, tweakLength: tweak.count, options: options)
	}

	func update(data: Data, final: Bool) throws -> Data {
		let outputLength = self.outputLength(for: data.count, final: final)
		guard let dataOut = NSMutableData(length: outputLength) else { throw Crypto.CryptorStatus.memoryFailure }
		var dataOutMoved = 0
		let status = self.update(dataIn: (data as NSData).bytes, dataInLength: data.count, dataOut: dataOut.mutableBytes, dataOutAvailable: outputLength, dataOutMoved: &dataOutMoved)
		guard case status = Crypto.CryptorStatus.success else { throw status }
		if final {
			var finalDataOutMoved = 0
			let finalStatus = self.final(dataOut: dataOut.mutableBytes + dataOutMoved, dataOutAvailable: outputLength - dataOutMoved, dataOutMoved: &finalDataOutMoved)
			guard case finalStatus = Crypto.CryptorStatus.success else { throw status }
			dataOutMoved += finalDataOutMoved
		}
		dataOut.length = dataOutMoved
		return dataOut as Data
	}

	func reset(initializationVector: Data) -> Crypto.CryptorStatus {
		let status = CCCryptorReset(self.cryptor, (initializationVector as NSData).bytes)
		return Crypto.CryptorStatus(rawValue: Int(status)) ?? .unspecifiedError
	}
}

public extension Data
{
	func encrypt(algorithm: Crypto.Algorithm, options: Crypto.Options = [], key: Data, initializationVector: Data? = nil) throws -> Data {
		return try Crypto.crypt(operation: .encrypt, algorithm: algorithm, options: options, key: key, initializationVector: initializationVector, data: self)
	}

	func decrypt(algorithm: Crypto.Algorithm, options: Crypto.Options = [], key: Data, initializationVector: Data? = nil) throws -> Data {
		return try Crypto.crypt(operation: .decrypt, algorithm: algorithm, options: options, key: key, initializationVector: initializationVector, data: self)
	}
}
