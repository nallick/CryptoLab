//
//  Crypto.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import CommonCrypto

public enum Crypto
{
	public enum Status: Int, Error {
		case success = 0					// kCCSuccess
		case paramError = -4300				// kCCParamError
		case bufferTooSmall = -4301			// kCCBufferTooSmall
		case memoryFailure = -4302			// kCCMemoryFailure
		case alignmentError = -4303			// kCCAlignmentError
		case decodeError = -4304			// kCCDecodeError
		case unimplemented = -4305			// kCCUnimplemented
		case overflow = -4306				// kCCOverflow
		case rngFailure = -4307				// kCCRNGFailure
		case unspecifiedError = -4308		// kCCUnspecifiedError
		case callSequenceError = -4309		// kCCCallSequenceError
		case keySizeError = -4310			// kCCKeySizeError
		case invalidKey = -4311				// kCCInvalidKey
	}
}
