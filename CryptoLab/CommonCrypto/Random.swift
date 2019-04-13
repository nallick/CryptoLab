//
//  Random.swift
//
//  Copyright © 2019 Purgatory Design. Licensed under the MIT License.
//

import CommonCrypto
import Foundation

public extension Crypto
{
	enum Random {
		typealias Status = Crypto.Status

		static func generate(bytes: UnsafeMutableRawPointer?, count: Int) -> Status {
			let status = CCRandomGenerateBytes(bytes, count)
			return Random.Status(rawValue: Int(status)) ?? .unspecifiedError
		}
	}
}

// MARK: - Convenience extensions

public extension Crypto.Random
{
	static func generate(count: Int) throws -> Data {
		guard let data = NSMutableData(length: count) else { throw Status.memoryFailure }
		let status = self.generate(bytes: data.mutableBytes, count: count)
		guard case status = Status.success else { throw status }
		return data as Data
	}
}
