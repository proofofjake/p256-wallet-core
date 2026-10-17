import Foundation
import P256WalletCore
import Testing

/// Checks the Swift binding is wired up. The logic itself is tested in Rust (`cargo test`).
@Suite struct BindingTests {
    @Test func callsIntoTheCore() throws {
        #expect(coreVersion() == "0.1.0")
        #expect(factoryAddress() == "0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a")
        #expect(try parseUnits(text: "1.5", decimals: 6) == "0x16e360")
        let owners = [String(repeating: "11", count: 64), String(repeating: "22", count: 64)].map { "0x" + $0 }
        #expect(try accountAddress(initialOwners: owners) == "0x2c12B943Dc11D552Fa5648796BD0e85Ac4ddE92b")
    }

    @Test func errorsCarryReadableMessages() {
        do {
            _ = try checksumAddress(address: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")
            Issue.record("expected a checksum error")
        } catch {
            #expect(error.localizedDescription == "Address checksum doesn't match (check for a typo): 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")
        }
    }

    @Test func userOperationEncodesAsBundlerJSON() throws {
        let op = UserOperation(
            sender: "0x2c12B943Dc11D552Fa5648796BD0e85Ac4ddE92b", nonce: "0x0", initCode: "0x", callData: "0x",
            callGasLimit: "0x1", verificationGasLimit: "0x2", preVerificationGas: "0x3", maxFeePerGas: "0x4",
            maxPriorityFeePerGas: "0x5", paymasterAndData: "0x", signature: "0x"
        )
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(op)) as? [String: String]
        #expect(json?["preVerificationGas"] == "0x3")
        #expect(json?["maxPriorityFeePerGas"] == "0x5")
        #expect(json?.count == 11)
    }
}
