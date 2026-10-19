import Foundation

extension CoreError: LocalizedError {
    /// The core's message, written to be shown to the user as-is.
    public var message: String {
        switch self {
        case .InvalidInput(let message), .InvalidAssertion(let message), .Refused(let message): message
        }
    }

    public var errorDescription: String? { message }
}
