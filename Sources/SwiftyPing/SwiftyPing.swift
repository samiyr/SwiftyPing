//
//  SwiftyPing.swift
//  SwiftyPing
//
//  Created by Sami Yrjänheikki on 6.8.2018.
//  Copyright © 2018 Sami Yrjänheikki. All rights reserved.
//

import Foundation
import Darwin

#if os(iOS)
import UIKit
#endif

public typealias Observer = ((_ response: PingResponse) -> Void)

/// Represents a ping delegate.
public protocol PingDelegate {
    /// Called when a ping response is received.
    /// - Parameter response: A `PingResponse` object representing the echo reply.
    func didReceive(response: PingResponse)
}

/// Describes all possible errors thrown within `SwiftyPing`
public enum PingError: Error, Equatable {
    // Response errors
    
    /// The response took longer to arrive than `configuration.timeoutInterval`.
    case responseTimeout
    
    // Response validation errors
    
    /// The response length was too short.
    case invalidLength(received: Int)
    /// The received checksum doesn't match the calculated one.
    case checksumMismatch(received: UInt16, calculated: UInt16)
    /// Response `type` was invalid.
    case invalidType(received: ICMPType.RawValue)
    /// Response `code` was invalid.
    case invalidCode(received: UInt8)
    /// Response `identifier` doesn't match what was sent.
    case identifierMismatch(received: UInt16, expected: UInt16)
    /// Response `sequenceNumber` doesn't match.
    case invalidSequenceIndex(received: Int, expected: Int)
    
    // Host resolve errors
    /// Unknown error occured within host lookup.
    case unknownHostError
    /// Address lookup failed.
    case addressLookupError
    /// Host was not found.
    case hostNotFound
    /// Address data could not be converted to `sockaddr`.
    case addressMemoryError

    // Request errors
    /// An error occured while sending the request.
    case requestError
    /// The request send timed out. Note that this is not "the" timeout,
    /// that would be `responseTimeout`. This timeout means that
    /// the ping request wasn't even sent within the timeout interval.
    case requestTimeout
    
    // Internal errors
    /// Checksum is out-of-bounds for `UInt16` in `computeCheckSum`. This shouldn't occur, but if it does, this error ensures that the app won't crash.
    case checksumOutOfBounds
    /// Unexpected payload length.
    case unexpectedPayloadLength
    /// Unspecified package creation error.
    case packageCreationFailed
    /// For some reason, the socket is `nil`. This shouldn't ever happen, but just in case...
    case socketNil
    /// The ICMP header offset couldn't be calculated.
    case invalidHeaderOffset
    /// Failed to change socket options, in particular SIGPIPE.
    case socketOptionsSetError(err: Int32)
}

// MARK: SwiftyPing

/// Class representing socket info, which contains a `SwiftyPing` instance and the identifier.
public class SocketInfo {
    public let pinger: SwiftyPing
    public let identifier: UInt16
    
    public init(pinger: SwiftyPing, identifier: UInt16) {
        self.pinger = pinger
        self.identifier = identifier
    }
}

/// Represents a single ping instance. A ping instance has a single destination.
public class SwiftyPing: NSObject {
    /// Describes the ping host destination.
    public struct Destination {
        /// The host name, can be a IP address or a URL.
        let host: String
        /// IPv4 address of the host.
        let ipv4Address: Data
        /// Socket address of `ipv4Address`.
        var socketAddress: sockaddr_in? { return ipv4Address.socketAddressInternet }
        /// IP address of the host.
        var ip: String? {
            guard let address = socketAddress else { return nil }
            return String(cString: inet_ntoa(address.sin_addr), encoding: .ascii)
        }
        
        /// Resolves the `host`.
        static func getIPv4AddressFromHost(host: String) throws -> Data {
            var streamError = CFStreamError()
            let cfhost = CFHostCreateWithName(nil, host as CFString).takeRetainedValue()
            let status = CFHostStartInfoResolution(cfhost, .addresses, &streamError)
            
            var data: Data?
            if !status {
                if Int32(streamError.domain) == kCFStreamErrorDomainNetDB {
                    throw PingError.addressLookupError
                } else {
                    throw PingError.unknownHostError
                }
            } else {
                var success: DarwinBoolean = false
                guard let addresses = CFHostGetAddressing(cfhost, &success)?.takeUnretainedValue() as? [Data] else {
                    throw PingError.hostNotFound
                }
                
                for address in addresses {
                    let addrin = address.socketAddress
                    if address.count >= MemoryLayout<sockaddr>.size && addrin.sa_family == UInt8(AF_INET) {
                        data = address
                        break
                    }
                }
                
                if data?.count == 0 || data == nil {
                    throw PingError.hostNotFound
                }
            }
            guard let returnData = data else { throw PingError.unknownHostError }
            return returnData
        }

    }
    // MARK: - Initialization
    /// Ping host
    public let destination: Destination
    /// Ping configuration
    public let configuration: PingConfiguration
    /// This closure gets called with ping responses.
    public var observer: Observer?
    /// This delegate gets called with ping responses.
    public var delegate: PingDelegate?
    /// The number of pings to make. Default is `nil`, which means no limit.
    public var targetCount: Int?

    /// A random identifier which is a part of the ping request.
    private let identifier = UInt16.random(in: 0..<UInt16.max)
    /// A random UUID fingerprint sent as the payload.
    private let fingerprint = UUID()
    /// User-specified dispatch queue. The `observer` is always called from this queue.
    private let currentQueue: DispatchQueue
    
    /// Socket for sending and receiving data.
    private var socket: CFSocket?
    /// Socket source
    private var socketSource: CFRunLoopSource?
    
    /// When the current request was sent.
    private var sequenceStart: Date?
    /// The current sequence number.
    private var _sequenceIndex = 0
    private var sequenceIndex: Int {
        get {
            _serial.sync { self._sequenceIndex }
        }
        set {
            _serial.sync { self._sequenceIndex = newValue }
        }
    }
    
    /// Initializes a pinger.
    /// - Parameter destination: Specifies the host.
    /// - Parameter configuration: A configuration object which can be used to customize pinging behavior.
    /// - Parameter queue: All responses are delivered through this dispatch queue.
    public init(destination: Destination, configuration: PingConfiguration, queue: DispatchQueue) throws {
        self.destination = destination
        self.configuration = configuration
        self.currentQueue = queue
                
        super.init()
        try createSocket()
        
        #if os(iOS)
        if configuration.handleBackgroundTransitions {
            addAppStateNotifications()
        }
        #endif
    }
    
    #if os(iOS)
    /// Adds notification observers for iOS app state changes.
    private func addAppStateNotifications() {
        NotificationCenter.default.addObserver(self, selector: #selector(didEnterBackground), name: UIApplication.didEnterBackgroundNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(didEnterForeground), name: UIApplication.didBecomeActiveNotification, object: nil)
    }
    
    /// A flag to determine whether the pinger was halted automatically by an app state change.
    private var autoHalted = false
    /// Called on `UIApplication.didEnterBackgroundNotification`.
    @objc private func didEnterBackground() {
        autoHalted = true
        haltPinging(resetSequence: false)
    }
    /// Called on ` UIApplication.didBecomeActiveNotification`.
    @objc private func didEnterForeground() {
        if autoHalted {
            autoHalted = false
            try? startPinging()
        }
    }
    #endif

    // MARK: - Convenience Initializers
    /// Initializes a pinger from an IPv4 address string.
    /// - Parameter ipv4Address: The host's IP address.
    /// - Parameter configuration: A configuration object which can be used to customize pinging behavior.
    /// - Parameter queue: All responses are delivered through this dispatch queue.
    public convenience init(ipv4Address: String, config configuration: PingConfiguration, queue: DispatchQueue) throws {
        var socketAddress = sockaddr_in()
        
        socketAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        socketAddress.sin_family = UInt8(AF_INET)
        socketAddress.sin_port = 0
        socketAddress.sin_addr.s_addr = inet_addr(ipv4Address.cString(using: .utf8))
        let data = Data(bytes: &socketAddress, count: MemoryLayout<sockaddr_in>.size)
        
        let destination = Destination(host: ipv4Address, ipv4Address: data)
        try self.init(destination: destination, configuration: configuration, queue: queue)
    }
    /// Initializes a pinger from a given host string.
    /// - Parameter host: A string describing the host. This can be an IP address or host name.
    /// - Parameter configuration: A configuration object which can be used to customize pinging behavior.
    /// - Parameter queue: All responses are delivered through this dispatch queue.
    /// - Throws: A `PingError` if the given host could not be resolved.
    public convenience init(host: String, configuration: PingConfiguration, queue: DispatchQueue) throws {
        let result = try Destination.getIPv4AddressFromHost(host: host)
        let destination = Destination(host: host, ipv4Address: result)
        try self.init(destination: destination, configuration: configuration, queue: queue)
    }
    
    /// Initializes a CFSocket.
    /// - Throws: If setting a socket options flag fails, throws a `PingError.socketOptionsSetError(:)`.
    private func createSocket() throws {
        // Create a socket context...
        let info = SocketInfo(pinger: self, identifier: identifier)
        var context = CFSocketContext(version: 0, info: Unmanaged.passRetained(info).toOpaque(), retain: nil, release: nil, copyDescription: nil)

        // ...and a socket...
        socket = CFSocketCreate(kCFAllocatorDefault, AF_INET, SOCK_DGRAM, IPPROTO_ICMP, CFSocketCallBackType.dataCallBack.rawValue, { socket, type, address, data, info in
            // Socket callback closure
            guard let socket = socket, let info = info, let data = data else { return }
            let socketInfo = Unmanaged<SocketInfo>.fromOpaque(info).takeUnretainedValue()
            let ping = socketInfo.pinger
            if (type as CFSocketCallBackType) == CFSocketCallBackType.dataCallBack {
                let cfdata = Unmanaged<CFData>.fromOpaque(data).takeUnretainedValue()
                ping.socket(socket: socket, didReadData: cfdata as Data)
            }
            
        }, &context)
        
        // Disable SIGPIPE, see issue #15 on GitHub.
        let handle = CFSocketGetNative(socket)
        var value: Int32 = 1
        let err = setsockopt(handle, SOL_SOCKET, SO_NOSIGPIPE, &value, socklen_t(MemoryLayout.size(ofValue: value)))
        guard err == 0 else {
            throw PingError.socketOptionsSetError(err: err)
        }
        
        // ...and add it to the main run loop.
        socketSource = CFSocketCreateRunLoopSource(nil, socket, 0)
        CFRunLoopAddSource(CFRunLoopGetMain(), socketSource, .commonModes)
    }

    // MARK: - Tear-down
    deinit {
        if socketSource != nil {
            CFRunLoopSourceInvalidate(socketSource)
            socketSource = nil
        }
        socket = nil
        timeoutTimer?.invalidate()
        timeoutTimer = nil
    }

    // MARK: - Single ping
    
    private var _isPinging = false
    private var isPinging: Bool {
        get {
            return _serial.sync { self._isPinging }
        }
        set {
            _serial.sync { self._isPinging = newValue }
        }
    }

    private var _timeoutTimer: Timer?
    private var timeoutTimer: Timer? {
        get {
            return _serial.sync { self._timeoutTimer }
        }
        set {
            _serial.sync { self._timeoutTimer = newValue }
        }
    }
        
    private func sendPing() {
        if isPinging || killswitch {
            return
        }
        isPinging = true
        sequenceStart = Date()
        
        let timer = Timer(timeInterval: self.configuration.timeoutInterval, target: self, selector: #selector(self.timeout), userInfo: nil, repeats: false)
        RunLoop.main.add(timer, forMode: .common)
        self.timeoutTimer = timer

        currentQueue.async {
            let address = self.destination.ipv4Address
            do {
                let icmpPackage = try self.createICMPPackage(identifier: UInt16(self.identifier), sequenceNumber: UInt16(self.sequenceIndex))
                
                guard let socket = self.socket else { return }
                let socketError = CFSocketSendData(socket, address as CFData, icmpPackage as CFData, self.configuration.timeoutInterval)

                if socketError != .success {
                    var error: PingError?
                    
                    switch socketError {
                    case .error: error = .requestError
                    case .timeout: error = .requestTimeout
                    default: break
                    }
                    let response = PingResponse(identifier: self.identifier,
                                                ipAddress: self.destination.ip,
                                                sequenceNumber: self.sequenceIndex,
                                                duration: self.timeIntervalSinceStart,
                                                error: error,
                                                byteCount: nil,
                                                ipHeader: nil)
                    self.isPinging = false
                    self.informObserver(of: response)
                    
                    return self.scheduleNextPing()
                }
            } catch {
                let pingError: PingError
                if let err = error as? PingError {
                    pingError = err
                } else {
                    pingError = .packageCreationFailed
                }
                let response = PingResponse(identifier: self.identifier,
                                            ipAddress: self.destination.ip,
                                            sequenceNumber: self.sequenceIndex,
                                            duration: self.timeIntervalSinceStart,
                                            error: pingError,
                                            byteCount: nil,
                                            ipHeader: nil)
                self.isPinging = false
                self.informObserver(of: response)
                
                return self.scheduleNextPing()
            }
        }
    }
    
    private var timeIntervalSinceStart: TimeInterval? {
        if let start = sequenceStart {
            return Date().timeIntervalSince(start)
        }
        return nil
    }

    @objc private func timeout() {
        let error = PingError.responseTimeout
        let response = PingResponse(identifier: self.identifier,
                                    ipAddress: self.destination.ip,
                                    sequenceNumber: self.sequenceIndex,
                                    duration: timeIntervalSinceStart,
                                    error: error,
                                    byteCount: nil,
                                    ipHeader: nil)
        self.isPinging = false
        informObserver(of: response)

        incrementSequenceIndex()
        scheduleNextPing()
    }
    
    private func informObserver(of response: PingResponse) {
        if killswitch { return }
        currentQueue.sync {
            self.observer?(response)
            self.delegate?.didReceive(response: response)
        }
    }
    
    // MARK: - Continuous ping
    
    private func shouldSchedulePing() -> Bool {
        if killswitch { return false }
        if let target = targetCount {
            if sequenceIndex < target {
                return true
            }
            return false
        }
        return true
    }
    private func scheduleNextPing() {
        if shouldSchedulePing() {
            currentQueue.asyncAfter(deadline: .now() + configuration.pingInterval) {
                self.sendPing()
            }
        }
    }
    
    private let _serial = DispatchQueue(label: "SwiftyPing internal")
    
    private var _killswitch = false
    private var killswitch: Bool {
        get {
            return _serial.sync { self._killswitch }
        }
        set {
            _serial.sync { self._killswitch = newValue }
        }
    }
    
    /// Start pinging the host.
    public func startPinging() throws {
        if socket == nil {
            try createSocket()
        }
        killswitch = false
        sendPing()
    }
    
    /// Stop pinging the host.
    /// - Parameter resetSequence: Controls whether the sequence index should be set back to zero.
    public func stopPinging(resetSequence: Bool = true) {
        killswitch = true
        isPinging = false
        if resetSequence {
            sequenceIndex = 0
            sequenceStart = nil
        }
    }
    /// Stops pinging the host and destroys the CFSocket object.
    /// - Parameter resetSequence: Controls whether the sequence index should be set back to zero.
    public func haltPinging(resetSequence: Bool = true) {
        stopPinging(resetSequence: resetSequence)
        if socketSource != nil {
            CFRunLoopSourceInvalidate(socketSource)
        }
        socketSource = nil
        socket = nil
    }
    
    private func incrementSequenceIndex() {
        // Handle overflow gracefully
        if sequenceIndex >= Int.max {
            sequenceIndex = 0
        } else {
            sequenceIndex += 1
        }
    }
    
    // MARK: - Socket callback
    private func socket(socket: CFSocket, didReadData data: Data?) {
        timeoutTimer?.invalidate()
        
        if killswitch { return }
        
        guard let data = data else { return }
        var validationError: PingError? = nil
        
        do {
            let validation = try validateResponse(from: data)
            if !validation { return }
        } catch let error as PingError {
            validationError = error
        } catch {
            print("Unhandled error thrown: \(error)")
        }
        var ipHeader: IPHeader? = nil
        if validationError == nil {
            ipHeader = data.withUnsafeBytes({ $0.load(as: IPHeader.self) })
        }
        let response = PingResponse(identifier: identifier,
                                    ipAddress: destination.ip,
                                    sequenceNumber: sequenceIndex,
                                    duration: timeIntervalSinceStart,
                                    error: validationError,
                                    byteCount: data.count,
                                    ipHeader: ipHeader)
        isPinging = false
        informObserver(of: response)
        
        incrementSequenceIndex()
        scheduleNextPing()
    }

    // MARK: - ICMP package
    
    /// Creates an ICMP package.
    private func createICMPPackage(identifier: UInt16, sequenceNumber: UInt16) throws -> Data {
        var header = ICMPHeader(type: ICMPType.EchoRequest.rawValue,
                                code: 0,
                                checksum: 0,
                                identifier: CFSwapInt16HostToBig(identifier),
                                sequenceNumber: CFSwapInt16HostToBig(sequenceNumber),
                                payload: fingerprint.uuid)
                
        let checksum = try computeChecksum(header: header)
        header.checksum = checksum
        
        let package = Data(bytes: &header, count: MemoryLayout<ICMPHeader>.size)
        return package
    }
    
    private func computeChecksum(header: ICMPHeader) throws -> UInt16 {
        let typecode = Data([header.type, header.code]).withUnsafeBytes { $0.load(as: UInt16.self) }
        var sum = UInt64(typecode) + UInt64(header.identifier) + UInt64(header.sequenceNumber)
        let payload = convert(payload: header.payload)
        
        guard payload.count % 2 == 0 else { throw PingError.unexpectedPayloadLength }
        
        var i = 0
        while i < payload.count {
            guard payload.indices.contains(i + 1) else { throw PingError.unexpectedPayloadLength }
            // Convert two 8 byte ints to one 16 byte int
            sum += Data([payload[i], payload[i + 1]]).withUnsafeBytes { UInt64($0.load(as: UInt16.self)) }
            i += 2
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }

        guard sum < UInt16.max else { throw PingError.checksumOutOfBounds }
        
        return ~UInt16(sum)
    }
        
    private func icmpHeaderOffset(of packet: Data) -> Int? {
        if packet.count >= MemoryLayout<IPHeader>.size + MemoryLayout<ICMPHeader>.size {
            let ipHeader = packet.withUnsafeBytes({ $0.load(as: IPHeader.self) })
            if ipHeader.versionAndHeaderLength & 0xF0 == 0x40 && ipHeader.protocol == IPPROTO_ICMP {
                let headerLength = Int(ipHeader.versionAndHeaderLength) & 0x0F * MemoryLayout<UInt32>.size
                if packet.count >= headerLength + MemoryLayout<ICMPHeader>.size {
                    return headerLength
                }
            }
        }
        return nil
    }
    
    private func convert(payload: uuid_t) -> [UInt8] {
        let p = payload
        return [p.0, p.1, p.2, p.3, p.4, p.5, p.6, p.7, p.8, p.9, p.10, p.11, p.12, p.13, p.14, p.15].map { UInt8($0) }
    }
    
    private func validateResponse(from data: Data) throws -> Bool {
        guard data.count >= MemoryLayout<ICMPHeader>.size + MemoryLayout<IPHeader>.size else {
            throw PingError.invalidLength(received: data.count)
        }
                
        guard let headerOffset = icmpHeaderOffset(of: data) else { throw PingError.invalidHeaderOffset }
        let icmpHeader = data.withUnsafeBytes({ $0.load(fromByteOffset: headerOffset, as: ICMPHeader.self) })
        
        let uuid = UUID(uuid: icmpHeader.payload)
        guard uuid == fingerprint else {
            // Wrong handler, ignore this response
            return false
        }

        let checksum = try computeChecksum(header: icmpHeader)
        
        guard icmpHeader.checksum == checksum else {
            throw PingError.checksumMismatch(received: icmpHeader.checksum, calculated: checksum)
        }
        guard icmpHeader.type == ICMPType.EchoReply.rawValue else {
            throw PingError.invalidType(received: icmpHeader.type)
        }
        guard icmpHeader.code == 0 else {
            throw PingError.invalidCode(received: icmpHeader.code)
        }
        guard CFSwapInt16BigToHost(icmpHeader.identifier) == identifier else {
            throw PingError.identifierMismatch(received: icmpHeader.identifier, expected: identifier)
        }
        let receivedSequenceIndex = CFSwapInt16BigToHost(icmpHeader.sequenceNumber)
        guard receivedSequenceIndex == sequenceIndex else {
            throw PingError.invalidSequenceIndex(received: Int(receivedSequenceIndex), expected: sequenceIndex)
        }
        return true
    }

}

    // MARK: ICMP

    /// Format of IPv4 header
    public struct IPHeader {
        var versionAndHeaderLength: UInt8
        var differentiatedServices: UInt8
        var totalLength: UInt16
        var identification: UInt16
        var flagsAndFragmentOffset: UInt16
        var timeToLive: UInt8
        var `protocol`: UInt8
        var headerChecksum: UInt16
        var sourceAddress: (UInt8, UInt8, UInt8, UInt8)
        var destinationAddress: (UInt8, UInt8, UInt8, UInt8)
    }

    /// ICMP header structure
    private struct ICMPHeader {
        /// Type of message
        var type: UInt8
        /// Type sub code
        var code: UInt8
        /// One's complement checksum of struct
        var checksum: UInt16
        /// Identifier
        var identifier: UInt16
        /// Sequence number
        var sequenceNumber: UInt16
        /// UUID payload
        var payload: uuid_t
    }

    /// ICMP echo types
    public enum ICMPType: UInt8 {
        case EchoReply = 0
        case EchoRequest = 8
    }

// MARK: - Helpers

/// A struct encapsulating a ping response.
public struct PingResponse {
    /// The randomly generated identifier used in the ping header.
    public let identifier: UInt16
    /// The IP address of the host.
    public let ipAddress: String?
    /// Running sequence number, starting from 0.
    public let sequenceNumber: Int
    /// Roundtrip time.
    public let duration: TimeInterval?
    /// An error associated with the response.
    public let error: PingError?
    /// Response data packet size in bytes.
    public let byteCount: Int?
    /// Response IP header.
    public let ipHeader: IPHeader?
}
/// Controls pinging behaviour.
public struct PingConfiguration {
    /// The time between consecutive pings in seconds.
    let pingInterval: TimeInterval
    /// Timeout interval in seconds.
    let timeoutInterval: TimeInterval
    /// If `true`, then `SwiftyPing` will automatically halt and restart the pinging when the app state changes. Only applicable on iOS. If `false`, then the user is responsible for appropriately handling app state changes, see issue #15 on GitHub.
    var handleBackgroundTransitions = true
    
    /// Initializes a `PingConfiguration` object with the given parameters.
    /// - Parameter interval: The time between consecutive pings in seconds. Defaults to 1.
    /// - Parameter timeout: Timeout interval in seconds. Defaults to 5.
    public init(interval: TimeInterval = 1, with timeout: TimeInterval = 5) {
        pingInterval = interval
        timeoutInterval = timeout
    }
    /// Initializes a `PingConfiguration` object with the given interval.
    /// - Parameter interval: The time between consecutive pings in seconds.
    /// - Note: Timeout interval will be set to 5 seconds.
    public init(interval: TimeInterval) {
        self.init(interval: interval, with: 5)
    }
}

// MARK: - Data Extensions

public extension Data {
    /// Expresses a chunk of data as a socket address.
    var socketAddress: sockaddr {
        return withUnsafeBytes { $0.load(as: sockaddr.self) }
    }
    /// Expresses a chunk of data as an internet-style socket address.
    var socketAddressInternet: sockaddr_in {
        return withUnsafeBytes { $0.load(as: sockaddr_in.self) }
    }
}
