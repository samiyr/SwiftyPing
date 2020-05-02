//
//  SwiftyPing.swift
//  SwiftyPing
//
//  Created by Sami Yrjänheikki on 6.8.2018.
//  Copyright © 2018 Sami Yrjänheikki. All rights reserved.
//

import Foundation
import Darwin

public typealias Observer = (( _ ping: SwiftyPing, _ response: PingResponse) -> Void)
public typealias ErrorClosure = ((_ ping: SwiftyPing, _ error: NSError) -> Void)

// MARK: SwiftyPing

public class SwiftyPing: NSObject {
    public struct Destination {
        let host: String
        let ipv4Address: Data
        var socketAddress: sockaddr_in? { return ipv4Address.socketAddressInternet }
        var ip: String? {
            guard let address = socketAddress else { return nil }
            return String(cString: inet_ntoa(address.sin_addr), encoding: .ascii)
        }
        
        enum HostResolveError: Error {
            case unknown, addressLookupError, hostNotFound, addressMemoryError
        }
        
        static func getIPv4AddressFromHost(host: String) throws -> Data {
            var streamError = CFStreamError()
            let cfhost = CFHostCreateWithName(nil, host as CFString).takeRetainedValue()
            let status = CFHostStartInfoResolution(cfhost, .addresses, &streamError)
            
            var data: Data?
            if !status {
                if Int32(streamError.domain)  == kCFStreamErrorDomainNetDB {
                    throw HostResolveError.addressLookupError
                } else {
                    throw HostResolveError.unknown
                }
            } else {
                var success: DarwinBoolean = false
                guard let addresses = CFHostGetAddressing(cfhost, &success)?.takeUnretainedValue() as? [Data] else {
                    throw HostResolveError.hostNotFound
                }
                
                for address in addresses {
                    guard let addrin = address.socketAddress else { throw HostResolveError.addressMemoryError }
                    if address.count >= MemoryLayout<sockaddr>.size && addrin.sa_family == UInt8(AF_INET) {
                        data = address
                        break
                    }
                }
                
                if data?.count == 0 || data == nil {
                    throw HostResolveError.hostNotFound
                }
            }
            guard let returnData = data else { throw HostResolveError.unknown }
            return returnData
        }

    }
    // MARK: - Initialization
    let destination: Destination
    let configuration: PingConfiguration
    let identifier = UInt32(arc4random_uniform(UInt32(UInt16.max)))
    
    let currentQueue: DispatchQueue
    
    var socket: CFSocket?
    var socketSource: CFRunLoopSource?
    
    public var observer: Observer?
    
    var sequenceStart: Date?
    var sequenceIndex = 0
    
    public var targetCount: Int?
    
    init(destination: Destination, configuration: PingConfiguration, queue: DispatchQueue) {
        self.destination = destination
        self.configuration = configuration
        self.currentQueue = queue
                
        super.init()

        var context = CFSocketContext(version: 0,
                                      info: Unmanaged.passRetained(self).toOpaque(),
                                      retain: nil,
                                      release: nil,
                                      copyDescription: nil)
        
        self.socket = CFSocketCreate(kCFAllocatorDefault, AF_INET, SOCK_DGRAM, IPPROTO_ICMP, CFSocketCallBackType.dataCallBack.rawValue, { socket, type, address, data, info in
            guard let socket = socket, let info = info else { return }
            let ping: SwiftyPing = Unmanaged.fromOpaque(info).takeUnretainedValue()
            if (type as CFSocketCallBackType) == CFSocketCallBackType.dataCallBack {
                let fData = data?.assumingMemoryBound(to: UInt8.self)
                let bytes = UnsafeBufferPointer<UInt8>(start: fData, count: MemoryLayout<UInt8>.size)
                let cfdata = Data(buffer: bytes)
                ping.socket(socket: socket, didReadData: cfdata)
            }
            
        }, &context)
        
        socketSource = CFSocketCreateRunLoopSource(nil, socket, 0)
        CFRunLoopAddSource(CFRunLoopGetMain(), socketSource, .commonModes)
    }

    // MARK: - Convenience Initializers
    convenience init(ipv4Address: String, config configuration: PingConfiguration, queue: DispatchQueue) {
        var socketAddress = sockaddr_in()
        memset(&socketAddress, 0, MemoryLayout<sockaddr_in>.size)
        
        socketAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        socketAddress.sin_family = UInt8(AF_INET)
        socketAddress.sin_port = 0
        socketAddress.sin_addr.s_addr = inet_addr(ipv4Address.cString(using: String.Encoding.utf8))
        let data = NSData(bytes: &socketAddress, length: MemoryLayout<sockaddr_in>.size)
        
        let destination = Destination(host: ipv4Address, ipv4Address: data as Data)
        self.init(destination: destination, configuration: configuration, queue: queue)
    }
    convenience init(host: String, configuration: PingConfiguration, queue: DispatchQueue) throws {
        let result = try Destination.getIPv4AddressFromHost(host: host)
        let destination = Destination(host: host, ipv4Address: result)
        self.init(destination: destination, configuration: configuration, queue: queue)
    }

    // MARK: - Tear-down
    deinit {
        CFRunLoopSourceInvalidate(socketSource)
        socketSource = nil
        socket = nil
    }

    // MARK: - Single ping
    
    var isPinging = false
    private var timeoutBlock: (() -> Void)?

    func sendPing() {
        if isPinging {
            return
        }
        isPinging = true
        sequenceIndex += 1
        sequenceStart = Date()
        
        currentQueue.async {
            let address = self.destination.ipv4Address
            guard let icmpPackage = self.createICMPPackage(identifier: UInt16(self.identifier), sequenceNumber: UInt16(self.sequenceIndex), payloadSize: Int(self.configuration.payloadSize)), let socket = self.socket else { return }
            let socketError = CFSocketSendData(socket, address as CFData, icmpPackage as CFData, self.configuration.timeoutInterval)
            
            switch socketError {
            case .error:
                let error = NSError(domain: NSURLErrorDomain, code:NSURLErrorCannotFindHost, userInfo: [:])
                let response = PingResponse(identifier: self.identifier, ipAddress: self.destination.ip ?? "", sequenceNumber: self.sequenceIndex, duration: Date().timeIntervalSince(self.sequenceStart ?? Date()), error: error)
                self.isPinging = false
                self.observer?(self, response)
                
                return self.scheduleNextPing()
            case .timeout:
                let error = NSError(domain: NSURLErrorDomain, code:NSURLErrorTimedOut, userInfo: [:])
                let response = PingResponse(identifier: self.identifier, ipAddress: self.destination.ip ?? "", sequenceNumber: self.sequenceIndex, duration: Date().timeIntervalSince(self.sequenceStart ?? Date()), error: error)
                self.isPinging = false
                self.observer?(self, response)
                
                return self.scheduleNextPing()
                
            default: break
            }
            
            let sequenceNumber = self.sequenceIndex
            self.timeoutBlock = { () -> Void in
                if sequenceNumber != self.sequenceIndex {
                    return
                }
                
                self.timeoutBlock = nil
                let error = NSError(domain: NSURLErrorDomain, code:NSURLErrorTimedOut, userInfo: [:])
                let response = PingResponse(identifier: self.identifier, ipAddress: self.destination.ip ?? "", sequenceNumber: self.sequenceIndex, duration: Date().timeIntervalSince(self.sequenceStart ?? Date()), error: error)
                self.isPinging = false
                self.observer?(self, response)
                self.scheduleNextPing()
            }
        }
    }

    
    // MARK: - Continuous ping
    
    func shouldSchedulePing() -> Bool {
        if let target = targetCount {
            if sequenceIndex < target {
                return true
            }
            return false
        }
        return true
    }
    func scheduleNextPing() {
        if shouldSchedulePing() {
            currentQueue.asyncAfter(deadline: .now() + configuration.pingInterval) {
                self.sendPing()
            }
        }
    }
    
    public func startPinging() {
        targetCount = nil
        sendPing()
    }
    
    public func stopPinging() {
        targetCount = 0
        isPinging = false
        sequenceIndex = 0
        sequenceStart = nil
    }
    
    // MARK: - Socket callback
    func socketCallback(socket: CFSocket, type: CFSocketCallBackType, address: CFData, data: UnsafeRawPointer, info: UnsafeMutableRawPointer) {
        var info = info
        let ping = withUnsafePointer(to: &info) { (temp) in
            return unsafeBitCast(temp, to: SwiftyPing.self)
        }
        
        if (type as CFSocketCallBackType) == CFSocketCallBackType.dataCallBack {
            let fData = data.assumingMemoryBound(to: UInt8.self)
            let bytes = UnsafeBufferPointer<UInt8>(start: fData, count: MemoryLayout<UInt8>.size)
            let cfdata = Data(buffer: bytes)
            ping.socket(socket: socket, didReadData: cfdata)
        }
    }

    func socket(socket: CFSocket, didReadData data: Data?) {
        var ipHeaderData:NSData?
        var ipData:NSData?
        var icmpHeaderData:NSData?
        var icmpData:NSData?
        
        let extractIPAddressBlock: () -> String? = {
            if ipHeaderData == nil {
                return nil
            }
            guard var bytes = ipHeaderData?.bytes else { return nil }
            let ipHeader:IPHeader = withUnsafePointer(to: &bytes) { (temp) in
                return unsafeBitCast(temp, to: IPHeader.self)
            }
            
            let sourceAddr = ipHeader.sourceAddress
            
            return "\(sourceAddr[0]).\(sourceAddr[1]).\(sourceAddr[2]).\(sourceAddr[3])"
        }
        guard let data = data else { return }
        if !extractResponse(from: data as NSData, ipHeaderData: &ipHeaderData, ipData: &ipData, icmpHeaderData: &icmpHeaderData, icmpData: &icmpData) {
            if ipHeaderData != nil, destination.ip == extractIPAddressBlock() {
                return
            }
        }
        guard let start = sequenceStart else { return }
        let response = PingResponse(identifier: identifier, ipAddress: destination.ip ?? "", sequenceNumber: sequenceIndex, duration: Date().timeIntervalSince(start), error: nil)
        isPinging = false
        observer?(self, response)
        
        scheduleNextPing()
    }

    // MARK: - ICMP package
    
    func createICMPPackage(identifier: UInt16, sequenceNumber: UInt16, payloadSize: Int)-> NSData? {
        let packageDebug = false  // triggers print statements below
        
        var icmpType = ICMPType.EchoRequest.rawValue
        var icmpCode: UInt8 = 0
        var icmpChecksum: UInt16 = 0
        var icmpIdentifier = identifier
        var icmpSequence = sequenceNumber
        
        let randomBytes = [UInt32](repeating: 0, count: payloadSize).map { _ in Int.random(in: 0...1) }
        let packetData = Data(bytes: randomBytes, count: payloadSize)
        
        var payload = NSData(data: packetData)
        payload = payload.subdata(with: NSRange(location: 0, length: Int(payloadSize))) as NSData
        guard let package = NSMutableData(capacity: MemoryLayout<ICMPHeader>.size + payload.length) else { return nil }
        package.replaceBytes(in: NSRange(location: 0, length: 1), withBytes: &icmpType)
        package.replaceBytes(in: NSRange(location: 1, length: 1), withBytes: &icmpCode)
        package.replaceBytes(in: NSRange(location: 2, length: 2), withBytes: &icmpChecksum)
        package.replaceBytes(in: NSRange(location: 4, length: 2), withBytes: &icmpIdentifier)
        package.replaceBytes(in: NSRange(location: 6, length: 2), withBytes: &icmpSequence)
        package.replaceBytes(in: NSRange(location: 8, length: payload.length), withBytes: payload.bytes)
        
        let bytes = package.mutableBytes
        icmpChecksum = computeCheckSum(buffer: bytes, bufLen: package.length)
        package.replaceBytes(in: NSRange(location: 2, length: 2), withBytes: &icmpChecksum)
        if packageDebug { print("ping package: \(package)") }
        return package
    }
    
    func computeCheckSum(buffer: UnsafeMutableRawPointer, bufLen: Int) -> UInt16 {
        var bufLen = bufLen
        var checksum:UInt32 = 0
        var buf = buffer.assumingMemoryBound(to: UInt16.self)
        
        while bufLen > 1 {
            checksum += UInt32(buf.pointee)
            buf = buf.successor()
            bufLen -= MemoryLayout<UInt16>.size
        }
        
        if bufLen == 1 {
            checksum += UInt32(UnsafeMutablePointer<UInt16>(buf).pointee)
        }
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        return ~UInt16(checksum)
    }
    
    func extractResponse(from data: NSData, ipHeaderData: AutoreleasingUnsafeMutablePointer<NSData?>, ipData: AutoreleasingUnsafeMutablePointer<NSData?>, icmpHeaderData: AutoreleasingUnsafeMutablePointer<NSData?>, icmpData: AutoreleasingUnsafeMutablePointer<NSData?>) -> Bool {
        
        guard let buffer = data.mutableCopy() as? NSMutableData else { return false }
        
        if buffer.length < (MemoryLayout<IPHeader>.size+MemoryLayout<ICMPHeader>.size) {
            return false
        }
        
        var mutableBytes = buffer.mutableBytes
        
        let ipHeader = withUnsafePointer(to: &mutableBytes) { (temp) in
            return unsafeBitCast(temp, to: IPHeader.self)
        }
        
        // IPv4 and ICMP
        guard ipHeader.versionAndHeaderLength & 0xF0 == 0x40, ipHeader.protocol == 1 else { return false }
        
        let ipHeaderLength = (ipHeader.versionAndHeaderLength & 0x0F) * UInt8(MemoryLayout<UInt32>.size)
        let range = NSMakeRange(0, MemoryLayout<IPHeader>.size)
        ipHeaderData.pointee = buffer.subdata(with: range) as NSData?
        
        if buffer.length >= MemoryLayout<IPHeader>.size + Int(ipHeaderLength) {
            ipData.pointee = buffer.subdata(with: NSMakeRange(MemoryLayout<IPHeader>.size, Int(ipHeaderLength))) as NSData?
        }
        
        if buffer.length < Int(ipHeaderLength) + MemoryLayout<ICMPHeader>.size {
            return false
        }
        
        let icmpHeaderOffset = size_t(ipHeaderLength)
        
        var headerBuffer = mutableBytes.assumingMemoryBound(to: UInt8.self) + icmpHeaderOffset
        
        var icmpHeader = withUnsafePointer(to: &headerBuffer) { (temp) in
            return unsafeBitCast(temp, to: ICMPHeader.self)
        }
        
        let receivedChecksum = icmpHeader.checkSum
        let calculatedChecksum = computeCheckSum(buffer: &icmpHeader, bufLen: buffer.length - icmpHeaderOffset)
        icmpHeader.checkSum = receivedChecksum
        
        if receivedChecksum != calculatedChecksum {
            print("invalid ICMP header. Checksums did not match")
            return false
        }
        
        let icmpDataRange = NSMakeRange(icmpHeaderOffset + MemoryLayout<ICMPHeader>.size, buffer.length - (icmpHeaderOffset + MemoryLayout<ICMPHeader>.size))
        icmpHeaderData.pointee = buffer.subdata(with: NSMakeRange(icmpHeaderOffset, MemoryLayout<ICMPHeader>.size)) as NSData?
        icmpData.pointee = buffer.subdata(with:icmpDataRange) as NSData?
        
        return true
    }
    

    // MARK: ICMP

    struct IPHeader {
        var versionAndHeaderLength: UInt8
        var differentiatedServices: UInt8
        var totalLength: UInt16
        var identification: UInt16
        var flagsAndFragmentOffset: UInt16
        var timeToLive: UInt8
        var `protocol`: UInt8
        var headerChecksum: UInt16
        var sourceAddress: [UInt8]
        var destinationAddress: [UInt8]
    }


    struct ICMPHeader {
        var type: UInt8      /* type of message*/
        var code: UInt8      /* type sub code */
        var checkSum: UInt16 /* ones complement cksum of struct */
        var identifier: UInt16
        var sequenceNumber: UInt16
        var data:timeval
    }

    // ICMP type and code combinations:

    enum ICMPType: UInt8{
        case EchoReply = 0           // code is always 0
        case EchoRequest = 8            // code is always 0
    }

}

// MARK: - Helpers

public struct PingResponse {
    public let identifier: UInt32
    public let ipAddress: String?
    public let sequenceNumber: Int
    public let duration: TimeInterval
    public let error: NSError?
}
public struct PingConfiguration {
    let pingInterval: TimeInterval
    let timeoutInterval: TimeInterval
    let payloadSize: UInt64
    
    public init(interval: TimeInterval = 1, with timeout: TimeInterval = 5, and payload: UInt64 = 64) {
        pingInterval = interval
        timeoutInterval = timeout
        payloadSize = payload
    }
    public init(interval: TimeInterval) {
        self.init(interval: interval, with: 5)
    }
    public init(interval: TimeInterval, with timeout: TimeInterval) {
        self.init(interval: interval, with: timeout, and: 64)
    }
}

// MARK: - Data Extensions

extension Data {
    public var socketAddress: sockaddr? {
        return self.withUnsafeBytes { (pointer: UnsafeRawBufferPointer) -> sockaddr? in
            let raw = pointer.baseAddress
            let address = raw?.assumingMemoryBound(to: sockaddr.self).pointee
            return address
        }
    }
    public var socketAddressInternet: sockaddr_in? {
        return self.withUnsafeBytes { (pointer: UnsafeRawBufferPointer) -> sockaddr_in? in
            let raw = pointer.baseAddress
            let address = raw?.assumingMemoryBound(to: sockaddr_in.self).pointee
            return address
        }
    }
}
