//
//  ViewController.swift
//  SwiftyPingTest
//
//  Created by Sami Yrjänheikki on 20/09/2018.
//  Copyright © 2018 Sami Yrjänheikki. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    @IBOutlet weak var textView: UITextView!
    override func viewDidLoad() {
        super.viewDidLoad()

        textView.text = ""
    }
    
    @IBAction func start(_ sender: Any) {
        startPinging()
    }
    @IBAction func stop(_ sender: Any) {
        ping?.stopPinging()
    }
    @IBAction func halt(_ sender: Any) {
        ping?.haltPinging()
    }
    var ping: SwiftyPing?
    func startPinging() {
        do {
            let host = "1.1.1.1"
            ping = try SwiftyPing(host: host, configuration: PingConfiguration(interval: 1.0, with: 1), queue: DispatchQueue.global())
            ping?.observer = { (response) in
                DispatchQueue.main.async {
                    var message = "\(response.duration * 1000) ms"
                    if let error = response.error {
                        if error == .responseTimeout {
                            message = "Timeout \(message)"
                        } else {
                            print(error)
                            message = error.localizedDescription
                        }
                    }
                    self.textView.text.append(contentsOf: "\nPing #\(response.trueSequenceNumber): \(message)")
                    self.textView.scrollRangeToVisible(NSRange(location: self.textView.text.count - 1, length: 1))
                }
            }
            ping?.finished = { (result) in
                DispatchQueue.main.async {
                    var message = "\n--- \(host) ping statistics ---\n"
                    message += "\(result.packetsTransmitted) transmitted, \(result.packetsReceived) received"
                    if let loss = result.packetLoss {
                        message += String(format: "\n%.1f%% packet loss\n", loss * 100)
                    } else {
                        message += "\n"
                    }
                    if let roundtrip = result.roundtrip {
                        message += String(format: "round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms", roundtrip.minimum * 1000, roundtrip.average * 1000, roundtrip.maximum * 1000, roundtrip.standardDeviation * 1000)
                    }
                    self.textView.text.append(contentsOf: message)
                    self.textView.scrollRangeToVisible(NSRange(location: self.textView.text.count - 1, length: 1))
                }
            }
//            ping?.targetCount = 1
            try ping?.startPinging()
        } catch {
            textView.text = error.localizedDescription
        }
    }
}

