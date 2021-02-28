//
//  ViewController.swift
//  SwiftyPingTestMac
//
//  Created by Sami Yrjänheikki on 28.2.2021.
//  Copyright © 2021 Sami Yrjänheikki. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {

    @IBOutlet var textView: NSTextView!
    override func viewDidLoad() {
        super.viewDidLoad()

        textView.string = ""
        textView.isEditable = false
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
            ping = try SwiftyPing(host: "1.1.1.1", configuration: PingConfiguration(interval: 1.0, with: 1), queue: DispatchQueue.global())
            ping?.observer = { (response) in
                DispatchQueue.main.async {
                    var message = "\(response.duration! * 1000) ms"
                    if let error = response.error {
                        if error == .responseTimeout {
                            message = "Timeout \(message)"
                        } else {
                            print(error)
                            message = error.localizedDescription
                        }
                    }
                    self.textView.string.append(contentsOf: "\nPing #\(response.sequenceNumber): \(message)")
                    self.textView.scrollRangeToVisible(NSRange(location: self.textView.string.count - 1, length: 1))
                }
            }
//            ping?.targetCount = 1
            try ping?.startPinging()
        } catch {
            textView.string = error.localizedDescription
        }
    }

}

