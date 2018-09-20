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
        startPinging()
    }
    
    func startPinging() {
        let ping = SwiftyPing(host: "1.1.1.1", configuration: PingConfiguration(interval: 0.5), queue: DispatchQueue.global())
        ping?.observer = { (ping, response) in
            DispatchQueue.main.async {
                self.textView.text.append(contentsOf: "\nPing #\(response.sequenceNumber): \(response.duration * 1000) ms")
                self.textView.scrollRangeToVisible(NSRange(location: self.textView.text.count - 1, length: 1))
            }
        }
        ping?.start()
    }

}

