# SwiftyPing
ICMP ping client for Swift 4

### SwiftyPing is an easy-to-use, one file ICMP ping client
This project is based on SwiftPing: https://github.com/ankitthakur/SwiftPing. This is basically the same code base, but with some obvious bug fixes, safety improvements and overall more Swift-y. Unfortunately, it's still largely based on unsafe memory manipulation.

### Usage
```swift

// Ping indefinitely
let pinger = SwiftyPing(host: "1.1.1.1", configuration: PingConfiguration(interval: 0.5, with: 5), queue: DispatchQueue.global())
pinger?.observer = { (_, response) in
    let duration = response.duration
    print(duration)
}
pinger?.start()

// Ping once
let once = SwiftyPing(host: "1.1.1.1", configuration: PingConfiguration(interval: 0.5, with: 5), queue: DispatchQueue.global())
once?.observer = { (_, response) in
    let duration = response.duration
    print(duration)
    once?.stop()
}
once?.start()

```
### Installation
Just drop the SwiftyPing.swift file to your project.  Using SwiftyPing for a Mac application requires allowing Network->Incoming Connections and Network->Outgoing Connections in the application sandbox.

### Future development and contributions
I made this project based on what I need, so I probably won't be adding any features unless I really need them. I will maintain it (meaning bug fixes and support for new Swift versions) for some time at least. However, you can submit a pull request and I'll take a look. Please try to keep the overall coding style.

### License
Use pretty much however you want. Officially licensed under MIT.
