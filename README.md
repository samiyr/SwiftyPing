# SwiftyPing
ICMP ping client for Swift 5

### SwiftyPing is an easy-to-use, one file ICMP ping client
This project is based on SwiftPing: https://github.com/ankitthakur/SwiftPing.

### Usage
```swift

// Ping indefinitely
let pinger = try? SwiftyPing(host: "1.1.1.1", configuration: PingConfiguration(interval: 0.5, with: 5), queue: DispatchQueue.global())
pinger?.observer = { (response) in
    let duration = response.duration
    print(duration)
}
pinger?.startPinging()

// Ping once
let once = try? SwiftyPing(host: "1.1.1.1", configuration: PingConfiguration(interval: 0.5, with: 5), queue: DispatchQueue.global())
once?.observer = { (response) in
    let duration = response.duration
    print(duration)
}
once?.targetCount = 1
once?.startPinging()

```
### Installation
Just drop the SwiftyPing.swift file to your project.  Using SwiftyPing for a Mac application requires allowing Network->Incoming Connections and Network->Outgoing Connections in the application sandbox.

You can also use Swift Package Manager:

```swift
.Package(url: "https://github.com/samiyr/SwiftyPing.git", branch: "master")
```

### Future development and contributions
I made this project based on what I need, so I probably won't be adding any features unless I really need them. I will maintain it (meaning bug fixes and support for new Swift versions) for some time at least. However, you can submit a pull request and I'll take a look. Please try to keep the overall coding style.

### Caveats
This is low-level code, basically C code translated to Swift. This means that there are unsafe casts from raw bytes to Swift structs, for which Swift's usual type safety checks no longer apply. These can fail ungracefully (throwing an exception), and may even be used as an exploit (I'm not a security researcher and thus don't have the expertise to say for sure), so use with caution, especially if pinging untrusted hosts.

Also, while I think that the API is now stable, I don't make any guarantees – some new version might break old stuff.

### License
Use pretty much however you want. Officially licensed under MIT.
