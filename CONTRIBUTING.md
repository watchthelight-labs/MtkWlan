# Contributing

The most useful thing right now is a report from another machine with an MT7925, and a report from anyone who joins a WPA2 network with it. Open an issue with the laptop model, the macOS build, the OpenCore version, the kext version, `mtkwifi status --json`, and `ioreg -r -c MtkWlan -l -w0` (it holds counters, never keys).

Pull requests: keep them small and say how you tested them, on which network type. I read and test every PR before merging. AI-assisted PRs are fine as long as you can explain the change, which is the same bar I hold my own code to.

Code style: the kernel parts follow Linux mt76 naming where they port it, and Apple's IOKit conventions elsewhere. Anything ported from mt76 or itlmt7925 names the function it came from in a comment, and `NOTICE.md` lists it per file. Keep it that way.
