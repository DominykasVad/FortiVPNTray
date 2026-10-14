import Testing
import FortiVPNShared
@testable import FortiVPNHelper

struct SessionLogTests {
    private let id = "6F0E6A5C-8E4B-4C1E-9D7A-2B3C4D5E6F70"

    @Test func testLinesAreStoredRedactedAndReadFromAnOffset() {
        var log = SessionLog(sessionID: id)
        #expect(log.read(from: 0) == LogChunk(lines: [], nextOffset: 0))
        log.append(rawLine: "INFO:   Connected to gateway.")
        log.append(rawLine: "DEBUG:  Cookie: SVPNCOOKIE=4f1d0c9a8b7e6d5c")
        log.append(rawLine: "DEBUG:  Using SAML authentication URL /remote/saml/auth_id?id=0123456789abcdef")
        #expect(log.read(from: 0) == LogChunk(lines: [
            "INFO:   Connected to gateway.",
            "DEBUG:  Cookie: [redacted]",
            "DEBUG:  Using SAML authentication URL [redacted]",
        ], nextOffset: 3))
        #expect(log.read(from: 2) == LogChunk(lines: ["DEBUG:  Using SAML authentication URL [redacted]"], nextOffset: 3))
        #expect(log.read(from: 3) == LogChunk(lines: [], nextOffset: 3))
        // Past the end: nothing, and the offset to continue from.
        #expect(log.read(from: 99) == LogChunk(lines: [], nextOffset: 3))
    }

    @Test func testOldestLinesAreDroppedPastTheLineLimit() {
        var log = SessionLog(sessionID: id)
        let total = SessionLog.maxLines * 3 + 7
        for number in 0..<total { log.append(rawLine: "line \(number)") }
        #expect(log.firstOffset == total - SessionLog.maxLines)
        #expect(log.endOffset == total)
        // A dropped offset continues at the oldest line kept.
        let chunk = log.read(from: 0)
        #expect(chunk.lines.first == "line \(total - SessionLog.maxLines)")
        #expect(chunk.lines.count == SessionLog.maxLines && chunk.nextOffset == total)
        #expect(log.read(from: total - 1) == LogChunk(lines: ["line \(total - 1)"], nextOffset: total))
    }

    @Test func testOldestLinesAreDroppedPastTheByteLimit() {
        var log = SessionLog(sessionID: id)
        let long = String(repeating: "x", count: 8192)
        for _ in 0..<(SessionLog.maxBytes / 8192 + 10) { log.append(rawLine: long) }
        #expect(log.firstOffset == 10)
        var kept = 0
        var offset = 0
        while offset < log.endOffset {
            let chunk = log.read(from: offset)
            kept += chunk.lines.reduce(0) { $0 + $1.utf8.count }
            offset = chunk.nextOffset
        }
        #expect(kept <= SessionLog.maxBytes)
    }

    @Test func testAChunkIsBoundedAndReadingContinues() {
        var log = SessionLog(sessionID: id)
        let long = String(repeating: "y", count: 8000)
        for _ in 0..<100 { log.append(rawLine: long) }
        let first = log.read(from: 0)
        #expect(first.lines.count == SessionLog.maxChunkBytes / 8000)
        let second = log.read(from: first.nextOffset)
        #expect(second.nextOffset == first.nextOffset + second.lines.count)
        // A line larger than a chunk is still returned on its own.
        var huge = SessionLog(sessionID: id)
        huge.append(rawLine: String(repeating: "z", count: SessionLog.maxChunkBytes + 1))
        #expect(huge.read(from: 0).lines.count == 1)
    }
}
