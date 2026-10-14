import Foundation
import FortiVPNShared

/// One session's output, redacted before it is stored, in memory only (PLAN.md 2.4).
///
/// Offsets count lines from the start of the session. When the buffer is full the
/// oldest lines are dropped; a read from an offset that was dropped continues at
/// the oldest line still kept.
struct SessionLog {
    static let maxLines = 5000
    static let maxBytes = 1 << 20
    /// The most a single `read` returns, so a reply stays small.
    static let maxChunkBytes = 256 << 10

    let sessionID: String
    private var lines: [String] = []
    /// Index in `lines` of the oldest line kept; the ones before it are dropped.
    private var head = 0
    private var bytes = 0
    /// Offset of `lines[head]`.
    private(set) var firstOffset = 0

    init(sessionID: String) {
        self.sessionID = sessionID
    }

    /// Offset the next appended line gets.
    var endOffset: Int { firstOffset + lines.count - head }

    /// Redacts `rawLine` and keeps it. The raw text is never stored.
    mutating func append(rawLine: String) {
        let line = LogParser.redacted(rawLine)
        lines.append(line)
        bytes += line.utf8.count
        while lines.count - head > Self.maxLines || (bytes > Self.maxBytes && lines.count - head > 1) {
            bytes -= lines[head].utf8.count
            lines[head] = ""
            head += 1
            firstOffset += 1
        }
        if head > Self.maxLines {
            lines.removeFirst(head)
            head = 0
        }
    }

    /// Lines from `offset` on, at most `maxChunkBytes` of them (always at least one
    /// if there is one). An offset past the end reads nothing and points at the end.
    func read(from offset: Int) -> LogChunk {
        var index = min(max(offset, firstOffset), endOffset)
        var chunk: [String] = []
        var size = 0
        while index < endOffset {
            let line = lines[head + index - firstOffset]
            size += line.utf8.count
            if size > Self.maxChunkBytes && !chunk.isEmpty { break }
            chunk.append(line)
            index += 1
        }
        return LogChunk(lines: chunk, nextOffset: index)
    }
}
