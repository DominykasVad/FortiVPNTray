import Testing
import FortiVPNShared

/// DNS suffixes pushed by the gateway (`http.c`: `Found dns suffix %s in xml config`).
/// openfortivpn prints the gateway's whole `domain=` value as one string, so a list
/// arrives in one line. Made-up names; the format is exactly what openfortivpn prints.
struct DNSSuffixTests {
    private func suffixes(_ lines: [String]) -> [String] {
        var parser = LogParser()
        for line in lines { _ = parser.consume(line) }
        return parser.dnsSuffixes
    }

    @Test func testSemicolonListInOneLine() {
        #expect(suffixes(["DEBUG:  Found dns suffix corp.example.com;example.lt in xml config"]) == ["corp.example.com", "example.lt"])
    }

    @Test func testWhitespaceAndEmptyPartsAroundSeparators() {
        #expect(suffixes(["DEBUG:  Found dns suffix corp.example.com; example.lt in xml config"]) == ["corp.example.com", "example.lt"])
        #expect(suffixes(["DEBUG:  Found dns suffix ;corp.example.com;;  example.lt ; in xml config"]) == ["corp.example.com", "example.lt"])
        #expect(suffixes(["DEBUG:  Found dns suffix corp.example.com example.lt in xml config"]) == ["corp.example.com", "example.lt"])
    }

    @Test func testInvalidPartsAreDroppedAndDuplicatesMerged() {
        #expect(suffixes(["DEBUG:  Found dns suffix corp.example.com;bad_name;-x.example;corp.example.com;example.lt in xml config",
                          "DEBUG:  Found dns suffix example.lt in xml config"]) == ["corp.example.com", "example.lt"])
    }

    @Test func testAtMostSixteen() {
        let many = (1...40).map { "d\($0).example.com" }.joined(separator: ";")
        let result = suffixes(["DEBUG:  Found dns suffix \(many) in xml config"])
        #expect(result == (1...16).map { "d\($0).example.com" })
    }

    @Test func testLineWithoutTheTrailer() {
        #expect(suffixes(["DEBUG:  Found dns suffix corp.example.com;example.lt"]) == ["corp.example.com", "example.lt"])
    }
}
