import Foundation

private enum ListBuilder {
    struct List {
        let name: String
        let url: String
    }

    private enum Constants {
        static let blocklists: [List] = [
            List(name: "AdGuard DNS filter", url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
            List(name: "AdAway Default Blocklist", url: "https://adaway.org/hosts.txt"),
            List(name: "Phishing URL Blocklist (PhishTank and OpenPhish)", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt"),
            List(name: "HaGeZi's Xiaomi Tracker Blocklist", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt"),
            List(name: "OISD Blocklist Big", url: "https://big.oisd.nl"),
            List(name: "Malicious URL Blocklist (URLHaus)", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt"),
            List(name: "Phishing Army", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt"),
            List(name: "AdGuard DNS filter", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"),
            List(name: "AdGuard DNS Popup Hosts filter", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt"),
            List(name: "AWAvenue Ads Rule", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt"),
            List(name: "Scam Blocklist by DurableNapkin", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt"),
            List(name: "Dandelion Sprout's Anti-Malware List", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt"),
            List(name: "uBlock₀ filters – Badware risks", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt"),
            List(name: "Steven Black's List", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt"),
            List(name: "Tv block ad", url: "https://raw.githubusercontent.com/hkamran80/blocklists/main/smart-tv.txt"),
            List(name: "Hagezi multi pro", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"),
            List(name: "HaGeZi's Apple Tracker DNS Blocklist", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.apple.txt"),
            List(name: "HaGeZi's Windows/Office Tracker DNS Blocklist", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winoffice.txt"),
            List(name: "The Block List Project - Ads List (adguard)", url: "https://blocklistproject.github.io/Lists/adguard/ads-ags.txt"),
            List(name: "Adguard filter Portugal", url: "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_9_Spanish/filter.txt"),
            List(name: "The Block List Project - Tracking List (adguard)", url: "https://blocklistproject.github.io/Lists/adguard/tracking-ags.txt"),
            List(name: "chapeubranco / filtros trackers", url: "https://codeberg.org/chapeubranco/filtros/raw/branch/master/filtros/filtros-trackers.txt"),
            List(name: "Lista Anti Nónio", url: "https://raw.githubusercontent.com/brunomiguel/antinonio/refs/heads/master/antinonio-adguard.txt")
        ]
        static let outputPath = "combined-adguard-list.txt"
    }

    private static func downloadList(from urlString: String) async -> [String] {
        guard let url = URL(string: urlString) else {
            print("Invalid URL: \(urlString)")
            return []
        }

        // Linux-compatible: Create a new URLSession (no .shared on Linux Foundation)
        let config = URLSessionConfiguration.default
        let session = URLSession(configuration: config)

        do {
            let (data, response) = try await session.data(from: url)

            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                print("Invalid response for \(urlString): \(response)")
                return []
            }

            // Decode as UTF-8 string
            guard let content = String(data: data, encoding: .utf8) else {
                print("Failed to decode UTF-8 for \(urlString)")
                return []
            }

            // Process lines: Split by "\n" (Linux-compatible), trim empty, filter comments
            let lines = content
                .components(separatedBy: "\n")
                .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !$0.hasPrefix("#") }

            print("Successfully downloaded \(lines.count) lines from \(urlString)")
            return lines
        } catch {
            print("Failed to download \(urlString): \(error)")
            return []
        }
    }

    static func buildList() async throws {
        var allLines = Set<String>()

        try await withThrowingTaskGroup(of: [String].self) { group in
            for list in Constants.blocklists {
                group.addTask {
                    await downloadList(from: list.url)
                }
            }

            for try await lines in group {
                allLines.insert("********************--************************")
                for line in lines {
                    allLines.insert(line)
                }
                allLines.insert("********************--************************")
            }
        }

        // Sort and combine (synchronous after awaits)
        let sortedLines = allLines.sorted()
        let combinedList = sortedLines.joined(separator: "\n")

        // Clear existing file if present (avoids appends)
        if FileManager.default.fileExists(atPath: Constants.outputPath) {
            try? FileManager.default.removeItem(atPath: Constants.outputPath)
        }

        // Write to file (synchronous, as it's I/O after network)
        try combinedList.write(toFile: Constants.outputPath, atomically: true, encoding: .utf8)
        print("Combined deduplicated list written to \(Constants.outputPath) with \(sortedLines.count) unique lines")
    }
}

// Single execution: Use DispatchGroup to block until complete (no duplicates)
let dispatchGroup = DispatchGroup()
dispatchGroup.enter()
Task {
    defer { dispatchGroup.leave() }
    do {
        try await ListBuilder.buildList()
        print("All tasks completed successfully.")
    } catch {
        print("Build failed: \(error)")
    }
}
dispatchGroup.wait()  // Blocks main thread until done
