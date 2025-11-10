use std::collections::HashSet;
use std::fs;
use anyhow::{Result, anyhow};

#[tokio::main]
async fn main() -> Result<()> {
    let blocklists = vec![
        ("AdGuard DNS filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
        ("AdAway Default Blocklist", "https://adaway.org/hosts.txt"),
        ("Phishing URL Blocklist (PhishTank and OpenPhish)", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt"),
        ("HaGeZi's Xiaomi Tracker Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt"),
        ("OISD Blocklist Big", "https://big.oisd.nl"),
        ("Malicious URL Blocklist (URLHaus)", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt"),
        ("Phishing Army", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt"),
        ("AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"),
        ("AdGuard DNS Popup Hosts filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt"),
        ("AWAvenue Ads Rule", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt"),
        ("Scam Blocklist by DurableNapkin", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt"),
        ("Dandelion Sprout's Anti-Malware List", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt"),
        ("uBlock₀ filters – Badware risks", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt"),
        ("Steven Black's List", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt"),
        ("Tv block ad", "https://raw.githubusercontent.com/hkamran80/blocklists/main/smart-tv.txt"),
        ("Hagezi multi pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"),
        ("HaGeZi's Apple Tracker DNS Blocklist", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/native.apple.txt"),
        ("HaGeZi's Windows/Office Tracker DNS Blocklist", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winoffice.txt"),
        ("The Block List Project - Ads List (adguard)", "https://blocklistproject.github.io/Lists/adguard/ads-ags.txt"),
        ("Adguard filter Portugal", "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_9_Spanish/filter.txt"),
        ("The Block List Project - Tracking List (adguard)", "https://blocklistproject.github.io/Lists/adguard/tracking-ags.txt"),
        ("chapeubranco / filtros trackers", "https://codeberg.org/chapeubranco/filtros/raw/branch/master/filtros/filtros-trackers.txt"),
        ("Lista Anti Nónio", "https://raw.githubusercontent.com/brunomiguel/antinonio/refs/heads/master/antinonio-adguard.txt"),
        // ("The Block List Project - Ads List (adguard)", "https://blocklistproject.github.io/Lists/adguard/ads-ags.txt"),
        ("The Block List Project - Scam List (adguard)", "https://blocklistproject.github.io/Lists/adguard/scam-ags.txt"),
        ("The Block List Project - Malware List (adguard)", "https://blocklistproject.github.io/Lists/adguard/malware-ags.txt"),
    ];

    let (all_lines, duplicates) = download_and_process_lists(&blocklists).await?;

    // Sort (HashSet iter is unordered; collect and sort for deterministic output)
    let mut sorted_lines: Vec<String> = all_lines.into_iter().collect();
    sorted_lines.sort();
    let combined = sorted_lines.join("\n");

    let output_path = "combined-adguard-list.txt";
    if std::path::Path::new(output_path).exists() {
        fs::remove_file(output_path)?;
    }

    fs::write(output_path, combined.as_bytes())?;
    println!("Combined deduplicated list written to {} with {} unique lines", output_path, sorted_lines.len());

    // Print duplicated entries
    if !duplicates.is_empty() {
        println!("\nDuplicated Entries:");
        for dup in duplicates {
            println!("{}", dup);
        }
    } else {
        println!("\nNo duplicated entries found.");
    }

    Ok(())
}

async fn download_and_process_lists(blocklists: &Vec<(&str, &str)>) -> Result<(HashSet<String>, Vec<String>)> {
    let mut all_lines = HashSet::new();
    let mut seen_lines = HashSet::new();
    let mut duplicates = HashSet::new();

    // Spawn concurrent tasks for all lists
    let futures: Vec<_> = blocklists.iter().map(|(name, url)| {
        let name_owned = name.to_string();  // Clone for move into task
        let url_owned = url.to_string();
        tokio::spawn(async move {
            download_list(&name_owned, &url_owned).await
        })
    }).collect();

    // Await all (parallel execution)
    for future in futures {
        match future.await {
            Ok(Ok((list_name, lines))) => {
                all_lines.insert(format!("Blocklist -> {}", list_name));
                for line in lines {
                    if !seen_lines.insert(line.clone()) {
                        duplicates.insert(line.clone());
                    }
                    all_lines.insert(line);
                }
                all_lines.insert("********************--************************".to_string());
            }
            Ok(Err(e)) => {
                eprintln!("Failed to process a list: {}", e);
            }
            Err(e) => {
                eprintln!("Task failed: {}", e);
            }
        }
    }
    let mut duplicates_vec: Vec<String> = duplicates.into_iter().collect();
    duplicates_vec.sort();
    Ok((all_lines, duplicates_vec))
}

async fn download_list(name: &str, url: &str) -> Result<(String, Vec<String>)> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow!("Invalid response for {}: {}", name, response.status()));
    }

    let content = response.text().await?;
    let lines: Vec<String> = content
        .lines()  // Efficient \n split
        .filter(|line| {
            let trimmed = line.trim();  // Whitespace/newline trim
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(|line| line.to_string())
        .collect();

    println!("Successfully downloaded {} lines from {}", lines.len(), url);
    Ok((name.to_string(), lines))
}