use anyhow::{Context, Result, anyhow, bail};
use owo_colors::OwoColorize;
use socks5_impl::protocol::WireAddress;
use tracing::warn;
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    process::exit,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tun2socks5::{ArgProxy, ProxyType};

use crate::{ClashOps, RemoteOps, UplinkCommand, UplinkInstanceCommand, state_paths};

pub fn load_saved_uplink_hub() -> Result<crate::uplink::UplinkHub> {
    let mut hub = crate::uplink::UplinkHub::new();
    let count = hub.load_saved_proxies()?;
    hub.load_stats()?;

    if count == 0 {
        warn!(
            "No saved proxies found. Import Clash config first with 'sp uplink clash config-add'."
        );
    }

    Ok(hub)
}

pub fn cmd_uplink(kind: UplinkCommand) -> Result<()> {
    match kind {
        UplinkCommand::Clash { cmd } => cmd_clash(cmd),
        UplinkCommand::Geph => bail!("Geph uplink not yet implemented"),
        UplinkCommand::Instance { name, cmd } => cmd_instance(name, cmd),
        UplinkCommand::Remote { cmd } => cmd_remote(cmd),
        UplinkCommand::Stats => cmd_stats(),
        UplinkCommand::Export { path } => cmd_export(path),
        UplinkCommand::Import { path } => cmd_import(path),
        UplinkCommand::DnsBackup { path } => cmd_dns_backup(path),
        UplinkCommand::DnsImport { path } => cmd_dns_import(path),
    }
}

fn cmd_stats() -> Result<()> {
    use crate::state_blueprint::PersistentState;
    use crate::uplink::UplinkStatsState;

    let mut hub = crate::uplink::UplinkHub::new();
    hub.hydrate_from_persisted()
        .context("Failed to load persisted proxies")?;
    hub.load_stats().context("Failed to load persisted stats")?;

    let stats_state = UplinkStatsState::load_or_default().context("Failed to load stats.json")?;

    // Collect all proxies; tag whether they have recorded stats for sort ordering.
    let mut rows: Vec<(bool, String, String, String, String)> = hub
        .all_proxies()
        .iter()
        .map(|(id, proxy)| {
            let nym = id.nym().to_string();
            let proxy_display = proxy.to_string();
            let (has_stats, latency_s, conn_s) = if let Some(s) = stats_state.stats.get(id) {
                let h = s.past_hour();
                let lat = h
                    .avg_latency_ms()
                    .map(|ms| format!("{:.0}ms", ms))
                    .unwrap_or_else(|| "-".to_string());
                let conn = match h.success_rate() {
                    Some(p) if p >= 0.5 => format!("{:.0}%", p * 100.0).green().to_string(),
                    Some(p) => format!("{:.0}%", p * 100.0).red().to_string(),
                    None => "?".dimmed().to_string(),
                };
                (true, lat, conn)
            } else {
                (false, "-".to_string(), "?".dimmed().to_string())
            };
            (has_stats, nym, proxy_display, latency_s, conn_s)
        })
        .collect();

    // Proxies with stats first; within each group sort by nym.
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    let total = rows.len();
    let shown = rows.len().min(10);

    println!(
        "{}",
        format!(
            "Uplink proxy stats ({} total, showing first {}):",
            total, shown
        )
        .bold()
    );
    println!(
        "  {:<8}  {:<40}  {:<10}  {}",
        "nym".bold(),
        "proxy".bold(),
        "latency".bold(),
        "conn".bold(),
    );
    println!("  {}", "-".repeat(70));

    for (_, nym, proxy_display, latency_s, conn_s) in rows.into_iter().take(10) {
        println!(
            "  {:<8}  {:<40}  {:<10}  {}",
            nym.cyan(),
            proxy_display,
            latency_s,
            conn_s,
        );
    }

    if total > 10 {
        println!("  ... and {} more", total - 10);
    }

    Ok(())
}

fn cmd_clash(cmd: ClashOps) -> Result<()> {
    match cmd {
        ClashOps::ConfigAdd { group_id, path } => clash_config_add(group_id, path),
        ClashOps::List => clash_list(),
        ClashOps::ConfigExplain { path } => clash_config_explain(path),
        ClashOps::Resolve {
            direct,
            refresh,
            backup,
        } => clash_resolve(direct, refresh, backup),
        ClashOps::TestResolve { direct, query } => clash_test_resolve(direct, query),
    }
}

fn clash_config_add(group_id: String, path: std::path::PathBuf) -> Result<()> {
    println!("Importing Clash profile");
    println!("  Group: {}", group_id);
    println!("  Config: {:?}", path);

    let mut hub = crate::uplink::UplinkHub::new();
    let _ = hub.hydrate_from_persisted()?;
    let mut clash_state = hub.load_clash_state()?.clone();

    let clash_profile = crate::uplink::clash::ClashProfile::load_file(&path)?;

    let append_report = clash_state.append_profile_to_group(
        &clash_profile,
        crate::uplink::clash::GroupId::from(group_id),
    )?;
    hub.set_clash_state(clash_state)?;

    println!("\n✓ Profile imported");
    println!(
        "  Tier1 nameservers: {}",
        clash_profile.tier1_nameservers.len()
    );
    println!(
        "  Tier2 nameservers: {}",
        clash_profile.tier2_nameservers.len()
    );
    println!("  Proxy servers: {}", clash_profile.proxy_domains.len());
    println!(
        "  Appended tier1 nameservers: {}",
        append_report.added_tier1_nameservers
    );
    println!(
        "  Appended tier2 nameservers: {}",
        append_report.added_tier2_nameservers
    );
    println!(
        "  Appended trojan proxies: {}",
        append_report.added_trojan_proxies
    );

    Ok(())
}

fn clash_list() -> Result<()> {
    let state = crate::uplink::clash::ClashState::load_or_default()?;
    if state.groups.is_empty() {
        println!("No Clash groups found");
        return Ok(());
    }

    println!("Clash Groups: {}", state.groups.len());
    println!("Tracked proxy domains: {}", state.domain_group.len());
    println!("Tracked trojan proxies: {}", state.trojan_proxies.len());

    let mut hub = crate::uplink::UplinkHub::new();
    match hub.load_clash_proxies() {
        Ok(count) => {
            println!("  Loaded {} proxy entries from clash state", count);
            let max_show = 15usize;
            println!("  Proxy nyms (first {}):", max_show);
            for (i, (id, proxy)) in hub.all_proxies().iter().take(max_show).enumerate() {
                if let Some(nym) = hub.get_nym(id) {
                    if let Some(stats) = hub.get_link_stats(id) {
                        println!("    {} => {} => {} ({})", i + 1, nym, proxy, stats);
                    } else {
                        println!("    {} => {} => {}", i + 1, nym, proxy);
                    }
                }
            }
        }
        Err(e) => {
            println!("  Warning: failed to load proxies: {}", e);
        }
    }

    Ok(())
}

fn clash_resolve(direct: bool, refresh: bool, backup: Option<std::path::PathBuf>) -> Result<()> {
    use crate::uplink::clash::GroupId;

    println!("Resolving Clash groups and updating resolved state...");

    let state = crate::uplink::clash::ClashState::load_or_default()?;
    if state.groups.is_empty() {
        println!("No Clash groups found");
        return Ok(());
    }

    let group_ids: Vec<GroupId> = state.groups.keys().cloned().collect();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let interrupted = rt.block_on(async {
        let mut hub = crate::uplink::UplinkHub::new();
        let initial_proxy_count = hub.hydrate_from_persisted()?;
        println!(
            "Hydrated uplink state ({} proxies available)",
            initial_proxy_count
        );

        let mut state = hub.load_clash_state()?.clone();

        let backup_only = if let Some(backup_path) = &backup {
            let json = std::fs::read_to_string(backup_path)
                .with_context(|| format!("Failed to read DNS backup from {:?}", backup_path))?;
            let dns_backup: crate::uplink::backup::UplinkBackup = serde_json::from_str(&json)
                .context("Failed to parse DNS backup JSON")?;
            dns_backup.merge_into_clash_state(&mut state);
            println!(
                "Preloaded DNS backup from {:?} (domains={})",
                backup_path,
                dns_backup.dns.len()
            );
            println!("Backup-only mode: skipping DNS resolver calls");
            true
        } else {
            false
        };

        let mut interrupted = false;

        if !backup_only {
            let cancel_flag = Arc::new(AtomicBool::new(false));
            let cancel_task_flag = Arc::clone(&cancel_flag);
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    cancel_task_flag.store(true, Ordering::SeqCst);
                }
            });

            for group_id in group_ids {
                if cancel_flag.load(Ordering::Relaxed) {
                    println!("\\nInterrupt received (Ctrl+C). Saving current resolved state...");
                    interrupted = true;
                    break;
                }

                let unresolved_before = state
                    .domain_group
                    .iter()
                    .filter(|(domain, gid)| gid == &&group_id && state.get_latest_proxy_ips(domain.as_str()).is_none())
                    .count();

                println!(
                    "Resolving group: {} (unresolved proxy domains before resolve: {})",
                    group_id.as_str(),
                    unresolved_before
                );

                match state
                    .resolve_group(
                        &group_id,
                        Some(&hub),
                        Some(cancel_flag.as_ref()),
                        direct,
                        refresh,
                    )
                    .await
                {
                    Ok(report) => {
                        println!("  resolved_domains={}", report.solved.domains.len());
                        println!(
                            "  metrics cache_hits={} proxied_tier2={} proxied_tier1={} direct_tier2={} direct_tier1={} unresolved={}",
                            report.metrics.cache_hits,
                            report.metrics.resolved_proxy_tier2,
                            report.metrics.resolved_proxy_tier1,
                            report.metrics.resolved_direct_tier2,
                            report.metrics.resolved_direct_tier1,
                            report.metrics.unresolved
                        );
                    }
                    Err(e) => {
                        println!("  Failed to resolve group {}: {}", group_id.as_str(), e);
                    }
                }

                if cancel_flag.load(Ordering::Relaxed) {
                    println!("\\nInterrupt received (Ctrl+C). Saving current resolved state...");
                    interrupted = true;
                    break;
                }
            }
        }

        state.remove_private_ips();

        hub.set_clash_state(state)?;

        if interrupted {
            println!("Saved partial resolved state. Exiting due to interrupt.");
            return Ok::<bool, anyhow::Error>(true);
        }

        let mut hub = crate::uplink::UplinkHub::new();
        let count = hub.hydrate_from_persisted()?;
        println!("Loaded {} proxies from resolved profiles", count);

        Ok::<bool, anyhow::Error>(false)
    })?;

    if interrupted {
        exit(130);
    }

    Ok(())
}

fn clash_test_resolve(direct: bool, query: String) -> Result<()> {
    println!("Testing single domain resolution: {}", query);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let mut hub = crate::uplink::UplinkHub::new();
        let proxy_count = hub.hydrate_from_persisted()?;
        println!("Hydrated uplink state ({} proxies available)", proxy_count);

        let state = hub.load_clash_state()?.clone();
        let report = state
            .resolve_one_domain_no_store(&query, Some(&hub), None, direct)
            .await?;

        if let Some(ips) = report.solved.get_latest_ips(&query) {
            let ips_joined = ips
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "resolved domain={} ip_count={} ips={}",
                query,
                ips.len(),
                ips_joined
            );
        } else {
            println!("resolved domain={} ip_count=0 ips=", query);
        }

        println!(
            "metrics cache_hits={} proxied_tier2={} proxied_tier1={} direct_tier2={} direct_tier1={} unresolved={}",
            report.metrics.cache_hits,
            report.metrics.resolved_proxy_tier2,
            report.metrics.resolved_proxy_tier1,
            report.metrics.resolved_direct_tier2,
            report.metrics.resolved_direct_tier1,
            report.metrics.unresolved
        );

        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

fn clash_config_explain(path: std::path::PathBuf) -> Result<()> {
    use clash_config::Config;

    println!("{}", "Clash Profile Analysis".bold().bright_cyan());
    println!();
    println!("  {}: {}", "Config".dimmed(), path.display());
    println!();

    if !path.exists() {
        bail!("Config file does not exist: {:?}", path);
    }

    let config = Config::try_from(path.clone()).context("Failed to parse Clash YAML config")?;

    println!("{}", "Two-Tier DNS".bold());
    println!();
    println!(
        "  {} {} {} {}",
        "Bootstrap".cyan().bold(),
        "->".dimmed(),
        "Main".cyan().bold(),
        "->".dimmed()
    );
    println!(
        "  {} resolves {} resolves {}",
        "IP nameservers".dimmed(),
        "main tier".dimmed(),
        "proxy domains".dimmed()
    );
    println!();

    let max_show = 3;
    println!(
        "  {} ({} total)",
        "Bootstrap Tier".cyan(),
        config.dns.default_nameserver.len()
    );
    for ns in config.dns.default_nameserver.iter().take(max_show) {
        println!("    {}", ns);
    }
    if config.dns.default_nameserver.len() > max_show {
        println!(
            "    {} ...",
            format!("+{} more", config.dns.default_nameserver.len() - max_show).dimmed()
        );
    }

    println!();
    println!(
        "  {} ({} total)",
        "Main Tier".cyan(),
        config.dns.nameserver.len()
    );
    for ns in config.dns.nameserver.iter().take(max_show) {
        println!("    {}", ns);
    }
    if config.dns.nameserver.len() > max_show {
        println!(
            "    {} ...",
            format!("+{} more", config.dns.nameserver.len() - max_show).dimmed()
        );
    }

    let proxies = config
        .proxy
        .as_ref()
        .context("No proxies found in Clash config")?;

    let mut trojan_count = 0;
    let mut other_count = 0;
    let mut proxy_domains: HashSet<String> = HashSet::new();

    for proxy in proxies {
        let proxy_type = proxy
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if proxy_type == "trojan" {
            trojan_count += 1;
            if let Some(server) = proxy.get("server").and_then(|v| v.as_str()) {
                proxy_domains.insert(server.to_string());
            }
        } else {
            other_count += 1;
        }
    }

    println!();
    println!("{}", "Proxies".bold());
    println!();
    println!("  {}  {}", "Total".dimmed(), proxies.len());
    println!(
        "  {}  {}",
        "Proxy Domains (unique)".dimmed(),
        proxy_domains.len()
    );
    if trojan_count > 0 {
        println!(
            "  {}  {} {}",
            "Trojan".dimmed(),
            trojan_count,
            "(supported)".green()
        );
    } else {
        println!(
            "  {}  {} {}",
            "Trojan".dimmed(),
            trojan_count,
            "(none found)".yellow()
        );
    }
    if other_count > 0 {
        println!(
            "  {}  {} {}",
            "Other".dimmed(),
            other_count,
            "(not supported)".yellow()
        );
    }

    println!();
    println!("{}", "Validation".bold());
    println!();
    let mut valid = true;

    if config.dns.default_nameserver.is_empty() {
        println!("  {} No bootstrap nameservers", "[x]".red().bold());
        valid = false;
    } else {
        let mut all_valid = true;
        for ns in &config.dns.default_nameserver {
            let valid_entry = url::Url::parse(ns).is_ok()
                || ns.parse::<std::net::SocketAddr>().is_ok()
                || ns.parse::<std::net::IpAddr>().is_ok()
                || url::Host::parse(ns).is_ok();

            if !valid_entry {
                println!(
                    "  {} Invalid bootstrap nameserver entry: {}",
                    "[!]".yellow().bold(),
                    ns
                );
                all_valid = false;
            }
        }
        if all_valid {
            println!(
                "  {} Bootstrap nameservers are valid endpoint entries",
                "[✓]".green().bold()
            );
        } else {
            valid = false;
        }
    }

    if trojan_count == 0 {
        println!(
            "  {} No Trojan proxies (only type supported)",
            "[!]".yellow().bold()
        );
        valid = false;
    } else {
        println!(
            "  {} Trojan proxies ({})",
            "[✓]".green().bold(),
            trojan_count
        );
    }

    println!();
    if valid {
        println!("  {} {}", "Status:".bold(), "VALID".green());
    } else {
        println!("  {} {}", "Status:".bold(), "ERRORS".red());
    }
    println!();

    Ok(())
}

fn cmd_remote(cmd: RemoteOps) -> Result<()> {
    match cmd {
        RemoteOps::Add { url } => {
            let proxy = ArgProxy::from_url(&url)?;
            let mut state = crate::uplink::RemoteProxyState::load_or_default()?;

            if state.add_proxy(proxy.clone()) {
                state.save_atomic()?;
                println!("Added remote proxy: {}://{}", proxy.proxy_type, proxy.addr);
            } else {
                println!("Remote proxy already exists: {}", proxy.addr);
            }
        }
        RemoteOps::Remove { nym } => {
            let mut state = crate::uplink::RemoteProxyState::load_or_default()?;
            if state.remove_proxy(&nym) {
                state.save_atomic()?;
                println!("Removed remote proxy: {}", nym);
            } else {
                println!("Remote proxy not found: {}", nym);
            }
        }
        RemoteOps::List => {
            let state = crate::uplink::RemoteProxyState::load_or_default()?;
            if state.proxies.is_empty() {
                println!("No remote proxies saved");
            } else {
                println!("Remote proxies:");
                for (index, proxy) in state.proxies.iter().enumerate() {
                    let id = nsproxy_common::routing::ProxyID::for_remote(proxy.addr);
                    println!(
                        "  {}. {}://{} (nym: {})",
                        index + 1,
                        proxy.proxy_type,
                        proxy.addr,
                        id.nym()
                    );
                }
            }
        }
    }

    Ok(())
}

fn cmd_instance(name: nsproxy_common::routing::ProxyNym, cmd: UplinkInstanceCommand) -> Result<()> {
    match cmd {
        UplinkInstanceCommand::Test => cmd_instance_test(name),
    }
}

fn cmd_instance_test(name: nsproxy_common::routing::ProxyNym) -> Result<()> {
    println!("{}", "Proxy Instance Test".bold().bright_cyan());
    println!();
    println!("  Instance: {}", name.to_string().cyan());
    println!();

    let mut hub = load_saved_uplink_hub()?;

    println!("Loaded {} proxies", hub.all_proxies().len());
    println!();

    let proxy_id = hub
        .nym_map
        .get(&name)
        .cloned()
        .ok_or_else(|| anyhow!("Proxy with nym '{}' not found", name))?;

    let proxy = hub
        .proxies
        .get(&proxy_id)
        .ok_or_else(|| anyhow!("Proxy with id '{}' not found", proxy_id))?
        .clone();

    println!("Found proxy: {:?}", &proxy_id);
    println!();

    match proxy {
        crate::uplink::UplinkProxy::Trojan(trojan) => {
            run_trojan_tests(&trojan, &mut hub, &proxy_id)
        }
        crate::uplink::UplinkProxy::Remote(remote) => run_remote_tests(remote),
        _ => Ok(()),
    }?;

    hub.save_stats()?;

    Ok(())
}

fn run_trojan_tests(
    trojan: &crate::uplink::clash::TrojanProxy,
    hub: &mut crate::uplink::UplinkHub,
    proxy_id: &nsproxy_common::routing::ProxyID,
) -> Result<()> {
    println!("{}", "Trojan Proxy Tests".bold());
    println!("  Server: {}", trojan.server_name);
    println!("  Port: {}", trojan.server_addr.port());
    println!();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let state = crate::uplink::clash::ClashState::load_or_default()?;
        let server_ip = state
            .get_latest_proxy_ips(&trojan.server_name)
            .and_then(|ips| ips.iter().next().copied())
            .ok_or_else(|| anyhow!("No resolved IP for {}", trojan.server_name))?;

        println!("{}  Testing TCP connectivity...", "[•]".cyan());
        match trojan
            .connect_tcp(server_ip, WireAddress::from(("ip.me", 80u16)))
            .await
        {
            Ok(crate::uplink::clash::TrojanConnection::TcpConnect(mut stream, _)) => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                let request = "GET / HTTP/1.1\r\nHost: ip.me\r\nConnection: close\r\n\r\n";

                // measure start before sending request; we'll treat first successful read as TTFB
                let start = std::time::Instant::now();

                if let Err(e) = stream.write_all(request.as_bytes()).await {
                    println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
                    // record failure in hub
                    hub.update_link_conn_check(proxy_id, false);
                } else {
                    // attempt first read (treat as TTFB)
                    let mut first_buf = vec![0u8; 2048];
                    match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut first_buf))
                        .await
                    {
                        Ok(Ok(n)) => {
                            if n == 0 {
                                println!("{}  TCP test failed: remote closed", "[✗]".red().bold());
                                hub.update_link_conn_check(proxy_id, false);
                            } else {
                                let latency = start.elapsed();
                                hub.update_link_ttfb(proxy_id, latency);
                                hub.update_link_conn_check(proxy_id, true);

                                // build response string from first chunk then read rest
                                let mut response =
                                    String::from_utf8_lossy(&first_buf[..n]).to_string();
                                match tokio::time::timeout(
                                    Duration::from_secs(10),
                                    stream.read_to_string(&mut response),
                                )
                                .await
                                {
                                    Ok(Ok(_)) => {
                                        println!(
                                            "    Raw TCP response ({} bytes):",
                                            response.len()
                                        );
                                        for line in response.lines() {
                                            println!("      {}", line);
                                        }

                                        if response.contains("200 OK") || !response.is_empty() {
                                            println!(
                                                "{}  TCP test passed (ip.me responded)",
                                                "[✓]".green().bold()
                                            );
                                        } else {
                                            println!(
                                                "{}  TCP test failed: invalid response",
                                                "[✗]".red().bold()
                                            );
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
                                        hub.update_link_conn_check(proxy_id, false);
                                    }
                                    Err(_) => {
                                        println!(
                                            "{}  TCP test failed: timeout",
                                            "[✗]".red().bold()
                                        );
                                        hub.update_link_conn_check(proxy_id, false);
                                    }
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
                            hub.update_link_conn_check(proxy_id, false);
                        }
                        Err(_) => {
                            println!("{}  TCP test failed: timeout", "[✗]".red().bold());
                            hub.update_link_conn_check(proxy_id, false);
                        }
                    }
                }
            }
            Ok(_) => {
                println!(
                    "{}  TCP test failed: wrong connection type",
                    "[✗]".red().bold()
                );
            }
            Err(e) => {
                println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
            }
        }

        println!("{}  Testing UDP connectivity...", "[•]".cyan());
        match crate::uplink::proxy_adapters::TrojanAdapter::connect_udp(
            trojan,
            WireAddress::from(("1.1.1.1", 53u16)),
            trojan.server_addr.ip(),
        )
        .await
        {
            Ok(crate::uplink::proxy_adapters::ProxyConnection::Udp(mut tunnel)) => {
                let dns_server =
                    WireAddress::SocketAddress(SocketAddr::new("1.1.1.1".parse::<IpAddr>()?, 53));
                match crate::uplink::proxy_dns::query_via_udp(
                    tunnel.as_mut(),
                    &dns_server,
                    "ip.me",
                    Duration::from_secs(5),
                )
                .await
                {
                    Ok(ips) => {
                        println!(
                            "{}  UDP test passed (resolved): {:?}",
                            "[✓]".green().bold(),
                            ips
                        );
                    }
                    Err(e) => {
                        println!("{}  UDP test failed: {}", "[✗]".red().bold(), e);
                    }
                }
            }
            Ok(_) => {
                println!(
                    "{}  UDP test failed: wrong connection type",
                    "[✗]".red().bold()
                );
            }
            Err(e) => {
                println!("{}  UDP test failed: {}", "[✗]".red().bold(), e);
            }
        }

        println!();
        println!("{}", "Test complete".bold());
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

fn run_remote_tests(remote: ArgProxy) -> Result<()> {
    println!("{}", "Remote Proxy Tests".bold());
    println!("  Type: {}", remote.proxy_type);
    println!("  Addr: {}", remote.addr);
    println!();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        match remote.proxy_type {
            ProxyType::Socks5 => run_remote_socks5_tests(&remote).await,
            ProxyType::Socks4 | ProxyType::Http => Ok(()),
        }
    })?;

    println!();
    println!("{}", "Test complete".bold());
    Ok(())
}

async fn run_remote_socks5_tests(remote: &ArgProxy) -> Result<()> {
    test_remote_socks5_tcp(remote).await;
    test_remote_socks5_udp(remote).await;
    Ok(())
}

async fn test_remote_socks5_tcp(remote: &ArgProxy) {
    use crate::uplink::proxy_adapters::{ProxyConnection, RemoteAdapter};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    println!("{}  Testing TCP connectivity...", "[•]".cyan());
    match RemoteAdapter::connect_tcp(remote, WireAddress::from(("ip.me", 80u16))).await {
        Ok(ProxyConnection::Tcp(mut stream)) => {
            println!("  TCP connected");
            let request = "GET / HTTP/1.1\r\nHost: ip.me\r\nConnection: close\r\n\r\n";
            if let Err(e) = stream.write_all(request.as_bytes()).await {
                println!("{}  TCP test failed: {:?}", "[✗]".red().bold(), e);
                return;
            }

            let mut response = String::new();
            match tokio::time::timeout(
                Duration::from_secs(10),
                stream.read_to_string(&mut response),
            )
            .await
            {
                Ok(Ok(_)) => {
                    if response.contains("200 OK") || !response.is_empty() {
                        println!("{}", response);
                        println!(
                            "{}  TCP test passed (ip.me responded)",
                            "[✓]".green().bold()
                        );
                    } else {
                        println!("{}  TCP test failed: invalid response", "[✗]".red().bold());
                    }
                }
                Ok(Err(e)) => {
                    println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
                }
                Err(_) => {
                    println!("{}  TCP test failed: timeout", "[✗]".red().bold());
                }
            }
        }
        Ok(_) => {
            println!(
                "{}  TCP test failed: wrong connection type",
                "[✗]".red().bold()
            );
        }
        Err(e) => {
            println!("{}  TCP test failed: {}", "[✗]".red().bold(), e);
        }
    }
}

async fn test_remote_socks5_udp(remote: &ArgProxy) {
    use crate::uplink::proxy_adapters::{ProxyConnection, RemoteAdapter};

    println!("{}  Testing UDP connectivity...", "[•]".cyan());
    match RemoteAdapter::connect_udp(remote).await {
        Ok(ProxyConnection::Udp(mut tunnel)) => {
            let dns_server =
                WireAddress::SocketAddress(SocketAddr::new("1.1.1.1".parse().unwrap(), 53));

            match crate::uplink::proxy_dns::query_via_udp(
                tunnel.as_mut(),
                &dns_server,
                "ip.me",
                Duration::from_secs(5),
            )
            .await
            {
                Ok(ips) => {
                    println!(
                        "{}  UDP test passed (resolved): {:?}",
                        "[✓]".green().bold(),
                        ips
                    );
                }
                Err(e) => {
                    println!("{}  UDP test failed: {}", "[✗]".red().bold(), e);
                }
            }
        }
        Ok(_) => {
            println!(
                "{}  UDP test failed: wrong connection type",
                "[✗]".red().bold()
            );
        }
        Err(e) => {
            println!("{}  UDP test failed: {}", "[✗]".red().bold(), e);
        }
    }
}

fn cmd_export(path: std::path::PathBuf) -> Result<()> {
    let mut hub = crate::uplink::UplinkHub::new();
    hub.hydrate_from_persisted()
        .context("Failed to load persisted uplink state")?;

    let snapshot = hub.export();
    let json =
        serde_json::to_string_pretty(&snapshot).context("Failed to serialize UplinkSnapshot")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create parent directory for export file")?;
    }
    std::fs::write(&path, &json)
        .with_context(|| format!("Failed to write snapshot to {:?}", path))?;

    let proxy_count = snapshot.remote_proxies.len()
        + snapshot
            .clash
            .as_ref()
            .map(|c| c.trojan_proxies.len())
            .unwrap_or(0);
    println!("✓ Exported uplink snapshot to {:?}", path);
    println!("  proxy configs: {}", proxy_count);
    println!("  stats entries: {}", snapshot.stats.len());
    Ok(())
}

fn cmd_import(path: std::path::PathBuf) -> Result<()> {
    let json = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read snapshot from {:?}", path))?;
    let snapshot: crate::uplink::UplinkSnapshot =
        serde_json::from_str(&json).context("Failed to parse UplinkSnapshot JSON")?;

    // Persist each sub-state so subsequent commands see it.
    use crate::state_blueprint::PersistentState;

    if let Some(ref clash_state) = snapshot.clash {
        clash_state
            .save_atomic()
            .context("Failed to persist Clash state from snapshot")?;
        println!("  ✓ Clash state written");
    }

    let remote_state = crate::uplink::RemoteProxyState {
        proxies: snapshot.remote_proxies.clone(),
    };
    remote_state
        .save_atomic()
        .context("Failed to persist remote proxy state from snapshot")?;
    println!(
        "  ✓ Remote proxy state written ({} proxies)",
        snapshot.remote_proxies.len()
    );

    let stats_state = crate::uplink::UplinkStatsState {
        stats: snapshot.stats.clone(),
        clear: nsproxy_common::stats::Timestamp::default(),
    };
    stats_state
        .save_atomic()
        .context("Failed to persist stats state from snapshot")?;
    println!("  ✓ Stats written ({} entries)", snapshot.stats.len());

    println!("✓ Import complete — run 'sp uplink clash resolve' to refresh proxy IPs if needed");
    Ok(())
}

fn cmd_dns_backup(path: std::path::PathBuf) -> Result<()> {
    let state = crate::uplink::clash::ClashState::load_or_default()
        .context("Failed to load clash state for DNS backup")?;
    let backup = crate::uplink::backup::UplinkBackup::from_clash_state(&state);
    let json = serde_json::to_string_pretty(&backup).context("Failed to serialize UplinkBackup")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create parent directory for DNS backup file")?;
    }

    std::fs::write(&path, &json)
        .with_context(|| format!("Failed to write DNS backup to {:?}", path))?;

    println!("✓ Exported DNS backup to {:?}", path);
    println!("  cached domains: {}", backup.dns.len());
    Ok(())
}

fn cmd_dns_import(path: std::path::PathBuf) -> Result<()> {
    use crate::state_blueprint::PersistentState;

    let json = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read DNS backup from {:?}", path))?;
    let backup: crate::uplink::backup::UplinkBackup =
        serde_json::from_str(&json).context("Failed to parse UplinkBackup JSON")?;

    let mut state = crate::uplink::clash::ClashState::load_or_default()
        .context("Failed to load clash state for DNS import")?;
    backup.merge_into_clash_state(&mut state);
    state
        .save_atomic()
        .context("Failed to persist clash state after DNS import")?;

    println!("✓ Imported DNS backup from {:?}", path);
    println!("  cached domains: {}", backup.dns.len());
    Ok(())
}
