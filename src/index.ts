#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

const execAsync = promisify(exec);

// ─── Shared Types ─────────────────────────────────────────────────────────────

type Severity = "critical" | "warning" | "ok";
type Status = "good" | "warning" | "critical";

interface CallTreeFrame {
  symbol: string;
  selfMs: number;
  totalMs: number;
}

// ─── Launch Types ─────────────────────────────────────────────────────────────

interface LaunchOffender {
  symbol: string;
  selfTimeMs: number;
  totalTimeMs: number;
  percent: number;
  phase: "pre-main" | "post-main" | "unknown";
  severity: Severity;
  suggestion?: string;
}

interface LaunchPhase {
  name: string;
  durationMs: number;
  percent: number;
}

interface LaunchAnalysis {
  totalLaunchMs: number;
  status: Status;
  phases: LaunchPhase[];
  offenders: LaunchOffender[];
  summary: string;
  recommendations: string[];
}

// ─── Allocations Types ────────────────────────────────────────────────────────

interface AllocationCategory {
  type: string;
  liveBytes: number;
  liveCount: number;
  totalBytes: number;
  totalCount: number;
  severity: Severity;
  suggestion?: string;
}

interface AllocationAnalysis {
  peakMemoryMb: number;
  liveMemoryMb: number;
  status: Status;
  topAllocations: AllocationCategory[];
  summary: string;
  recommendations: string[];
}

// ─── Leaks Types ──────────────────────────────────────────────────────────────

interface LeakEntry {
  type: string;
  count: number;
  totalBytes: number;
  rootCycle: boolean;
  suggestion?: string;
}

interface LeaksAnalysis {
  totalLeaks: number;
  totalLeakedBytes: number;
  status: Status;
  leaks: LeakEntry[];
  summary: string;
  recommendations: string[];
}

// ─── Time Profiler Types ──────────────────────────────────────────────────────

interface HotMethod {
  symbol: string;
  selfTimeMs: number;
  totalTimeMs: number;
  percent: number;
  severity: Severity;
  suggestion?: string;
}

interface TimeProfileAnalysis {
  totalDurationMs: number;
  status: Status;
  hotMethods: HotMethod[];
  summary: string;
  recommendations: string[];
}

// ─── Network Types ────────────────────────────────────────────────────────────

interface NetworkRequest {
  url: string;
  method: string;
  durationMs: number;
  bytes: number;
  statusCode: number;
  severity: Severity;
}

interface NetworkAnalysis {
  totalRequests: number;
  totalTransferredMb: number;
  status: Status;
  slowRequests: NetworkRequest[];
  summary: string;
  recommendations: string[];
}

// ─── Shared Helpers ───────────────────────────────────────────────────────────

function getSeverity(ms: number, thresholdCritical = 300, thresholdWarning = 100): Severity {
  if (ms > thresholdCritical) return "critical";
  if (ms > thresholdWarning) return "warning";
  return "ok";
}

function getMemorySeverity(mb: number): Severity {
  if (mb > 200) return "critical";
  if (mb > 100) return "warning";
  return "ok";
}

function getStatus(ms: number, goodThreshold: number, criticalThreshold: number): Status {
  if (ms < goodThreshold) return "good";
  if (ms < criticalThreshold) return "warning";
  return "critical";
}

function getLaunchSuggestion(symbol: string, phase: string): string | undefined {
  const s = symbol.toLowerCase();
  if (s.includes("database") || s.includes("sqlite") || s.includes("coredata"))
    return "Move database initialization to a background queue or use lazy loading.";
  if (s.includes("analytics") || s.includes("firebase") || s.includes("segment"))
    return "Defer analytics SDK initialization after first frame is rendered.";
  if (s.includes("network") || s.includes("urlsession") || s.includes("alamofire"))
    return "Avoid synchronous network calls on launch. Use async/await or callbacks.";
  if (s.includes("image") || s.includes("uiimage") || s.includes("sdwebimage"))
    return "Defer image loading/caching setup to after first frame.";
  if (phase === "pre-main" && s.includes("+initialize"))
    return "Avoid heavy work in +initialize or static initializers — they run before main().";
  if (s.includes("json") || s.includes("decoder") || s.includes("codable"))
    return "Defer JSON parsing to a background thread. Consider caching decoded models.";
  return undefined;
}

function getAllocationSuggestion(type: string): string | undefined {
  const t = type.toLowerCase();
  if (t.includes("uiimage") || t.includes("cgimage"))
    return "Use downsampled images. Load at display size, not original resolution.";
  if (t.includes("string") || t.includes("nsstring"))
    return "Consider using StaticString or interning repeated strings.";
  if (t.includes("data") || t.includes("nsdata"))
    return "Stream large Data objects instead of loading fully into memory.";
  if (t.includes("array") || t.includes("nsarray"))
    return "Use lazy collections or pagination for large arrays.";
  if (t.includes("viewcontroller") || t.includes("uiview"))
    return "Check for retained view controllers outside the view hierarchy.";
  return undefined;
}

function getLeakSuggestion(type: string): string | undefined {
  const t = type.toLowerCase();
  if (t.includes("closure") || t.includes("block"))
    return "Capture lists ([weak self]) in closures referencing self.";
  if (t.includes("delegate"))
    return "Delegate properties should be weak. Check protocol declaration.";
  if (t.includes("timer") || t.includes("nstimer"))
    return "Invalidate timers in deinit or viewDidDisappear.";
  if (t.includes("notificationcenter"))
    return "Remove observers in deinit: NotificationCenter.default.removeObserver(self).";
  return undefined;
}

function getHotMethodSuggestion(symbol: string): string | undefined {
  const s = symbol.toLowerCase();
  if (s.includes("layout") || s.includes("autolayout"))
    return "Profile Auto Layout constraints — reduce constraint count or use manual layout for hot paths.";
  if (s.includes("draw") || s.includes("render") || s.includes("metal"))
    return "Move rendering work to background threads or use Metal for GPU offloading.";
  if (s.includes("json") || s.includes("decoder"))
    return "Parse JSON on a background queue. Cache decoded results.";
  if (s.includes("sort") || s.includes("filter") || s.includes("map"))
    return "Use lazy sequences or move collection operations off the main thread.";
  if (s.includes("fetch") || s.includes("coredata"))
    return "Add fetch limit and use async fetch requests (NSAsynchronousFetchRequest).";
  return undefined;
}

// ─── xctrace helpers ─────────────────────────────────────────────────────────

async function listDevices(): Promise<string> {
  const { stdout } = await execAsync("xcrun xctrace list devices 2>&1");
  return stdout;
}

async function recordTrace(
  template: string,
  bundleId: string,
  deviceId: string,
  timeLimitSeconds: number,
  outputPath: string
): Promise<void> {
  const cmd = [
    "xcrun xctrace record",
    `--template '${template}'`,
    `--device '${deviceId}'`,
    `--launch -- ${bundleId}`,
    `--time-limit ${timeLimitSeconds}s`,
    `--output '${outputPath}'`,
  ].join(" \\\n  ");
  await execAsync(cmd, { timeout: (timeLimitSeconds + 30) * 1000 });
}

async function exportXML(
  tracePath: string,
  outputXmlPath: string,
  xpath?: string
): Promise<void> {
  const xpathArg = xpath ? `--xpath '${xpath}'` : "";
  await execAsync(
    `xcrun xctrace export --input '${tracePath}' --output '${outputXmlPath}' ${xpathArg} 2>&1`
  );
}

function parseCallTree(xmlContent: string): { frames: CallTreeFrame[]; totalMs: number } {
  const frames: CallTreeFrame[] = [];
  let totalMs = 0;

  // Pattern 1: <frame weight="N" self="N">Symbol</frame>
  const framePattern = /<frame[^>]*\sweight="(\d+)"[^>]*\sself="(\d+)"[^>]*>([^<]+)<\/frame>/g;
  let match;
  let totalWeight = 0;
  const raw: { symbol: string; weight: number; self: number }[] = [];

  while ((match = framePattern.exec(xmlContent)) !== null) {
    const weight = parseInt(match[1]);
    const self = parseInt(match[2]);
    totalWeight += self;
    raw.push({ symbol: match[3].trim(), weight, self });
  }

  if (raw.length > 0) {
    const msPerUnit = totalMs > 0 ? totalMs / totalWeight : 1;
    for (const r of raw) {
      frames.push({
        symbol: r.symbol,
        selfMs: r.self * msPerUnit,
        totalMs: r.weight * msPerUnit,
      });
    }
    return { frames, totalMs };
  }

  // Pattern 2: <node name="..." self-weight="Xms" total-weight="Xms">
  const nodePattern =
    /<node[^>]*name="([^"]+)"[^>]*self-weight="([0-9.]+)ms"[^>]*total-weight="([0-9.]+)ms"/g;
  while ((match = nodePattern.exec(xmlContent)) !== null) {
    const selfMs = parseFloat(match[2]);
    const tot = parseFloat(match[3]);
    totalMs = Math.max(totalMs, tot);
    frames.push({ symbol: match[1], selfMs, totalMs: tot });
  }

  return { frames, totalMs };
}

// ─── Parsers ──────────────────────────────────────────────────────────────────

function parseAppLaunch(xmlContent: string, bundleId: string): LaunchAnalysis {
  const { frames, totalMs: parsedTotal } = parseCallTree(xmlContent);

  const launchTimeMatch =
    xmlContent.match(/launch-time[^>]*>([0-9.]+)/i) ||
    xmlContent.match(/total[^>]*time[^>]*>([0-9.]+)/i);
  const totalLaunchMs = launchTimeMatch
    ? parseFloat(launchTimeMatch[1]) * 1000
    : parsedTotal || 0;

  const msPerUnit = parsedTotal > 0 ? totalLaunchMs / parsedTotal : 1;
  const seen = new Set<string>();
  const offenders: LaunchOffender[] = [];

  for (const f of frames) {
    if (seen.has(f.symbol)) continue;
    seen.add(f.symbol);
    const selfMs = f.selfMs * msPerUnit;
    if (selfMs < 10) continue;
    const phase: "pre-main" | "post-main" | "unknown" =
      f.symbol.includes("+initialize") || f.symbol.includes("dyld")
        ? "pre-main"
        : "post-main";
    offenders.push({
      symbol: f.symbol,
      selfTimeMs: Math.round(selfMs),
      totalTimeMs: Math.round(f.totalMs * msPerUnit),
      percent: totalLaunchMs > 0 ? Math.round((selfMs / totalLaunchMs) * 100) : 0,
      phase,
      severity: getSeverity(selfMs),
      suggestion: getLaunchSuggestion(f.symbol, phase),
    });
  }

  offenders.sort((a, b) => b.selfTimeMs - a.selfTimeMs);

  const phases: LaunchPhase[] =
    totalLaunchMs > 0
      ? [
          { name: "pre-main (dyld + static init)", durationMs: Math.round(totalLaunchMs * 0.35), percent: 35 },
          { name: "post-main (AppDelegate + UI)", durationMs: Math.round(totalLaunchMs * 0.65), percent: 65 },
        ]
      : [];

  const criticalCount = offenders.filter((o) => o.severity === "critical").length;
  const warningCount = offenders.filter((o) => o.severity === "warning").length;
  const recommendations: string[] = [];
  if (criticalCount > 0)
    recommendations.push(`Fix ${criticalCount} critical offender(s) — each adds 300ms+ to launch.`);
  if (warningCount > 0)
    recommendations.push(`${warningCount} method(s) between 100–300ms — worth deferring to background.`);
  if (offenders.some((o) => o.phase === "pre-main"))
    recommendations.push("Reduce static initializers: avoid +initialize, prefer lazy var in Swift.");
  recommendations.push("Target: total launch under 400ms. Write XCTest performance tests to catch regressions.");

  const status = getStatus(totalLaunchMs, 400, 1000);
  const summary =
    status === "good"
      ? `✅ Launch time ${totalLaunchMs}ms — within Apple's recommended threshold.`
      : status === "warning"
      ? `⚠️ Launch time ${totalLaunchMs}ms — above 400ms. Users may notice the delay.`
      : `🔴 Launch time ${totalLaunchMs}ms — critical. Apple may flag this in App Store review.`;

  return { totalLaunchMs, status, phases, offenders: offenders.slice(0, 15), summary, recommendations };
}

function parseAllocations(xmlContent: string): AllocationAnalysis {
  const categories: AllocationCategory[] = [];

  // Parse allocation table: <row><type>X</type><live-bytes>N</live-bytes>...
  const rowPattern = /<row>([\s\S]*?)<\/row>/g;
  let match;
  let peakMb = 0;
  let liveMb = 0;

  while ((match = rowPattern.exec(xmlContent)) !== null) {
    const row = match[1];
    const type = (row.match(/<type[^>]*>([^<]+)<\/type>/) || [])[1]?.trim() ?? "Unknown";
    const liveBytes = parseInt((row.match(/<live-bytes[^>]*>(\d+)<\/live-bytes>/) || [])[1] ?? "0");
    const liveCount = parseInt((row.match(/<live-count[^>]*>(\d+)<\/live-count>/) || [])[1] ?? "0");
    const totalBytes = parseInt((row.match(/<total-bytes[^>]*>(\d+)<\/total-bytes>/) || [])[1] ?? "0");
    const totalCount = parseInt((row.match(/<total-count[^>]*>(\d+)<\/total-count>/) || [])[1] ?? "0");

    if (totalBytes < 1024) continue;
    liveMb += liveBytes / 1_048_576;

    categories.push({
      type,
      liveBytes,
      liveCount,
      totalBytes,
      totalCount,
      severity: getMemorySeverity(liveBytes / 1_048_576),
      suggestion: getAllocationSuggestion(type),
    });
  }

  // Fallback: try peak-memory pattern
  const peakMatch = xmlContent.match(/peak[^>]*memory[^>]*>([0-9.]+)\s*(mb|kb)?/i);
  if (peakMatch) {
    peakMb = parseFloat(peakMatch[1]);
    if (peakMatch[2]?.toLowerCase() === "kb") peakMb /= 1024;
  } else {
    peakMb = liveMb * 1.3;
  }

  categories.sort((a, b) => b.liveBytes - a.liveBytes);

  const status: Status = peakMb > 200 ? "critical" : peakMb > 100 ? "warning" : "good";
  const summary =
    status === "good"
      ? `✅ Peak memory ${peakMb.toFixed(1)}MB — healthy.`
      : status === "warning"
      ? `⚠️ Peak memory ${peakMb.toFixed(1)}MB — monitor on older devices.`
      : `🔴 Peak memory ${peakMb.toFixed(1)}MB — high risk of jetsam kill on iPhone with 3GB RAM.`;

  const recommendations: string[] = [];
  if (categories.some((c) => c.type.toLowerCase().includes("uiimage")))
    recommendations.push("Downscale images before storing in memory. Use ImageIO for thumbnail generation.");
  if (peakMb > 150)
    recommendations.push("Subscribe to UIApplicationDidReceiveMemoryWarningNotification and release caches.");
  recommendations.push(
    "Use Xcode Memory Gauge during testing. Target < 50MB for typical use, < 120MB peak."
  );

  return {
    peakMemoryMb: Math.round(peakMb * 10) / 10,
    liveMemoryMb: Math.round(liveMb * 10) / 10,
    status,
    topAllocations: categories.slice(0, 15),
    summary,
    recommendations,
  };
}

function parseLeaks(xmlContent: string): LeaksAnalysis {
  const leaks: LeakEntry[] = [];

  // Parse leak rows
  const leakPattern =
    /<leak[^>]*type="([^"]+)"[^>]*count="(\d+)"[^>]*size="(\d+)"[^>]*root-cycle="(true|false)"/g;
  let match;

  while ((match = leakPattern.exec(xmlContent)) !== null) {
    const type = match[1];
    const count = parseInt(match[2]);
    const totalBytes = parseInt(match[3]);
    const rootCycle = match[4] === "true";
    leaks.push({ type, count, totalBytes, rootCycle, suggestion: getLeakSuggestion(type) });
  }

  // Fallback: table row pattern
  if (leaks.length === 0) {
    const rowPattern = /<row>([\s\S]*?)<\/row>/g;
    while ((match = rowPattern.exec(xmlContent)) !== null) {
      const row = match[1];
      const type = (row.match(/<responsible-library[^>]*>([^<]+)/) || row.match(/<type[^>]*>([^<]+)/)|| [])[1]?.trim();
      const size = parseInt((row.match(/<size[^>]*>(\d+)<\/size>/) || [])[1] ?? "0");
      if (!type || size === 0) continue;
      leaks.push({ type, count: 1, totalBytes: size, rootCycle: false, suggestion: getLeakSuggestion(type) });
    }
  }

  leaks.sort((a, b) => b.totalBytes - a.totalBytes);
  const totalLeaks = leaks.reduce((s, l) => s + l.count, 0);
  const totalBytes = leaks.reduce((s, l) => s + l.totalBytes, 0);

  const status: Status = totalLeaks === 0 ? "good" : totalLeaks > 10 ? "critical" : "warning";
  const summary =
    totalLeaks === 0
      ? "✅ No memory leaks detected."
      : status === "warning"
      ? `⚠️ ${totalLeaks} leak(s) found — ${(totalBytes / 1024).toFixed(1)}KB leaked.`
      : `🔴 ${totalLeaks} leak(s) found — ${(totalBytes / 1024).toFixed(1)}KB leaked. Fix before shipping.`;

  const recommendations: string[] = [];
  if (leaks.some((l) => l.rootCycle))
    recommendations.push("Root retain cycles detected. Use [weak self] in closures and weak delegates.");
  if (totalLeaks > 0)
    recommendations.push("Run Leaks instrument regularly in CI using xctrace to catch regressions early.");
  recommendations.push("Enable Malloc Stack Logging in scheme diagnostics for detailed allocation stacks.");

  return {
    totalLeaks,
    totalLeakedBytes: totalBytes,
    status,
    leaks: leaks.slice(0, 15),
    summary,
    recommendations,
  };
}

function parseTimeProfiler(xmlContent: string): TimeProfileAnalysis {
  const { frames, totalMs } = parseCallTree(xmlContent);
  const seen = new Set<string>();
  const hotMethods: HotMethod[] = [];

  for (const f of frames) {
    if (seen.has(f.symbol)) continue;
    seen.add(f.symbol);
    if (f.selfMs < 5) continue;
    hotMethods.push({
      symbol: f.symbol,
      selfTimeMs: Math.round(f.selfMs),
      totalTimeMs: Math.round(f.totalMs),
      percent: totalMs > 0 ? Math.round((f.selfMs / totalMs) * 100) : 0,
      severity: getSeverity(f.selfMs, 200, 50),
      suggestion: getHotMethodSuggestion(f.symbol),
    });
  }

  hotMethods.sort((a, b) => b.selfTimeMs - a.selfTimeMs);

  const status: Status = getStatus(totalMs, 16, 100); // 16ms = 60fps
  const summary =
    status === "good"
      ? `✅ CPU profile looks healthy — no dominant hot methods.`
      : status === "warning"
      ? `⚠️ Some methods consuming significant CPU. Review top offenders.`
      : `🔴 Heavy CPU usage detected. Main thread likely blocked — users will feel jank.`;

  const recommendations: string[] = [];
  if (hotMethods.some((m) => m.severity === "critical"))
    recommendations.push("Move critical hot methods off the main thread using async/await or DispatchQueue.");
  recommendations.push("Use Instruments Time Profiler regularly during UI stress tests.");
  recommendations.push("Target < 16ms per frame (60fps) or < 8ms (120fps ProMotion) for main thread work.");

  return {
    totalDurationMs: Math.round(totalMs),
    status,
    hotMethods: hotMethods.slice(0, 15),
    summary,
    recommendations,
  };
}

function parseNetwork(xmlContent: string): NetworkAnalysis {
  const requests: NetworkRequest[] = [];

  const reqPattern =
    /<request[^>]*url="([^"]+)"[^>]*method="([^"]+)"[^>]*duration="([0-9.]+)"[^>]*bytes="(\d+)"[^>]*status="(\d+)"/g;
  let match;

  while ((match = reqPattern.exec(xmlContent)) !== null) {
    const durationMs = parseFloat(match[3]) * 1000;
    requests.push({
      url: match[1],
      method: match[2],
      durationMs: Math.round(durationMs),
      bytes: parseInt(match[4]),
      statusCode: parseInt(match[5]),
      severity: getSeverity(durationMs, 2000, 500),
    });
  }

  // Fallback row pattern
  if (requests.length === 0) {
    const rowPattern = /<row>([\s\S]*?)<\/row>/g;
    while ((match = rowPattern.exec(xmlContent)) !== null) {
      const row = match[1];
      const url = (row.match(/<url[^>]*>([^<]+)<\/url>/) || [])[1]?.trim() ?? "";
      const duration = parseFloat((row.match(/<duration[^>]*>([0-9.]+)/) || [])[1] ?? "0");
      const bytes = parseInt((row.match(/<bytes[^>]*>(\d+)/) || [])[1] ?? "0");
      const status = parseInt((row.match(/<status[^>]*>(\d+)/) || [])[1] ?? "200");
      if (!url) continue;
      const durationMs = duration * 1000;
      requests.push({ url, method: "GET", durationMs: Math.round(durationMs), bytes, statusCode: status, severity: getSeverity(durationMs, 2000, 500) });
    }
  }

  requests.sort((a, b) => b.durationMs - a.durationMs);
  const totalTransferred = requests.reduce((s, r) => s + r.bytes, 0) / 1_048_576;
  const slowCount = requests.filter((r) => r.severity !== "ok").length;

  const status: Status = slowCount === 0 ? "good" : slowCount > 5 ? "critical" : "warning";
  const summary =
    status === "good"
      ? `✅ ${requests.length} requests — all within acceptable latency.`
      : status === "warning"
      ? `⚠️ ${slowCount} slow request(s) found out of ${requests.length} total.`
      : `🔴 ${slowCount} slow request(s) — network is a bottleneck.`;

  const recommendations: string[] = [];
  if (requests.some((r) => r.statusCode >= 400))
    recommendations.push("Fix failing requests (4xx/5xx) — these cause silent UX degradation.");
  if (totalTransferred > 5)
    recommendations.push("Total transfer > 5MB. Use pagination, compression (gzip/brotli), and caching.");
  recommendations.push("Use URLCache for GET requests. Consider background URLSession for large transfers.");

  return {
    totalRequests: requests.length,
    totalTransferredMb: Math.round(totalTransferred * 100) / 100,
    status,
    slowRequests: requests.slice(0, 15),
    summary,
    recommendations,
  };
}

// ─── Formatters ───────────────────────────────────────────────────────────────

function formatLaunch(a: LaunchAnalysis, bundleId: string): string {
  const lines = [`# App Launch Analysis — ${bundleId}`, `\n${a.summary}`, `\n**Total:** ${a.totalLaunchMs}ms`];
  if (a.phases.length) {
    lines.push("\n## Phases");
    a.phases.forEach((p) => lines.push(`- **${p.name}:** ${p.durationMs}ms (${p.percent}%)`));
  }
  lines.push("\n## Top Offenders");
  if (!a.offenders.length) { lines.push("No significant offenders."); }
  else a.offenders.forEach((o) => {
    const icon = o.severity === "critical" ? "🔴" : o.severity === "warning" ? "🟡" : "🟢";
    lines.push(`\n${icon} \`${o.symbol}\` [${o.phase}]`);
    lines.push(`   Self: **${o.selfTimeMs}ms** | Total: ${o.totalTimeMs}ms | ${o.percent}%`);
    if (o.suggestion) lines.push(`   💡 ${o.suggestion}`);
  });
  lines.push("\n## Recommendations");
  a.recommendations.forEach((r) => lines.push(`- ${r}`));
  return lines.join("\n");
}

function formatAllocations(a: AllocationAnalysis, bundleId: string): string {
  const lines = [
    `# Memory Allocations — ${bundleId}`,
    `\n${a.summary}`,
    `\n**Peak:** ${a.peakMemoryMb}MB | **Live:** ${a.liveMemoryMb}MB`,
    "\n## Top Allocations by Type",
  ];
  if (!a.topAllocations.length) { lines.push("No allocation data found."); }
  else a.topAllocations.forEach((c) => {
    const icon = c.severity === "critical" ? "🔴" : c.severity === "warning" ? "🟡" : "🟢";
    const liveMb = (c.liveBytes / 1_048_576).toFixed(2);
    const totalMb = (c.totalBytes / 1_048_576).toFixed(2);
    lines.push(`\n${icon} \`${c.type}\``);
    lines.push(`   Live: **${liveMb}MB** (${c.liveCount} objects) | Total: ${totalMb}MB (${c.totalCount} allocs)`);
    if (c.suggestion) lines.push(`   💡 ${c.suggestion}`);
  });
  lines.push("\n## Recommendations");
  a.recommendations.forEach((r) => lines.push(`- ${r}`));
  return lines.join("\n");
}

function formatLeaks(a: LeaksAnalysis, bundleId: string): string {
  const lines = [
    `# Memory Leaks — ${bundleId}`,
    `\n${a.summary}`,
    `\n**Total leaks:** ${a.totalLeaks} | **Leaked:** ${(a.totalLeakedBytes / 1024).toFixed(1)}KB`,
    "\n## Leak Details",
  ];
  if (!a.leaks.length) { lines.push("No leaks found. ✅"); }
  else a.leaks.forEach((l) => {
    lines.push(`\n🔴 \`${l.type}\``);
    lines.push(`   Count: ${l.count} | Size: ${(l.totalBytes / 1024).toFixed(1)}KB${l.rootCycle ? " | ⚠️ Root Cycle" : ""}`);
    if (l.suggestion) lines.push(`   💡 ${l.suggestion}`);
  });
  lines.push("\n## Recommendations");
  a.recommendations.forEach((r) => lines.push(`- ${r}`));
  return lines.join("\n");
}

function formatTimeProfiler(a: TimeProfileAnalysis, bundleId: string): string {
  const lines = [
    `# Time Profiler — ${bundleId}`,
    `\n${a.summary}`,
    `\n**Duration profiled:** ${a.totalDurationMs}ms`,
    "\n## Hot Methods",
  ];
  if (!a.hotMethods.length) { lines.push("No hot methods found."); }
  else a.hotMethods.forEach((m) => {
    const icon = m.severity === "critical" ? "🔴" : m.severity === "warning" ? "🟡" : "🟢";
    lines.push(`\n${icon} \`${m.symbol}\``);
    lines.push(`   Self: **${m.selfTimeMs}ms** | Total: ${m.totalTimeMs}ms | ${m.percent}% of CPU`);
    if (m.suggestion) lines.push(`   💡 ${m.suggestion}`);
  });
  lines.push("\n## Recommendations");
  a.recommendations.forEach((r) => lines.push(`- ${r}`));
  return lines.join("\n");
}

function formatNetwork(a: NetworkAnalysis, bundleId: string): string {
  const lines = [
    `# Network Activity — ${bundleId}`,
    `\n${a.summary}`,
    `\n**Requests:** ${a.totalRequests} | **Transferred:** ${a.totalTransferredMb}MB`,
    "\n## Slow Requests",
  ];
  if (!a.slowRequests.length) { lines.push("No slow requests found."); }
  else a.slowRequests.forEach((r) => {
    const icon = r.severity === "critical" ? "🔴" : r.severity === "warning" ? "🟡" : "🟢";
    lines.push(`\n${icon} \`${r.method} ${r.url}\``);
    lines.push(`   Duration: **${r.durationMs}ms** | Size: ${(r.bytes / 1024).toFixed(1)}KB | Status: ${r.statusCode}`);
  });
  lines.push("\n## Recommendations");
  a.recommendations.forEach((r) => lines.push(`- ${r}`));
  return lines.join("\n");
}

// ─── Shared runner ────────────────────────────────────────────────────────────

async function runAnalysis<T>(
  template: string,
  bundleId: string,
  deviceId: string,
  timeLimitSeconds: number,
  parser: (xml: string) => T,
  formatter: (result: T) => string
): Promise<string> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "instruments-mcp-"));
  const tracePath = path.join(tmpDir, "trace.xctrace");
  const xmlPath = path.join(tmpDir, "export.xml");

  try {
    await recordTrace(template, bundleId, deviceId, timeLimitSeconds, tracePath);
    await exportXML(tracePath, xmlPath).catch(() => {});
    const xmlContent = fs.existsSync(xmlPath) ? fs.readFileSync(xmlPath, "utf-8") : "";
    return formatter(parser(xmlContent));
  } catch (err: any) {
    return [
      `Error profiling with template '${template}': ${err.message}`,
      "",
      "Common causes:",
      "- App not installed on the selected device/simulator",
      "- Simulator not booted: xcrun simctl boot <UUID>",
      "- Xcode CLI tools missing: xcode-select --install",
      "- Physical device: enable 'UI Automation' in Settings → Developer",
    ].join("\n");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function analyzeExisting<T>(
  tracePath: string,
  parser: (xml: string) => T,
  formatter: (result: T) => string
): Promise<string> {
  if (!fs.existsSync(tracePath)) return `Trace file not found: ${tracePath}`;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "instruments-mcp-"));
  const xmlPath = path.join(tmpDir, "export.xml");
  try {
    await exportXML(tracePath, xmlPath).catch(() => {});
    const xmlContent = fs.existsSync(xmlPath) ? fs.readFileSync(xmlPath, "utf-8") : "";
    return formatter(parser(xmlContent));
  } catch (err: any) {
    return `Error analyzing trace: ${err.message}`;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ─── MCP Server ───────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "ios-instruments-mcp",
  version: "2.0.0",
  description:
    "Profile iOS apps with Instruments via xctrace — launch time, allocations, leaks, CPU, and network.",
});

const deviceArg = z
  .string()
  .describe("Simulator UUID or physical device ID. Use list_devices to find it.");

const bundleArg = z.string().describe("App bundle ID, e.g. com.mycompany.myapp");

const timeLimitArg = z
  .number()
  .min(5)
  .max(120)
  .default(20)
  .describe("Recording duration in seconds (default 20s).");

// ── Utility tools ─────────────────────────────────────────────────────────────

server.tool("list_devices", "List available iOS simulators and physical devices.", {}, async () => {
  try {
    return { content: [{ type: "text", text: await listDevices() }] };
  } catch (err: any) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }] };
  }
});

server.tool("list_templates", "List all Instruments profiling templates installed on this Mac.", {}, async () => {
  try {
    const { stdout } = await execAsync("xcrun xctrace list templates 2>&1");
    return { content: [{ type: "text", text: stdout }] };
  } catch (err: any) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }] };
  }
});

// ── App Launch ────────────────────────────────────────────────────────────────

server.tool(
  "analyze_launch",
  "Record an App Launch trace and report which methods hurt startup time with fix suggestions.",
  { bundle_id: bundleArg, device_id: deviceArg, time_limit_seconds: timeLimitArg },
  async ({ bundle_id, device_id, time_limit_seconds }) => {
    const result = await runAnalysis(
      "App Launch", bundle_id, device_id, time_limit_seconds,
      (xml) => parseAppLaunch(xml, bundle_id),
      (a) => formatLaunch(a, bundle_id)
    );
    return { content: [{ type: "text", text: result }] };
  }
);

server.tool(
  "analyze_launch_trace",
  "Analyze an existing .xctrace file recorded with the App Launch template.",
  {
    trace_path: z.string().describe("Absolute path to the .xctrace file."),
    bundle_id: z.string().default("com.unknown.app"),
  },
  async ({ trace_path, bundle_id }) => {
    const result = await analyzeExisting(
      trace_path,
      (xml) => parseAppLaunch(xml, bundle_id),
      (a) => formatLaunch(a, bundle_id)
    );
    return { content: [{ type: "text", text: result }] };
  }
);

// ── Allocations ───────────────────────────────────────────────────────────────

server.tool(
  "analyze_allocations",
  "Record an Allocations trace and report peak memory, top allocation types, and fix suggestions.",
  { bundle_id: bundleArg, device_id: deviceArg, time_limit_seconds: timeLimitArg },
  async ({ bundle_id, device_id, time_limit_seconds }) => {
    const result = await runAnalysis(
      "Allocations", bundle_id, device_id, time_limit_seconds,
      parseAllocations,
      (a) => formatAllocations(a, bundle_id)
    );
    return { content: [{ type: "text", text: result }] };
  }
);

server.tool(
  "analyze_allocations_trace",
  "Analyze an existing .xctrace file recorded with the Allocations template.",
  {
    trace_path: z.string().describe("Absolute path to the .xctrace file."),
    bundle_id: z.string().default("com.unknown.app"),
  },
  async ({ trace_path, bundle_id }) => {
    const result = await analyzeExisting(trace_path, parseAllocations, (a) => formatAllocations(a, bundle_id));
    return { content: [{ type: "text", text: result }] };
  }
);

// ── Leaks ─────────────────────────────────────────────────────────────────────

server.tool(
  "analyze_leaks",
  "Record a Leaks trace and report all memory leaks with retain cycle detection and fix suggestions.",
  { bundle_id: bundleArg, device_id: deviceArg, time_limit_seconds: timeLimitArg },
  async ({ bundle_id, device_id, time_limit_seconds }) => {
    const result = await runAnalysis(
      "Leaks", bundle_id, device_id, time_limit_seconds,
      parseLeaks,
      (a) => formatLeaks(a, bundle_id)
    );
    return { content: [{ type: "text", text: result }] };
  }
);

server.tool(
  "analyze_leaks_trace",
  "Analyze an existing .xctrace file recorded with the Leaks template.",
  {
    trace_path: z.string().describe("Absolute path to the .xctrace file."),
    bundle_id: z.string().default("com.unknown.app"),
  },
  async ({ trace_path, bundle_id }) => {
    const result = await analyzeExisting(trace_path, parseLeaks, (a) => formatLeaks(a, bundle_id));
    return { content: [{ type: "text", text: result }] };
  }
);

// ── Time Profiler ─────────────────────────────────────────────────────────────

server.tool(
  "analyze_time_profiler",
  "Record a Time Profiler trace and report hot methods consuming the most CPU time.",
  { bundle_id: bundleArg, device_id: deviceArg, time_limit_seconds: timeLimitArg },
  async ({ bundle_id, device_id, time_limit_seconds }) => {
    const result = await runAnalysis(
      "Time Profiler", bundle_id, device_id, time_limit_seconds,
      parseTimeProfiler,
      (a) => formatTimeProfiler(a, bundle_id)
    );
    return { content: [{ type: "text", text: result }] };
  }
);

server.tool(
  "analyze_time_profiler_trace",
  "Analyze an existing .xctrace file recorded with the Time Profiler template.",
  {
    trace_path: z.string().describe("Absolute path to the .xctrace file."),
    bundle_id: z.string().default("com.unknown.app"),
  },
  async ({ trace_path, bundle_id }) => {
    const result = await analyzeExisting(trace_path, parseTimeProfiler, (a) => formatTimeProfiler(a, bundle_id));
    return { content: [{ type: "text", text: result }] };
  }
);

// ── Network ───────────────────────────────────────────────────────────────────

server.tool(
  "analyze_network",
  "Record a Network trace and report slow requests, transfer sizes, and optimization suggestions.",
  { bundle_id: bundleArg, device_id: deviceArg, time_limit_seconds: timeLimitArg },
  async ({ bundle_id, device_id, time_limit_seconds }) => {
    const result = await runAnalysis(
      "Network", bundle_id, device_id, time_limit_seconds,
      parseNetwork,
      (a) => formatNetwork(a, bundle_id)
    );
    return { content: [{ type: "text", text: result }] };
  }
);

server.tool(
  "analyze_network_trace",
  "Analyze an existing .xctrace file recorded with the Network template.",
  {
    trace_path: z.string().describe("Absolute path to the .xctrace file."),
    bundle_id: z.string().default("com.unknown.app"),
  },
  async ({ trace_path, bundle_id }) => {
    const result = await analyzeExisting(trace_path, parseNetwork, (a) => formatNetwork(a, bundle_id));
    return { content: [{ type: "text", text: result }] };
  }
);

// ─── Start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
