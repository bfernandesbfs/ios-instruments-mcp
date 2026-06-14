# ios-instruments-mcp

MCP server that wraps `xctrace` (Instruments) to profile iOS apps directly from Claude. Ask natural language questions about your app's performance and get actionable answers.

## What you can ask Claude

```
"Faz o launch timer do com.myapp.ios e diz-me os ofensores"
"Analisa o memory footprint do app no simulador"
"Verifica se há leaks de memória no com.myapp.ios"
"Qual função está a consumir mais CPU?"
"Há requests de rede lentos no app?"
"Analisa o trace em ~/Desktop/launch.xctrace"
```

## Requirements

- macOS with Xcode installed
- Xcode Command Line Tools: `xcode-select --install`
- Node.js ≥ 18

## Setup

```bash
# 1. Clone and install
git clone https://github.com/bfernandesbfs/ios-instruments-mcp.git
cd ios-instruments-mcp
npm install
npm run build

# 2. Register in Claude Desktop
```

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ios-instruments": {
      "command": "node",
      "args": ["/absolute/path/to/ios-instruments-mcp/build/index.js"]
    }
  }
}
```

Restart Claude Desktop after saving.

## Available Tools

| Tool | Template | Description |
|---|---|---|
| `list_devices` | — | Lists simulators and physical devices |
| `list_templates` | — | Lists all Instruments templates on this Mac |
| `analyze_launch` | App Launch | Records + analyzes app startup time |
| `analyze_launch_trace` | App Launch | Analyzes an existing `.xctrace` file |
| `analyze_allocations` | Allocations | Peak memory, top allocation types |
| `analyze_allocations_trace` | Allocations | Analyzes an existing `.xctrace` file |
| `analyze_leaks` | Leaks | Memory leak detection with retain cycle info |
| `analyze_leaks_trace` | Leaks | Analyzes an existing `.xctrace` file |
| `analyze_time_profiler` | Time Profiler | CPU hot methods and main thread usage |
| `analyze_time_profiler_trace` | Time Profiler | Analyzes an existing `.xctrace` file |
| `analyze_network` | Network | Slow requests, transfer sizes, status codes |
| `analyze_network_trace` | Network | Analyzes an existing `.xctrace` file |

## Example output (App Launch)

```
# App Launch Analysis — com.myapp.ios

⚠️ Launch time 1240ms — above 400ms. Users may notice the delay.

**Total:** 1240ms

## Phases
- pre-main (dyld + static init): 434ms (35%)
- post-main (AppDelegate + UI): 806ms (65%)

## Top Offenders

🔴 `-[DatabaseManager setup]` [post-main]
   Self: 540ms | Total: 540ms | 43%
   💡 Move database initialization to a background queue or use lazy loading.

🟡 `+[AnalyticsSDK configure:]` [post-main]
   Self: 210ms | Total: 210ms | 17%
   💡 Defer analytics SDK initialization after first frame is rendered.

## Recommendations
- Fix 1 critical offender(s) — each adds 300ms+ to launch.
- Target: total launch under 400ms.
```

## Notes

- Physical devices require **Enable UI Automation** in Settings → Developer
- Temp `.xctrace` files are cleaned up automatically after each run
- The parser handles both legacy and modern `xctrace` XML formats
- All tools have an `_trace` variant for analyzing files you already have on disk

## License

MIT
