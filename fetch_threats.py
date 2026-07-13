import json
import urllib.request

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def generate_svg():
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())

        vulns = sorted(
            data["vulnerabilities"],
            key=lambda x: x["dateAdded"],
            reverse=True
        )[:5]

        terminal_lines = ""
        for idx, vuln in enumerate(vulns):
            cve_id = vuln.get("cveID", "UNKNOWN")
            date_added = vuln.get("dateAdded", "YYYY-MM-DD")
            raw_name = vuln.get("vulnerabilityName", "Unknown Vulnerability")

            max_len = 65
            name = raw_name[:max_len] + "..." if len(raw_name) > max_len else raw_name

            y_pos = idx * 35

            terminal_lines += f'''
            <text x="0" y="{y_pos}" class="font-mono">
                <tspan class="timestamp">[{date_added}]</tspan>
                <tspan class="cve-id"> {cve_id} </tspan>
                <tspan class="vuln-name"> {name}</tspan>
            </text>'''

        svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg" width="850" height="300">
        <style>
            .bg {{ fill: #0D1117; stroke: #30363D; stroke-width: 1px; }}
            .header-bg {{ fill: #161B22; }}
            .font-mono {{ font-family: 'Fira Code', 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 14px; }}

            .prompt {{ fill: #58A6FF; font-weight: bold; }}
            .cursor {{ fill: #C9D1D9; animation: blink 1s step-end infinite; }}
            .timestamp {{ fill: #8B949E; }}
            .cve-id {{ fill: #FF7B72; font-weight: bold; }}
            .vuln-name {{ fill: #7EE787; }}

            .scroll-group {{ animation: logSequence 12s ease-in-out infinite; }}

            @keyframes blink {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0; }}
            }}

            @keyframes logSequence {{
                0% {{ transform: translate(20px, 320px); opacity: 0; }}
                5% {{ opacity: 1; }}
                15% {{ transform: translate(20px, 110px); }}
                85% {{ transform: translate(20px, 110px); opacity: 1; }}
                95% {{ opacity: 0; }}
                100% {{ transform: translate(20px, -20px); opacity: 0; }}
            }}
        </style>

        <rect width="100%" height="100%" class="bg" rx="8" ry="8"/>

        <rect width="100%" height="35" class="header-bg" rx="8" ry="8" />
        <rect width="100%" height="15" y="20" class="header-bg" />
        <circle cx="20" cy="17" r="6" fill="#FF5F56" />
        <circle cx="40" cy="17" r="6" fill="#FFBD2E" />
        <circle cx="60" cy="17" r="6" fill="#27C93F" />
        <text x="425" y="22" class="font-mono timestamp" text-anchor="middle" font-size="13px">Live CISA KEV Feed</text>

        <text x="20" y="70" class="font-mono prompt">6H057@local:~$ <tspan fill="#C9D1D9">tail -f /var/log/kev_alerts.log</tspan><tspan class="cursor">_</tspan></text>

        <clipPath id="terminal-clip">
            <rect width="100%" height="210" y="85" />
        </clipPath>

        <g clip-path="url(#terminal-clip)">
            <g class="scroll-group">
                {terminal_lines}
            </g>
        </g>
        </svg>"""

        with open("siem_terminal.svg", "w") as f:
            f.write(svg_content)

        print("Successfully generated polished siem_terminal.svg")

    except Exception as e:
        print(f"Pipeline Failed: {e}")

if __name__ == "__main__":
    generate_svg()
