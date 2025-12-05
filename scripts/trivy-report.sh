#!/usr/bin/env bash
# Generates individual Trivy HTML report per image
set -e

IMAGE=$1
TAG=$2
OUTPUT_DIR=$3

mkdir -p "${OUTPUT_DIR}"

FILE_JSON="${OUTPUT_DIR}/trivy-${IMAGE}.json"
FILE_HTML="${OUTPUT_DIR}/trivy-${IMAGE}.html"

echo "🔍 Scanning image: ${IMAGE}:${TAG}"

# Generate JSON report
trivy image \
  --format json \
  --severity HIGH,CRITICAL,MEDIUM,LOW,UNKNOWN \
  --timeout 10m \
  --ignore-unfixed \
  -o "${FILE_JSON}" \
  "${IMAGE}:${TAG}"

# Convert JSON to simple HTML table
cat > "${FILE_HTML}" <<EOF
<!DOCTYPE html>
<html>
<head>
<title>Trivy Report - ${IMAGE}</title>
<style>
body { font-family: Arial; margin: 20px; }
h1 { color: #D9534F; }
.table { width: 100%; border-collapse: collapse; margin-top: 20px; }
.table th, .table td { padding: 10px; border: 1px solid #ddd; font-size: 14px; }
.table th { background: #c62828; color: white; }
.badge { padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; }
.CRITICAL { background:#8e0000 }
.HIGH { background:#d84315 }
.MEDIUM { background:#558b2f }
.LOW { background:#0277bd }
.UNKNOWN { background:#616161 }
</style>
</head>
<body>
<h1>Trivy Scan Report — ${IMAGE}:${TAG}</h1>
<p>Generated: $(date)</p>
<table class="table">
<tr>
<th>Package</th><th>Version</th><th>Severity</th><th>Vulnerability</th><th>Description</th>
</tr>
EOF

jq -c '.Results[].Vulnerabilities[]' "${FILE_JSON}" | while read -r vuln; do
  PKG=$(echo "$vuln" | jq -r '.PkgName')
  VER=$(echo "$vuln" | jq -r '.InstalledVersion')
  SEV=$(echo "$vuln" | jq -r '.Severity')
  ID=$(echo "$vuln" | jq -r '.VulnerabilityID')
  DESC=$(echo "$vuln" | jq -r '.Description' | sed 's/"/\\"/g' | cut -c1-300)
  echo "<tr>
<td>${PKG}</td>
<td>${VER}</td>
<td><span class=\"badge ${SEV}\">${SEV}</span></td>
<td>${ID}</td>
<td>${DESC}</td>
</tr>" >> "${FILE_HTML}"
done

cat >> "${FILE_HTML}" <<EOF
</table>
<p style="font-size:12px;margin-top:20px;">Generated automatically by CI security scan</p>
</body>
</html>
EOF

echo "📄 Report generated: ${FILE_HTML}"
