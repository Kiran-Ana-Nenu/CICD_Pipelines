#!/usr/bin/env bash
# Generates combined Trivy summary dashboard
set -e

REPORT_DIR="trivy-reports"
SUMMARY_HTML="${REPORT_DIR}/trivy-summary.html"

mkdir -p "${REPORT_DIR}"

declare -A images counts_CRITICAL counts_HIGH counts_MEDIUM counts_LOW counts_UNKNOWN

# Collect counts per image from JSON files
for f in ${REPORT_DIR}/*.json; do
  img=$(basename "$f" | sed 's/trivy-\(.*\)\.json/\1/')
  images[$img]=$f
  counts_CRITICAL[$img]=$(jq '[.Results[].Vulnerabilities[] | select(.Severity=="CRITICAL")] | length' "$f")
  counts_HIGH[$img]=$(jq '[.Results[].Vulnerabilities[] | select(.Severity=="HIGH")] | length' "$f")
  counts_MEDIUM[$img]=$(jq '[.Results[].Vulnerabilities[] | select(.Severity=="MEDIUM")] | length' "$f")
  counts_LOW[$img]=$(jq '[.Results[].Vulnerabilities[] | select(.Severity=="LOW")] | length' "$f")
  counts_UNKNOWN[$img]=$(jq '[.Results[].Vulnerabilities[] | select(.Severity=="UNKNOWN")] | length' "$f")
done

# Generate summary HTML
cat > "$SUMMARY_HTML" <<EOF
<!DOCTYPE html>
<html>
<head>
<title>Trivy Summary Dashboard</title>
<style>
body { font-family: Arial; margin: 20px; }
h1 { color: #673ab7; }
.table { border-collapse: collapse; width: 100%; margin-top: 20px; }
.table th, .table td { border: 1px solid #ddd; padding: 10px; text-align: center; }
.table th { background: #512da8; color: white; }
.badge { padding: 3px 8px; border-radius: 4px; color: white; }
.CRITICAL { background:#8e0000 }
.HIGH { background:#d84315 }
.MEDIUM { background:#558b2f }
.LOW { background:#0277bd }
.UNKNOWN { background:#616161 }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<h1>Trivy Security Summary</h1>
<p>Generated: $(date)</p>

<table class="table">
<tr>
<th>Image</th>
<th>CRITICAL</th>
<th>HIGH</th>
<th>MEDIUM</th>
<th>LOW</th>
<th>UNKNOWN</th>
<th>Total</th>
</tr>
EOF

labels=""
critData=""
highData=""
medData=""
lowData=""
unkData=""

for img in "${!images[@]}"; do
  total=$(( counts_CRITICAL[$img] + counts_HIGH[$img] + counts_MEDIUM[$img] + counts_LOW[$img] + counts_UNKNOWN[$img] ))
  echo "<tr>
<td>${img}</td>
<td><span class='badge CRITICAL'>${counts_CRITICAL[$img]}</span></td>
<td><span class='badge HIGH'>${counts_HIGH[$img]}</span></td>
<td><span class='badge MEDIUM'>${counts_MEDIUM[$img]}</span></td>
<td><span class='badge LOW'>${counts_LOW[$img]}</span></td>
<td><span class='badge UNKNOWN'>${counts_UNKNOWN[$img]}</span></td>
<td>${total}</td>
</tr>" >> "$SUMMARY_HTML"

  labels="${labels}'${img}',"
  critData="${critData}${counts_CRITICAL[$img]},"
  highData="${highData}${counts_HIGH[$img]},"
  medData="${medData}${counts_MEDIUM[$img]},"
  lowData="${lowData}${counts_LOW[$img]},"
  unkData="${unkData}${counts_UNKNOWN[$img]},"
done

cat >> "$SUMMARY_HTML" <<EOF
</table>

<h2 style="margin-top:40px;">Vulnerabilities by Image</h2>
<canvas id="barChart" width="900" height="400"></canvas>
<canvas id="pieChart" width="900" height="400" style="margin-top:40px;"></canvas>

<script>
const labels = [${labels}];
new Chart(document.getElementById('barChart'), {
  type: 'bar',
  data: {
    labels: labels,
    datasets: [
      { label: 'CRITICAL', data: [${critData}], backgroundColor:'#8e0000' },
      { label: 'HIGH', data: [${highData}], backgroundColor:'#d84315' },
      { label: 'MEDIUM', data: [${medData}], backgroundColor:'#558b2f' },
      { label: 'LOW', data: [${lowData}], backgroundColor:'#0277bd' },
      { label: 'UNKNOWN', data: [${unkData}], backgroundColor:'#616161' }
    ]
  },
  options: { responsive: true, plugins: { legend: { position:'top' } } }
});

new Chart(document.getElementById('pieChart'), {
  type: 'pie',
  data: {
    labels: labels,
    datasets: [{
      data: [${critData%?},${highData%?},${medData%?},${lowData%?},${unkData%?}],
      backgroundColor:['#8e0000','#d84315','#558b2f','#0277bd','#616161']
    }]
  },
  options: { responsive: true, plugins:{ legend:{ position:'right' } } }
});
</script>

<p style="font-size:12px;margin-top:20px;">Generated automatically by CI security dashboard</p>
</body>
</html>
EOF

echo "📄 Summary dashboard created: ${SUMMARY_HTML}"
