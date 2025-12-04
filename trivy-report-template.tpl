<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Trivy Security Report - {{ .ArtifactName }}</title>

<style>
    body { font-family: Arial, sans-serif; background: #f7f9fc; margin: 0; padding: 20px; }
    h1 { color: #2c3e50; margin-bottom: 10px; }
    .clean { background: #27ae60; padding: 10px; border-radius: 8px; color:#fff; font-weight:bold; margin-top: 15px; }
    .summary-box { background: #ffffff; padding: 15px; border-radius: 8px; margin: 15px 0; box-shadow: 0px 2px 8px rgba(0,0,0,0.05); font-size: 15px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th { background: #34495e; color: #fff; padding: 10px; text-align: left; }
    td { padding: 8px; border-bottom: 1px solid #ddd; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    tr:hover { background-color: #e6f7ff; transition: 0.18s; }
    .sev-high { color: #e67e22; font-weight:bold; }
    .sev-critical { color: #c0392b; font-weight:bold; }
</style>
</head>

<body>
<h1>🔍 Trivy Security Scan Report – {{ .ArtifactName }}</h1>

{{ $critical := 0 }} {{ $high := 0 }}
{{ range .Results }} {{ range .Vulnerabilities }}
{{ if eq .Severity "CRITICAL" }} {{ $critical = add $critical 1 }} {{ end }}
{{ if eq .Severity "HIGH" }} {{ $high = add $high 1 }} {{ end }}
{{ end }} {{ end }}

<div class="summary-box">
    <strong>Critical: {{$critical}}</strong> &nbsp;&nbsp;
    <strong>High: {{$high}}</strong>
</div>

{{ if and (eq $critical 0) (eq $high 0) }}
<div class="clean">🎉 No HIGH or CRITICAL vulnerabilities found. Build is Secure! 💪</div>
{{ else }}

{{ range .Results }}
<table>
<thead>
<tr>
    <th>Vulnerability</th>
    <th>Severity</th>
    <th>Package</th>
    <th>Installed</th>
    <th>Fixed</th>
    <th>Description</th>
</tr>
</thead>
<tbody>
{{ range .Vulnerabilities }}
{{ if or (eq .Severity "HIGH") (eq .Severity "CRITICAL") }}
<tr>
    <td>{{ .VulnerabilityID }}</td>
    <td class="sev-{{ .Severity | lower }}">{{ .Severity }}</td>
    <td>{{ .PkgName }}</td>
    <td>{{ .InstalledVersion }}</td>
    <td>{{ .FixedVersion }}</td>
    <td>{{ .Title }}</td>
</tr>
{{ end }} {{ end }}
</tbody>
</table>
<br>
{{ end }}

{{ end }}
</body>
</html>
