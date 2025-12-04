<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Trivy Security Report - {{ .ArtifactName }}</title>

<style>
    body { font-family: Arial, sans-serif; background: #f7f9fc; margin: 0; padding: 20px; }
    h1 { color: #2c3e50; margin-bottom: 5px; }
    h3 { margin-top: 0px; color: #34495e; }

    .summary-box {
        background: #ffffff; padding: 15px; border-radius: 8px;
        margin: 15px 0; display: flex; gap: 20px;
        box-shadow: 0px 2px 8px rgba(0,0,0,0.05); font-size: 14px;
    }
    .badge { padding: 6px 12px; border-radius: 5px; font-weight: bold; color: #fff; }
    .critical { background: #c0392b; }
    .high { background: #e67e22; }
    .clean {
        background: #27ae60; padding: 6px 12px; border-radius: 5px; color:#fff;
        font-weight:bold; margin-top: 10px;
    }

    details {
        background: #ffffff; padding: 12px; border-radius: 6px;
        margin-top: 15px; box-shadow: 0px 2px 8px rgba(0,0,0,0.05);
    }
    summary { font-weight: bold; cursor: pointer; }

    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th { background: #34495e; color: #fff; padding: 10px; text-align: left; }
    td { padding: 8px; border-bottom: 1px solid #ddd; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    tr:hover { background-color: #e6f7ff; transition: 0.18s; }

    .sev-high { color: #e67e22; font-weight:bold; }
    .sev-critical { color: #c0392b; font-weight:bold; }
</style>
</head>

<body>
<h1>🔍 Trivy Security Scan Report</h1>
<h3>Target: {{ .ArtifactName }}</h3>

<div class="summary-box">
    <div class="badge critical">Critical: {{ count .Vulnerabilities "CRITICAL" }}</div>
    <div class="badge high">High: {{ count .Vulnerabilities "HIGH" }}</div>
</div>

{{ if eq (len .Vulnerabilities) 0 }}
<div class="clean">🎉 No HIGH or CRITICAL vulnerabilities found. Secure Build! 💪</div>
{{ else }}

{{ range .Results }}
<details open>
    <summary>📦 {{ .Target }}</summary>

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
            <td class="sev-{{ lower .Severity }}">{{ .Severity }}</td>
            <td>{{ .PkgName }}</td>
            <td>{{ .InstalledVersion }}</td>
            <td>{{ .FixedVersion }}</td>
            <td>{{ .Title }}</td>
        </tr>
        {{ end }}
        {{ end }}
        </tbody>
    </table>
</details>
{{ end }}

{{ end }}
</body>
</html>
