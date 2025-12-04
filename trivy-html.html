<!DOCTYPE html>
<html>
<head>
    <title>Trivy Report - {{ .ArtifactName }}</title>
    <style>
        body { font-family: Arial; }
        h2 { color: #c0392b; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background: #e74c3c; color: white; }
    </style>
</head>
<body>
    <h2>🔍 Trivy Vulnerabilities - {{ .ArtifactName }}</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Package</th>
            <th>Installed Version</th>
            <th>Fixed Version</th>
            <th>Description</th>
        </tr>
        {{ range .Results }}
        {{ range .Vulnerabilities }}
        {{ if or (eq .Severity "HIGH") (eq .Severity "CRITICAL") }}
        <tr>
            <td>{{ .VulnerabilityID }}</td>
            <td>{{ .Severity }}</td>
            <td>{{ .PkgName }}</td>
            <td>{{ .InstalledVersion }}</td>
            <td>{{ .FixedVersion }}</td>
            <td>{{ .Title }}</td>
        </tr>
        {{ end }}
        {{ end }}
        {{ end }}
    </table>
</body>
</html>
