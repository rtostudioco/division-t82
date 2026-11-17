# API CONTRACT (IPC boundary) — v1

El frontend **solo** consume estos handlers. Ningún comando del sistema se ejecuta desde el cliente. Salvo `POST /api/scans` (ejecuta auditoría read-only) y `POST /api/settings/reset` (borra datos locales con auditoría), todo es GET.

## GET /api/engine/status
```json
{ "platform":"linux", "platformLabel":"Linux", "hostname":"…", "os":"Debian GNU/Linux", "osVersion":"13 (trixie)", "distro":"debian", "kernel":"5.10.134", "arch":"x64", "user":"z", "isRoot":false,
  "adapters":[{ "platform":"linux","status":"ACTIVE" },{ "platform":"windows","status":"DESIGNED_NOT_IMPLEMENTED" },{ "platform":"macos","status":"DESIGNED_NOT_IMPLEMENTED" }],
  "engineVersion":"1.0.0", "rulesTotal":32, "rulesImplementedLinux":20, "lastScanAt":null|"ISO" }
```

## POST /api/scans  body `{ "scope": ["IDENTITY_ACCESS","…"] }` (vacío = todas)
Ejecuta auditoría → `{ "scanId":"cuid" }`

## GET /api/scans → `[{ id, startedAt, finishedAt, status, score, coverage, counts:{pass,fail,warning,notApplicable,notAssessed,error}, severityCounts:{critical,high,medium,low,info}, host:{hostname,os,osVersion} }]`

## GET /api/scans/[id] →
```json
{ "id":"…","startedAt":"…","finishedAt":"…","status":"completed","score":87.5,"coverage":92.3,
  "counts":{…},"severityCounts":{…},
  "host":{ "hostname","os","osVersion","kernel","arch","isRoot" },
  "categories":[{ "category":"IDENTITY_ACCESS","score":90.0,"coverage":100,
    "controls":[{ "id":"VC-LNX-0101","name":{"en","es"},"severity":"HIGH","status":"NOT_APPLICABLE",
      "reason":"sshd not installed","explanation":{"en","es"},"implemented":true,"evidenceSource":"/etc/ssh/sshd_config" }] }] }
```

## GET /api/scans/[id]/findings → `[{ controlId, name:{en,es}, severity, status:"FAIL"|"WARNING", category, detail, explanation:{en,es}, remediation:{...}, evidenceId }]`
## GET /api/scans/[id]/inventory → `{ os:{…}, hardware:{cpuModel,cores,memoryMB}, packages:{count}, users:[…], interfaces:[…], services:[…], listeners:[…], evidenceNotes:[…] }`
## GET /api/scans/[id]/report?format=json|csv → descarga (Content-Disposition)
## GET /api/network (último scan) → `{ fromScanId, listeners:[{proto,address,port}], interfaces:[…], firewall:{detected,active,tool}, ipForward }`
## GET /api/knowledge/articles?query=&category=&level=&platform= → `[{ slug,title:{en,es},summary:{en,es},level,category,platforms,relatedControls }]`
## GET /api/knowledge/articles/[slug] → artículo completo (21 secciones)
## GET /api/remediation/[controlId] → preview Hardening Studio del catálogo (advisory)
## GET /api/history → `[{ id, action, target?, detail?, createdAt }]`
## GET /api/overview → `{ engine:{platform,osLabel,…}, lastScan:{…}, scoreHistory:[{at,score,coverage}], categoryScores:[…], topFindings:[…], counts:{…} }`
## GET /api/settings · POST /api/settings/reset → `{ ok:true }` (audita)
