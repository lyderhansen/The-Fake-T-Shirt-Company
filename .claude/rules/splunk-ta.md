---
paths:
  - "TA-FAKE-TSHRT/TA-FAKE-TSHRT/**"
---

# Splunk TA Development Rules

These rules apply when working on the TA-FAKE-TSHRT Splunk app.

## REST Endpoints - CRITICAL

**NEVER use `MConfigHandler` or `admin_external`** - they return 405 errors for POST.

**ALWAYS use this pattern:**

```python
from splunk.persistconn.application import PersistentServerConnectionApplication

class MyHandler(PersistentServerConnectionApplication):
    def handle(self, in_string):
        request = json.loads(in_string)
        method = request.get('method', 'GET')
        # ... handle request
```

## restmap.conf Configuration

Required settings for POST support:

```ini
[script:endpoint_name]
match = /app/endpoint
script = handler.py
scripttype = persist           # REQUIRED
handler = handler.ClassName    # REQUIRED
requireAuthentication = true
output_modes = json
passPayload = true
python.version = python3
```

## web.conf - Expose to Dashboards

Without this, endpoints are only accessible via splunkd (8089):

```ini
[expose:endpoint_name]
pattern = app/endpoint
methods = GET, POST
```

## SimpleXML JavaScript

1. **Never use inline `<script>` tags** - Splunk strips them
2. Use external JS: `<dashboard script="file.js">`
3. Place files in `appserver/static/`
4. Use delegated events: `$(document).on('click', '#id', fn)`

## AJAX Calls

```javascript
var url = Splunk.util.make_url('/splunkd/__raw/services/app/endpoint');
$.ajax({ url: url, method: 'POST', data: {...} });
```

## After Changes

**Restart Splunk** for restmap.conf and handler changes:

```bash
$SPLUNK_HOME/bin/splunk restart
```
