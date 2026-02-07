---
name: splunk-endpoint
description: Create a new REST endpoint for the Splunk TA. Use when adding new functionality to the admin dashboard.
metadata:
    argument-hint: "<endpoint-name>"
---

# Create Splunk REST Endpoint

Follow these steps to add a new REST endpoint to TA-FAKE-TSHRT.

## CRITICAL: Use the Right Handler Pattern

**DO NOT use `MConfigHandler` or `admin_external`** - these return 405 errors for POST requests.

**ALWAYS use `PersistentServerConnectionApplication`** with `scripttype = persist`.

## Step 1: Create Handler (bin/<name>.py)

```python
#!/usr/bin/env python3
"""
REST handler for <description>.
"""

import json
import os
import sys

# Handle Splunk imports gracefully
try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
    HAS_SPLUNK = True
except ImportError:
    HAS_SPLUNK = False
    class PersistentServerConnectionApplication:
        pass


class MyHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line, command_arg):
        if HAS_SPLUNK:
            super().__init__()

    def handle(self, in_string):
        """Main entry point for REST requests."""
        try:
            request = json.loads(in_string)
        except:
            return {'status': 400, 'payload': {'error': 'Invalid request'}}

        method = request.get('method', 'GET')
        session_key = request.get('session', {}).get('authtoken')

        # Parse form data (comes as list of [key, value] pairs)
        form_data = {}
        for item in request.get('form', []):
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                form_data[item[0]] = item[1]

        # Route by HTTP method
        if method == 'POST':
            return self.handle_post(form_data, session_key)
        elif method == 'GET':
            return self.handle_get(request, session_key)
        else:
            return {'status': 405, 'payload': {'error': f'Method {method} not allowed'}}

    def handle_get(self, request, session_key):
        """Handle GET requests."""
        return {
            'status': 200,
            'payload': {
                'info': 'Use POST to execute action',
                'available_options': ['option1', 'option2']
            }
        }

    def handle_post(self, form_data, session_key):
        """Handle POST requests."""
        try:
            # Your logic here
            result = do_something(form_data)

            return {
                'status': 200,
                'payload': {
                    'status': 'success',
                    'message': 'Operation completed',
                    'result': result
                }
            }
        except Exception as e:
            return {
                'status': 200,  # Return 200 with error in payload
                'payload': {
                    'status': 'error',
                    'error': str(e)
                }
            }
```

## Step 2: Configure restmap.conf

Add to `TA-FAKE-TSHRT/TA-FAKE-TSHRT/default/restmap.conf`:

```ini
[script:ta_fake_tshrt_myendpoint]
match = /ta_fake_tshrt/myendpoint
script = myhandler.py
scripttype = persist                    # REQUIRED for POST support
handler = myhandler.MyHandler           # Class reference
requireAuthentication = true
output_modes = json
passPayload = true
passHttpHeaders = true
passHttpCookies = true
python.version = python3
```

## Step 3: Expose to Splunk Web

Add to `TA-FAKE-TSHRT/TA-FAKE-TSHRT/default/web.conf`:

```ini
[expose:ta_fake_tshrt_myendpoint]
pattern = ta_fake_tshrt/myendpoint
methods = GET, POST
```

**Without this, the endpoint is only accessible via splunkd (port 8089), not from dashboards (port 8000).**

## Step 4: Call from JavaScript

In your dashboard JavaScript:

```javascript
require(['jquery', 'splunkjs/mvc'], function($, mvc) {
    'use strict';

    var url = Splunk.util.make_url('/splunkd/__raw/services/ta_fake_tshrt/myendpoint');

    // POST request
    $.ajax({
        url: url,
        method: 'POST',
        data: {
            param1: 'value1',
            param2: 'value2',
            output_mode: 'json'
        },
        timeout: 120000,
        success: function(response) {
            var payload = response.payload || response;
            if (payload.status === 'success') {
                console.log('Success:', payload.message);
            } else {
                console.error('Error:', payload.error);
            }
        },
        error: function(xhr, status, error) {
            console.error('Request failed:', xhr.responseText);
        }
    });
});
```

## Step 5: Restart Splunk

**Changes to restmap.conf and Python handlers require a full restart:**

```bash
$SPLUNK_HOME/bin/splunk restart
```

## Making Splunk API Calls from Handler

```python
import splunk.rest as rest

# GET request
response, content = rest.simpleRequest(
    "/services/data/indexes/myindex",
    sessionKey=session_key,
    method='GET',
    getargs={'output_mode': 'json'}
)

# POST request
response, content = rest.simpleRequest(
    "/services/data/indexes",
    sessionKey=session_key,
    method='POST',
    postargs={
        'name': 'new_index',
        'maxDataSize': 'auto_high_volume'
    }
)

if response.status == 200:
    data = json.loads(content)
```

## Running External Commands

For long-running operations, spawn a subprocess:

```python
import subprocess

cmd = ['python3', '/path/to/script.py', '--arg=value']

# Synchronous (wait for completion)
result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

# Asynchronous (return immediately)
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
# Return job_id, poll for status later
```

## Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| 405 Method Not Allowed | Using MConfigHandler | Use PersistentServerConnectionApplication |
| 401 CSRF Failed | Missing token | Use `Splunk.util.make_url()` (auto-handled) |
| Endpoint not found | Missing web.conf | Add `[expose:...]` stanza |
| Changes not reflected | Cache | Full Splunk restart |

## SimpleXML JavaScript Notes

- Splunk **strips `<script>` tags** from HTML panels
- Use external JS files: `<dashboard script="file.js">`
- Use delegated events: `$(document).on('click', '#id', fn)`
- Place JS files in `appserver/static/`
