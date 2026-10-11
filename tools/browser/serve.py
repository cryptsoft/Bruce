# serve.py -- serve the browser check and collect its result.
#
# The check needs a real browser, and a real browser needs a human: Chrome
# runs the ceremony but then blocks on its own security-key dialog, which
# is browser UI. Automation cannot reach it -- CDP input does not apply to
# it, and macOS refuses osascript assistive access. Tried, measured, and
# that is the boundary.
#
# What this does remove is the *reporting* step. Open the page with
# ?auto=1 and it starts by itself and POSTs its results back here, so
# nobody has to read a screen and retype what it said.
#
#   python3 tools/browser/serve.py tools/browser 8765 /tmp/result.json
#   open 'http://localhost:8765/largeblob-check.html?auto=1'
#
# SPDX-License-Identifier: Apache-2.0
import http.server, os, sys, json
ROOT = sys.argv[1]; PORT = int(sys.argv[2]); OUT = sys.argv[3]

class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n)
        with open(OUT, 'wb') as f:
            f.write(body)
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass

http.server.HTTPServer(('127.0.0.1', PORT), H).serve_forever()
