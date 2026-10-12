import urllib.request, json

def post(path, body):
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        "http://localhost:5000" + path, data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    r = urllib.request.urlopen(req)
    return json.loads(r.read())

print("=" * 60)
print("  LIVE API TESTS -- ScamGuard AI")
print("=" * 60)

tests = [
    ("Phishing Email",
     "/api/v1/analyze",
     {"content": "URGENT! Your PayPal account expires in 2 HOURS! Verify now or lose access FOREVER! Click: http://paypal-verify.xyz.tk/login", "source": "email"}),
    ("Financial Scam",
     "/api/v1/analyze",
     {"content": "GUARANTEED 500% returns on Bitcoin in 48 hours! No risk! Only 3 slots left, invest NOW!", "source": "chat"}),
    ("Fake Emergency",
     "/api/v1/analyze",
     {"content": "Mom I got arrested! I need 500 dollars in gift cards right now. Do not tell Dad please hurry!", "source": "sms"}),
    ("Crypto Pump",
     "/api/v1/analyze",
     {"content": "Buy this coin before it moons tonight! Insider tip, price will skyrocket in 2 hours!", "source": "chat"}),
    ("Legitimate Email",
     "/api/v1/analyze",
     {"content": "Hi, just a reminder about our team meeting tomorrow at 10am. Let me know if you can make it.", "source": "email"}),
    ("Email Endpoint",
     "/api/v1/analyze/email",
     {"subject": "URGENT: Account Suspended", "body": "Your account will be closed in 24 hours. Verify immediately.", "sender": "alert@suspicious.xyz"}),
    ("URL Endpoint",
     "/api/v1/analyze/url",
     {"url": "http://192.168.1.1/paypal-login-verify"}),
]

icons = {"safe": "OK", "low": "LOW", "medium": "MED", "high": "HIGH", "critical": "CRIT"}

for name, path, body in tests:
    try:
        d = post(path, body)
        risk = d.get("risk_level", "?")
        tag  = icons.get(risk, "?")
        scam_label = "SCAM" if d.get("is_scam") else "CLEAN"
        score = d.get("overall_score", 0)
        ms    = d.get("processing_time_ms", 0)
        print("  [%s] %-20s | %-5s | score=%.3f | risk=%-8s | %.1fms" % (
            tag, name, scam_label, score, risk.upper(), ms))
    except Exception as e:
        print("  [ERR] %-20s | %s" % (name, e))

# Stats
r = urllib.request.urlopen("http://localhost:5000/api/v1/stats")
s = json.loads(r.read())
print()
print("  Stats: %d analyzed | %d scams | detection rate=%s%%" % (
    s.get("total_analyzed", 0), s.get("scams_detected", 0), s.get("detection_rate", 0)))
print("=" * 60)
print("  Dashboard running at: http://localhost:5000")
print("=" * 60)
