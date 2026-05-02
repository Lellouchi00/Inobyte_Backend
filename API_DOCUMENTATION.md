# Inobyte Backend API Documentation

Base URL:

```text
http://localhost:5000
```

Run the server:

```powershell
npm start
```

Development mode:

```powershell
npm run dev
```

Health check:

```powershell
curl http://localhost:5000/
```

Expected response:

```text
API Running
```

## UI Endpoints

These endpoints match the current Visily UI screens: Dashboard, Users List, and User Details.

## Website Management

Each account can manage multiple websites. Every website has its own tracking API key.

### Create Website

```http
POST /api/websites
Authorization: Bearer JWT_TOKEN
Content-Type: application/json
```

```powershell
Invoke-RestMethod http://localhost:5000/api/websites `
  -Method Post `
  -Headers @{ Authorization = "Bearer $token" } `
  -ContentType "application/json" `
  -Body '{"domain":"https://client.com"}'
```

### List Websites

```http
GET /api/websites
Authorization: Bearer JWT_TOKEN
```

### Verify Website

```http
POST /api/websites/verify
Authorization: Bearer JWT_TOKEN
Content-Type: application/json
```

```powershell
Invoke-RestMethod http://localhost:5000/api/websites/verify `
  -Method Post `
  -Headers @{ Authorization = "Bearer $token" } `
  -ContentType "application/json" `
  -Body '{"websiteId":"WEBSITE_ID"}'
```

Website registration blocks localhost, private IPs, and domains resolving to private IP ranges.

### Visualization Dashboard

```http
GET /api/visualization/dashboard
Authorization: Bearer JWT_TOKEN
```

Optional query params:

```text
range=1h | 24h | 7d | 30d
limit=10
```

PowerShell:

```powershell
Invoke-RestMethod "http://localhost:5000/api/visualization/dashboard?range=24h&limit=10" `
  -Headers @{ Authorization = "Bearer $token" }
```

Response shape:

```json
{
  "range": "24h",
  "since": "2026-05-01T10:00:00.000Z",
  "generatedAt": "2026-05-02T10:00:00.000Z",
  "overview": {
    "securityScore": 88,
    "securityLabel": "GOOD",
    "totalEvents": 120,
    "totalAlerts": 2,
    "highAlerts": 1,
    "activeSessions": 14
  },
  "charts": {
    "eventTimeline": [
      {
        "bucket": "2026-05-02 10:00",
        "count": 12
      }
    ],
    "eventTypeBreakdown": [
      {
        "eventType": "page_view",
        "count": 80
      }
    ],
    "severityBreakdown": [
      {
        "severity": "high",
        "count": 1
      }
    ],
    "geoDistribution": [
      {
        "location": "Paris, FR",
        "count": 10
      }
    ],
    "topPages": [
      {
        "url": "https://client.com/dashboard",
        "count": 24
      }
    ]
  },
  "liveFeed": [
    {
      "id": "eventId",
      "eventType": "click",
      "url": "https://client.com/dashboard",
      "location": "Paris, FR",
      "ip": "8.8.8.8",
      "userAgent": "browser",
      "createdAt": "2026-05-02T10:00:00.000Z"
    }
  ],
  "alerts": [
    {
      "_id": "alertId",
      "message": "Brute force suspected: 21 failed login attempts in 1 minute",
      "severity": "high",
      "createdAt": "2026-05-02T10:00:00.000Z"
    }
  ]
}
```

Use this endpoint for the dashboard charts:

```text
overview.securityScore      -> score ring
overview.totalEvents        -> total activity card
overview.activeSessions     -> active sessions/users card
overview.totalAlerts        -> alerts card
charts.eventTimeline        -> activity line chart
charts.eventTypeBreakdown   -> event type chart
charts.severityBreakdown    -> alert severity chart
charts.geoDistribution      -> location chart/map list
charts.topPages             -> top pages table
liveFeed                    -> live intelligence feed
alerts                      -> recent alerts panel
```

### Dashboard

```http
GET /api/dashboard?websiteId=WEBSITE_ID
Authorization: Bearer JWT_TOKEN
```

PowerShell:

```powershell
Invoke-RestMethod "http://localhost:5000/api/dashboard?websiteId=WEBSITE_ID" `
  -Headers @{ Authorization = "Bearer $token" }
```

Response example:

```json
{
  "website": {
    "id": "websiteId",
    "domain": "client.com",
    "verified": true
  },
  "summary": {
    "totalEvents": 1284,
    "alertsToday": 4,
    "securityScore": 85,
    "riskLevel": "low"
  },
  "liveEvents": [
    {
      "id": "eventId",
      "eventType": "login",
      "data": {
        "currentUrl": "https://client.com/dashboard"
      },
      "ip": "8.8.8.8",
      "location": "Paris, France",
      "userAgent": "browser",
      "createdAt": "2026-05-02T08:00:00.000Z"
    }
  ],
  "alerts": [
    {
      "id": "alertId",
      "message": "Brute force suspected: 21 failed login attempts in 1 minute",
      "severity": "high",
      "timestamp": "2026-05-02T08:00:00.000Z"
    }
  ],
  "charts": {
    "eventsOverTime": [
      {
        "time": "14:00",
        "count": 32
      }
    ],
    "alertsBySeverity": [
      {
        "severity": "high",
        "count": 5
      }
    ]
  }
}
```

### Socket.IO Realtime

Connect with the same JWT used for REST APIs:

```js
const socket = io("http://localhost:5000", {
  auth: {
    token
  }
});

socket.on("connected", (payload) => {
  console.log("connected", payload.userId);
});

socket.on("new_event", (event) => {
  console.log("new event", event);
});

socket.on("new_alert", (alert) => {
  console.log("new alert", alert);
});
```

Server behavior:

```text
JWT is verified during socket connection.
Each socket joins a private room named with userId.
New events emit: new_event
New alerts emit: new_alert
Users only receive their own room events.
Events and alerts are scoped by userId and websiteId.
```

Realtime payload examples:

```json
{
  "id": "eventId",
  "eventType": "click",
  "data": {
    "currentUrl": "https://client.com/dashboard"
  },
  "ip": "8.8.8.8",
  "location": "Paris, FR",
  "userAgent": "browser",
  "createdAt": "2026-05-02T08:00:00.000Z"
}
```

```json
{
  "id": "alertId",
  "message": "Rate abuse suspected: 501 events received in 1 minute",
  "severity": "medium",
  "timestamp": "2026-05-02T08:00:00.000Z"
}
```

Dashboard score logic:

```text
Starts at 100.
High alert   = -15
Medium alert = -10
Low alert    = -5

>= 80 => low risk
>= 60 => medium risk
< 60  => high risk
```
    }
  ]
}
```

### Users List

```http
GET /api/users
Authorization: Bearer JWT_TOKEN
```

Optional query params:

```text
search=paris
status=all | active | idle | inactive
flagged=true | false
```

PowerShell:

```powershell
Invoke-RestMethod "http://localhost:5000/api/users?status=all" `
  -Headers @{ Authorization = "Bearer $token" }
Invoke-RestMethod "http://localhost:5000/api/users?search=Paris" `
  -Headers @{ Authorization = "Bearer $token" }
Invoke-RestMethod "http://localhost:5000/api/users?flagged=true" `
  -Headers @{ Authorization = "Bearer $token" }
```

Response example:

```json
{
  "totalScope": 7,
  "critical": 2,
  "monitoring": 2,
  "users": [
    {
      "id": "userId",
      "email": "user@example.com",
      "apiKey": "sk_xxx",
      "displayName": "User ••4821",
      "location": "Paris, FR",
      "status": "active",
      "flagged": true,
      "riskLevel": "review",
      "totalEvents": 12,
      "flaggedEvents": 2,
      "firstSeen": "2026-05-01T08:00:00.000Z",
      "firstSeenLabel": "May 1",
      "lastSeen": "2026-05-02T08:00:00.000Z",
      "lastSeenLabel": "Today",
      "lastActive": "3m ago"
    }
  ]
}
```

### User Details

```http
GET /api/users/:identifier
Authorization: Bearer JWT_TOKEN
```

PowerShell:

```powershell
Invoke-RestMethod "http://localhost:5000/api/users/sk_your_api_key" `
  -Headers @{ Authorization = "Bearer $token" }
Invoke-RestMethod "http://localhost:5000/api/users/USER_MONGO_ID" `
  -Headers @{ Authorization = "Bearer $token" }
```

Response example:

```json
{
  "id": "userId",
  "email": "user@example.com",
  "apiKey": "sk_xxx",
  "displayName": "User ••4821",
  "location": "Paris, France",
  "status": "active",
  "flagged": true,
  "riskLevel": "review",
  "totalEvents": 5,
  "flaggedEvents": 2,
  "firstSeenLabel": "Oct 12",
  "lastSeenLabel": "Today",
  "lastActive": "2m ago",
  "eventHistory": [
    {
      "id": "eventId",
      "apiKey": "sk_xxx",
      "title": "Unusual login from new device",
      "eventType": "unusual_login",
      "location": "Paris, FR",
      "flagged": true,
      "severity": "critical",
      "time": "14:22",
      "relativeTime": "2m ago"
    }
  ],
  "riskAssessment": {
    "level": "moderate",
    "summary": "This user has flagged activity and should be reviewed before being cleared."
  }
}
```

## Auth Flow

### Register

```http
POST /api/auth/register
Content-Type: application/json
```

Body:

```json
{
  "email": "user@example.com",
  "password": "12345678"
}
```

PowerShell:

```powershell
Invoke-RestMethod http://localhost:5000/api/auth/register `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"email":"user@example.com","password":"12345678"}'
```

### Verify OTP

```http
POST /api/auth/verify-otp
Content-Type: application/json
```

Body:

```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

### Login

```http
POST /api/auth/login
Content-Type: application/json
```

Body:

```json
{
  "email": "user@example.com",
  "password": "12345678"
}
```

Response:

```json
{
  "token": "jwt_token",
  "apiKey": "sk_generated_key",
  "expiresIn": "7d"
}
```

Use `apiKey` to send tracking events and to open user details.

## Tracking Events For UI Data

The UI screens are populated from websites and events. Send events with the website `apiKey` returned by `POST /api/websites`.

Embed the browser tracker:

```html
<script>
  window.INOBYTE_API_KEY = "sk_website_api_key";
</script>
<script src="http://localhost:5000/tracker.js"></script>
```

In production, replace the script domain:

```html
<script src="https://mydomain.com/tracker.js"></script>
```

The SDK automatically sends:

```text
page_view
click
```

Each event includes:

```text
currentUrl
timestamp
userAgent
```

```http
POST /api/events/track
Content-Type: application/json
```

Normal event:

```powershell
Invoke-RestMethod http://localhost:5000/api/events/track `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"apiKey":"sk_your_api_key","eventType":"login","data":{"title":"New login from Paris, France","location":"Paris, FR"}}'
```

Flagged event:

```powershell
Invoke-RestMethod http://localhost:5000/api/events/track `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"apiKey":"sk_your_api_key","eventType":"unusual_login","data":{"title":"Unusual login from new device","location":"Paris, FR","flagged":true,"severity":"critical"}}'
```

Useful `data` fields for the UI:

```json
{
  "title": "Event title shown in UI",
  "message": "Alternative event title",
  "location": "Paris, FR",
  "city": "Paris",
  "country": "FR",
  "flagged": true,
  "severity": "critical"
}
```

Tracking response:

```json
{
  "message": "Event saved",
  "eventId": "eventId",
  "location": "Paris, FR",
  "alerts": []
}
```

Detection rules:

```text
Impossible Travel = login/login_success from different countries within 2 hours
Brute Force       = more than 20 failed_login events in 1 minute
Rate Abuse        = more than 500 events for one apiKey in 1 minute
```

Security protections:

```text
API key is validated against registered users
Tracking route has rate limiting
Private and localhost IPs are ignored for GeoIP
The event endpoint does not fetch user-provided URLs, which avoids SSRF in tracking
Payload size is limited
```

## Status Rules

User status is calculated from the latest event:

```text
active   = last event within 15 minutes
idle     = last event within 24 hours
inactive = no events or older than 24 hours
```

A user is flagged when one of their events has:

```text
data.flagged = true
```

or the event type/severity contains:

```text
alert, critical, failed, flagged, suspicious, unusual, risk
```

## Website Security Scan

This endpoint performs a passive website security scan. It checks DNS resolution, HTTPS usage, TLS certificate information, HTTP status, HTTP-to-HTTPS redirect, and common security headers.

It does not run exploit attempts, password attacks, or aggressive vulnerability probing.

```http
POST /api/scans
Authorization: Bearer JWT_TOKEN
Content-Type: application/json
```

Body:

```json
{
  "url": "https://example.com"
}
```

PowerShell:

```powershell
$token = "PASTE_LOGIN_TOKEN_HERE"

Invoke-RestMethod http://localhost:5000/api/scans `
  -Method Post `
  -Headers @{ Authorization = "Bearer $token" } `
  -ContentType "application/json" `
  -Body '{"url":"https://example.com"}'
```

Response shape:

```json
{
  "_id": "scanId",
  "userId": "userId",
  "url": "https://example.com/",
  "status": "completed",
  "results": {
    "target": {
      "input": "https://example.com",
      "normalizedUrl": "https://example.com/",
      "hostname": "example.com"
    },
    "score": 79,
    "riskLevel": "medium",
    "standards": {
      "frameworkMode": "alignedWith",
      "note": "These mappings show design alignment with OWASP SAMM and CIS Controls. They do not represent formal compliance certification.",
      "controlsCovered": [
        "DNS_RESOLUTION",
        "HTTPS_REQUIRED",
        "TLS_CERTIFICATE",
        "HTTPS_REDIRECT",
        "SECURITY_HEADERS",
        "HTTP_AVAILABILITY"
      ]
    },
    "checks": {
      "dns": {
        "resolves": true,
        "addresses": [],
        "standards": {
          "frameworkMode": "alignedWith"
        }
      },
      "https": {
        "enabled": true
      },
      "http": {
        "statusCode": 200,
        "finalUrl": "https://example.com/",
        "server": "cloudflare",
        "poweredBy": null
      },
      "redirect": {
        "checked": true,
        "statusCode": 301,
        "location": "https://example.com/",
        "redirectsToHttps": true
      },
      "tls": {
        "available": true,
        "authorized": true,
        "issuer": "Google Trust Services",
        "subject": "example.com",
        "validFrom": "2026-01-01T00:00:00.000Z",
        "validTo": "2026-04-01T00:00:00.000Z",
        "daysUntilExpiry": 30
      },
      "headers": {
        "present": {
          "strict-transport-security": "max-age=31536000"
        },
        "missing": [
          {
            "header": "content-security-policy",
            "label": "Content Security Policy"
          }
        ]
      }
    },
    "alerts": [
      {
        "message": "Content Security Policy header is missing",
        "severity": "medium",
        "standards": {
          "frameworkMode": "alignedWith"
        }
      }
    ]
  }
}
```

Security standards rule:

```text
All cybersecurity checks and generated alerts include standards alignment metadata.
Current targets: OWASP SAMM and CIS Controls v8.
This is alignment metadata, not a formal compliance certificate.
```
