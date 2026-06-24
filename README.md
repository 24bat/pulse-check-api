# Pulse Check API — Dead Man's Switch 🔴

A backend service that monitors remote devices using a **Dead Man's Switch** pattern. Devices register with a countdown timer and must send periodic heartbeats. If a device goes silent and the timer expires, the system automatically fires an alert.

Built with **Python** and **Flask**. Secured with API key authentication, rate limiting, and input sanitization.

---

## Architecture Diagram

### System Overview

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                     PULSE CHECK API                             │
 │                                                                 │
 │  ┌─────────────┐     ┌──────────────────────┐                  │
 │  │ Solar farm  │     │   SECURITY LAYER      │                  │
 │  │ device-001  │────>│  API Key · Rate Limit │──> 401/403/429   │
 │  └─────────────┘     │  Input Sanitization   │                  │
 │  ┌─────────────┐     └──────────┬───────────┘                  │
 │  │   Weather   │                │                               │
 │  │   station   │────>           │                               │
 │  └─────────────┘     ┌──────────▼───────────┐                  │
 │  ┌─────────────┐     │    FLASK API ROUTES   │                  │
 │  │   Remote    │     │  POST /monitors       │                  │
 │  │   sensor    │────>│  POST /heartbeat      │                  │
 │  └─────────────┘     │  POST /pause          │                  │
 │   POST /heartbeat     │  GET  /monitors/{id}  │                  │
 │                       └──────────┬───────────┘                  │
 │                                  │ read/write                   │
 │                       ┌──────────▼───────────┐                  │
 │                       │   IN-MEMORY STORE     │                  │
 │                       │  monitors { }         │                  │
 │                       │  id · status          │                  │
 │                       │  deadline · history   │                  │
 │                       └──────────┬───────────┘                  │
 │                                  │ polls every 1s               │
 │                       ┌──────────▼───────────┐                  │
 │                       │  WATCHDOG SCHEDULER   │                  │
 │                       │  daemon thread        │                  │
 │                       │  checks deadlines     │                  │
 │                       └──────────┬───────────┘                  │
 │                                  │ timer expired                │
 │                       ┌──────────▼───────────┐                  │
 │                       │     ALERT FIRED       │                  │
 │                       │  status → "down"      │                  │
 │                       │  🚨 console.log JSON  │                  │
 └───────────────────────┴──────────────────────┘                  
```

### Monitor State Machine

```
                    POST /monitors
                         │
                         ▼
                   ┌─────────────┐
                   │   ACTIVE    │◄──────────────┐
                   │  counting   │               │
                   └──────┬──────┘               │
                          │                      │
          ┌───────────────┼───────────────┐      │
          │               │               │      │
          ▼               ▼               ▼      │
   heartbeat         timer = 0        POST /pause│
   received          no heartbeat               │
          │               │               │      │
          ▼               ▼               ▼      │
   timer reset       ┌─────────┐    ┌──────────┐│
   200 OK            │  DOWN   │    │  PAUSED  ││
                     │  alert  │    │ no alerts││
                     │  fired  │    └─────┬────┘│
                     └─────────┘          │      │
                                    heartbeat    │
                                    received     │
                                          └──────┘
```

### Sequence Diagram

```
  Device          Security Layer      Flask API       Watchdog
    │                   │                │               │
    │  POST /monitors   │                │               │
    │──────────────────>│                │               │
    │  check API key    │                │               │
    │  check rate limit │                │               │
    │  sanitize input   │                │               │
    │                   │─── pass ──────>│               │
    │                   │    201 Created │               │
    │<──────────────────────────────────│               │
    │                   │                │  start timer  │
    │                   │                │──────────────>│
    │                   │                │               │ checks every 1s
    │  POST /heartbeat  │                │               │
    │──────────────────>│────────────────>│               │
    │                   │    200 OK      │  reset timer  │
    │<──────────────────────────────────│──────────────>│
    │                   │                │               │
    │  [goes silent...] │                │               │
    │                   │                │         timer expires
    │                   │                │               │
    │                   │                │<── ALERT ─────│
    │                   │           status = "down"      │
    │                   │          🚨 console.log        │
```

---

## Setup Instructions

### Prerequisites
- Python 3.8 or higher
- pip

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/pulse-check-api.git
cd pulse-check-api
```

### 2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate        # Mac/Linux
venv\Scripts\activate           # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Start the server
```bash
python main.py
```

Server runs on **http://localhost:5000**

---

## Security

Every request must include the API key header:

```
X-API-Key: supersecretkey123
```

| Feature | Description |
|---|---|
| API Key Auth | Requests without a valid key return `401` or `403` |
| Rate Limiting | Max 30 requests per 60 seconds per IP — returns `429` |
| Input Sanitization | Blocks special characters in input fields — prevents injection attacks |

---

## API Documentation

**Base URL:** `http://localhost:5000`

**Required header on all requests:** `X-API-Key: supersecretkey123`

---

### `POST /monitors` — Register a monitor

**Request:**
```json
{
  "id": "device-123",
  "timeout": 60,
  "alert_email": "admin@critmon.com"
}
```

**Response `201 Created`:**
```json
{
  "message": "Monitor for 'device-123' registered successfully.",
  "id": "device-123",
  "timeout": 60,
  "status": "active",
  "deadline": "2025-06-19T10:10:00Z"
}
```

---

### `POST /monitors/{id}/heartbeat` — Reset the timer

**Response `200 OK`:**
```json
{
  "message": "Heartbeat received for 'device-123'. Timer reset.",
  "status": "active",
  "new_deadline": "2025-06-19T10:11:00Z"
}
```

**Response `404`:** Device not found  
**Response `409`:** Device already down

---

### `POST /monitors/{id}/pause` — Pause monitoring

Stops the countdown. No alerts will fire. Send a heartbeat to resume.

**Response `200 OK`:**
```json
{
  "message": "Monitor 'device-123' is now paused. No alerts will fire.",
  "status": "paused"
}
```

---

### `GET /monitors/{id}` — Get status and history *(Developer's Choice)*

**Response `200 OK`:**
```json
{
  "id": "device-123",
  "status": "active",
  "timeout": 60,
  "seconds_remaining": 42.5,
  "history": [
    { "event": "Monitor registered with timeout=60s", "timestamp": "2025-06-19T10:09:00Z" },
    { "event": "Heartbeat received — timer reset", "timestamp": "2025-06-19T10:09:18Z" }
  ]
}
```

---

### `GET /monitors` — List all monitors

**Response `200 OK`:**
```json
{
  "total": 2,
  "monitors": [
    { "id": "device-123", "status": "active", "seconds_remaining": 42.5 },
    { "id": "solar-7", "status": "down", "seconds_remaining": null }
  ]
}
```

---

### `DELETE /monitors/{id}` — Delete a monitor

**Response `200 OK`:**
```json
{ "message": "Monitor 'device-123' has been deleted." }
```

---

### Alert output (when timer expires)

Fired automatically to the terminal when a device goes silent:

```json
{
  "ALERT": "Device device-123 is down!",
  "time": "2025-06-19T10:10:00Z",
  "alert_email": "admin@critmon.com"
}
```

---

## Developer's Choice: Event History Log

### What I added
A `GET /monitors/{id}` endpoint that returns the complete **event history** of any monitor — every registration, heartbeat, pause, resume, and alert, each with a precise UTC timestamp.

### Why I added it
The original spec defines a system that fires alerts but provides no way to inspect what actually happened to a device over time. In a real infrastructure monitoring tool, this is a critical gap:

- How do you know when a device last sent a heartbeat?
- How do you verify an alert actually fired?
- How do you audit a device's behaviour during an incident?

Without history, the API is a black box. The event log turns it into an **observable system** — engineers can trace exactly what happened, when, and in what order. This is a foundational principle in backend engineering: **observability**. You cannot debug what you cannot see.

---

## Project Structure

```
pulse-check-api/
├── main.py           # Entire application — server, store, scheduler, routes
├── requirements.txt  # Python dependencies (Flask)
├── .gitignore        # Excludes venv, .env, __pycache__
└── README.md         # This file
```

---

## Pre-submission Checklist

- [x] `POST /monitors` — register with timeout ✅
- [x] `POST /monitors/{id}/heartbeat` — reset timer ✅
- [x] Alert fires when timer expires ✅
- [x] `POST /monitors/{id}/pause` — snooze button ✅
- [x] Developer's Choice — event history log ✅
- [x] API Key Authentication ✅
- [x] Rate Limiting ✅
- [x] Input Sanitization ✅
- [x] Architecture diagram in README ✅
- [x] API documentation with example requests ✅
