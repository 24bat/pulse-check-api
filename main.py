# Pulse Check API (Dead Man's Switch)


# flask is the web framework — it creates the web server and handles HTTP requests

from flask import Flask, request, jsonify

# datetime = lets us work with dates and times (e.g. "right now")
# timedelta = lets us add/subtract time (e.g. "now + 60 seconds")
from datetime import datetime, timedelta

# threading = lets us run code in the background without blocking the API

import threading

# logging = Python's built-in way to write structured log messages to the terminal
# because it includes timestamps and severity levels (INFO, WARNING, CRITICAL)
import logging

# re = regular expressions module — used to search strings for patterns
# We use it to detect dangerous/invalid characters in user input
import re

# defaultdict = a special dictionary that auto-creates a default value for missing keys
# We use it for the rate tracker so we don't have to manually create entries per IP
from collections import defaultdict


# LOGGING SETUP
# Configures how log messages appear in the terminal


# basicConfig sets the global logging settings for the whole app
logging.basicConfig(
    level=logging.INFO,                               # show INFO level messages and above (INFO, WARNING, ERROR, CRITICAL)
    format="%(asctime)s [%(levelname)s] %(message)s"  # format: "2025-06-19 10:00:00 [INFO] message"
)

# Create a named logger specifically for this app
# This way log messages are tagged with "pulse-check-api" as the source
logger = logging.getLogger("pulse-check-api")



# SECURITY CONFIG



# The API key that every request must include in the header: X-API-Key: supersecretkey123

API_KEY = "supersecretkey123"

# Maximum number of requests any single IP address can make within RATE_WINDOW seconds
RATE_LIMIT = 30  # 30 requests allowed per window

# The time window (in seconds) for rate limiting — resets after this many seconds
RATE_WINDOW = 60  # 60 second window (1 minute)

# Dictionary that tracks request counts per IP address
# defaultdict means if an IP is seen for the first time, it auto-creates {"count": 0, "window_start": now}

rate_tracker = defaultdict(lambda: {"count": 0, "window_start": datetime.utcnow()})

# A lock to safely read/write rate_tracker across multiple threads
# Without this, two simultaneous requests could corrupt the count
rate_lock = threading.Lock()



# SECURITY FUNCTIONS



def check_api_key():
    """
    Checks that the incoming HTTP request has the correct API key.
    The client must include this header: X-API-Key: supersecretkey123
    Returns an error response tuple if the key is missing or wrong.
    Returns None if the key is valid — meaning "all good, continue".
    """

    # request.headers is a dictionary of all HTTP headers sent with the request

    key = request.headers.get("X-API-Key")

    # If the header was not included at all, reject with 401 Unauthorized
    if not key:
        # Log a warning so we can see rejected attempts in the terminal
        logger.warning(f"Rejected request — no API key from {request.remote_addr}")
        # Return a JSON error response with HTTP status 401
        return jsonify({"error": "Missing API key. Include X-API-Key header."}), 401

    # If a key was provided but it doesn't match our expected key, reject with 403 Forbidden
    if key != API_KEY:
        # Log the rejected attempt with the offending IP address
        logger.warning(f"Rejected request — wrong API key from {request.remote_addr}")
        # Return a JSON error response with HTTP status 403
        return jsonify({"error": "Invalid API key."}), 403

    # If we reach here, the key is valid, return None to signal success
    return None


def check_rate_limit():
    """
    Enforces a rate limit per IP address.
    Each IP is allowed RATE_LIMIT (30) requests per RATE_WINDOW (60) seconds.
    If exceeded, returns a 429 Too Many Requests response.
    Returns None if under the limit — meaning "all good, continue".
    """

    # request.remote_addr gives us the IP address of whoever sent this request
    ip = request.remote_addr


    # "with store_lock" means: acquire the lock, run the block, then release it
    with rate_lock:

        # Get the rate tracking record for this IP (auto-created if first visit)
        tracker = rate_tracker[ip]

        # Get the current UTC time to compare against the window start
        now = datetime.utcnow()

        # Calculate how many seconds have passed since this IP's window started
        window_age = (now - tracker["window_start"]).total_seconds()

        # If the window has expired (more than RATE_WINDOW seconds old), reset it
        if window_age > RATE_WINDOW:
            tracker["count"] = 0           # reset the request count back to zero
            tracker["window_start"] = now  # start a fresh window from right now

        # Increment the request count for this IP by 1
        tracker["count"] += 1

        # If the count has exceeded the allowed limit, block this request
        if tracker["count"] > RATE_LIMIT:
            # Log the rate limit violation with the IP and current count
            logger.warning(f"Rate limit exceeded by {ip} ({tracker['count']} requests)")
            # Return a 429 Too Many Requests response with a helpful error message
            return jsonify({
                "error": f"Rate limit exceeded. Max {RATE_LIMIT} requests per {RATE_WINDOW}s."
            }), 429

    # If we got here, the IP is under the limit — return None to signal success
    return None


def sanitize_string(value: str, field_name: str):
    """
    Checks a string for dangerous characters that could be used in injection attacks.
    Only allows: letters, numbers, hyphens, underscores, dots, @ signs, spaces.
    Blocks: angle brackets, quotes, semicolons, and other special characters.
    Returns an error response if dangerous input is found, None if the input is clean.
    """

    # Define a regex pattern that matches any character that is NOT allowed
    # [^...] means "NOT any of these characters"
    # a-zA-Z = letters, 0-9 = digits, \-_\.@ = hyphen/underscore/dot/at, \s = spaces
    pattern = r"[^a-zA-Z0-9\-_\.@\s]"

    # re.search scans the entire string for any character matching the pattern
    # If it finds one, the input contains a dangerous character
    if re.search(pattern, str(value)):
        # Log the suspicious input so we can see it in the terminal
        logger.warning(f"Suspicious input in field '{field_name}': {value}")
        # Return a 400 Bad Request response explaining what went wrong
        return jsonify({
            "error": f"Invalid characters in field '{field_name}'. Only letters, numbers, hyphens, underscores, dots and @ are allowed."
        }), 400

    # Input is clean, return None to signal success
    return None


def run_security_checks(sanitize_fields=None):
    """
    Master security function that runs ALL three checks in order:
    1. API Key check
    2. Rate limit check
    3. Input sanitization (only if field values are passed in)

    sanitize_fields = optional dict of { "field_name": "value" } to sanitize
    Returns the first error response it finds, or None if all checks pass.
    """

    # Run check 1: API Key, if it fails, return the error immediately
    err = check_api_key()
    if err:
        return err  # stop here, don't run the other checks

    # Run check 2: Rate Limiting, if it fails, return the error immediately
    err = check_rate_limit()
    if err:
        return err  # stop here

    # Run check 3: Input Sanitization, only if fields were passed in
    if sanitize_fields:
        # Loop through each field name and its value
        for field_name, value in sanitize_fields.items():
            # Sanitize this specific field
            err = sanitize_string(value, field_name)
            if err:
                return err  # stop here if any field is dangerous

    # All checks passed, return None to signal "safe to proceed"
    return None


# IN-MEMORY STORE


# monitors is the main dictionary storing all registered devices
# Key = device ID string (e.g. "device-123")

monitors = {}

# A lock to safely read/write monitors across multiple threads
# The scheduler thread and the API thread both access monitors and the lock keeps them in sync
store_lock = threading.Lock()


def add_history(device_id: str, event: str):
    """
    Appends a new timestamped event to a device's history log.
    Called every time something notable happens to a monitor.
    This is the Developer's Choice feature, Full audit trail.

    """

    # Only log if the device actually exists in our store
    if device_id in monitors:
        # Append a new dictionary to the device's history list
        monitors[device_id]["history"].append({
            "event": event,                                    # what happened
            "timestamp": datetime.utcnow().isoformat() + "Z"  # when it happened in UTC ISO format
        })



# WATCHDOG SCHEDULER
# This is the heart of the Dead Man's Switch
# It runs in the background every second, checking timers


def check_monitors():
    """
    Called every 1 second by the background loop.
    Loops through ALL registered monitors and checks:
    "Has any active monitor's timer expired without a heartbeat?"
    If yes, fires the alert and marks the device as DOWN.
    """

    # Get the exact current UTC time to compare against deadlines
    now = datetime.utcnow()

    # Acquire the store lock before reading/writing the monitors dictionary
    with store_lock:

        # Loop through every device ID and its monitor data
        for device_id, monitor in monitors.items():

            # Only check monitors that are actively counting down
            # Skip anything already "down" or "paused" — nothing to do
            if monitor["status"] != "active":
                continue  # skip this device and move to the next one

            # Compare the current time against the device's deadline
            # If now has passed the deadline, the device missed its heartbeat
            if now >= monitor["deadline"]:

                # Mark this device as DOWN so the alert doesn't fire twice
                monitor["status"] = "down"

                # Build the alert JSON object — exactly as specified in the brief
                alert = {
                    "ALERT": f"Device {device_id} is down!",        # the alert message
                    "time": now.isoformat() + "Z",                   # current timestamp in ISO format
                    "alert_email": monitor.get("alert_email", "N/A") # who should be notified
                }

                # Log this as a CRITICAL level message — highest severity
                # In a real system this would trigger an email, SMS, or webhook
                logger.critical(alert)

                # Also print it clearly to the terminal so it's impossible to miss
                print(f"\n🚨 ALERT FIRED: {alert}\n")

                # Record this alert event in the device's history log
                add_history(device_id, "ALERT_FIRED — device went down")


def start_scheduler():
    """
    Starts the background watchdog loop.
    Uses a recursive threading.Timer to call check_monitors() every 1 second.
    The function schedules itself again after each run — creating an infinite loop.
    daemon=True means the thread dies automatically when the main app stops.
    """

    def loop():
        # Call the actual check function to inspect all monitors
        check_monitors()

        # Create a new timer that will call this same loop() function again in 1.0 seconds
        # This is the recursive pattern that keeps the watchdog running forever
        t = threading.Timer(1.0, loop)

        # daemon=True means this thread is a background thread
        # It will automatically stop when the main Flask process exits (e.g. Ctrl+C)
        t.daemon = True

        # Start the timer — it will fire in 1 second
        t.start()

    # Call loop() once to kick off the very first iteration
    loop()

    # Log that the scheduler has started successfully
    logger.info("Watchdog scheduler started — checking every 1 second")



# FLASK APP yk to Creates the web server and defines all URL endpoints


# Create the Flask application instance
# __name__ tells Flask where the application is located
app = Flask(__name__)


# A simple health check — visiting http://localhost:5000/ shows the API is running
@app.route("/")  # this decorator maps the "/" URL to the index() function below
def index():
    # Return a JSON object listing the service info and available endpoints
    return jsonify({
        "service": "Pulse Check API — Dead Man's Switch",  # name of the service
        "status": "running",                                # confirms the server is alive
        "security": ["API Key Auth", "Rate Limiting", "Input Sanitization"],  # active security features
        "endpoints": [                                      # list of all available routes
            "POST   /monitors",
            "POST   /monitors/<id>/heartbeat",
            "POST   /monitors/<id>/pause",
            "GET    /monitors/<id>",
            "GET    /monitors",
            "DELETE /monitors/<id>"
        ]
    }), 200  # 200 = HTTP OK


# ENDPOINT 1: POST /monitors
# Registers a new device and starts its countdown timer

@app.route("/monitors", methods=["POST"])  # only responds to POST requests at /monitors
def register_monitor():

    # Parse the JSON body from the incoming HTTP request
    # Returns None if the Content-Type header is not application/json or body is empty
    data = request.get_json()

    # If no JSON body was provided, return a 400 Bad Request error
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    # Extract each required field from the parsed JSON dictionary
    device_id   = data.get("id")           # the unique device identifier
    timeout     = data.get("timeout")      # how many seconds the countdown lasts
    alert_email = data.get("alert_email")  # email address to notify on alert

    # Validate that all three required fields are present
    if not device_id or timeout is None or not alert_email:
        # Return 400 with a message telling the client exactly what's missing
        return jsonify({"error": "Missing required fields: id, timeout, alert_email"}), 400

    # Validate that timeout is a positive number (can't countdown from -5 or "abc")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        return jsonify({"error": "timeout must be a positive number"}), 400

    # Run all security checks, passing id and alert_email for sanitization
    # If any check fails, err will be a tuple (response, status_code) — return it immediately
    err = run_security_checks(sanitize_fields={"id": device_id, "alert_email": alert_email})
    if err:
        return err  # blocked by security

    # Acquire the store lock before writing to the monitors dictionary
    with store_lock:

        # Calculate the deadline: current UTC time + timeout seconds
        # e.g. if timeout=60, deadline = now + 60 seconds from right now
        deadline = datetime.utcnow() + timedelta(seconds=timeout)

        # Create the monitor entry and store it in the monitors dictionary
        monitors[device_id] = {
            "timeout":     timeout,                              
            "alert_email": alert_email,                         
            "status":      "active",                           
            "deadline":    deadline,                           
            "created_at":  datetime.utcnow().isoformat() + "Z", 
            "history":     []                                   
        }

        # Record the registration event in the device's history log
        add_history(device_id, f"Monitor registered with timeout={timeout}s")

    # Return a 201 Created response confirming the monitor was registered
    return jsonify({
        "message":     f"Monitor for '{device_id}' registered successfully.",
        "id":          device_id,    
        "timeout":     timeout,     
        "alert_email": alert_email,  
        "status":      "active",     
        "deadline":    deadline.isoformat() + "Z" 
    }), 201  # 201 = HTTP Created


# ENDPOINT 2
# The device calls this to prove it's still alive — resets the countdown
@app.route("/monitors/<device_id>/heartbeat", methods=["POST"])
def heartbeat(device_id):  # device_id is passed in automatically from the URL

    # Run security checks, no body fields to sanitize on a heartbeat
    err = run_security_checks()
    if err:
        return err  # 

    # Acquire the store lock before reading/writing monitor data
    with store_lock:

        # Check if a monitor with this device ID actually exists
        if device_id not in monitors:
            # Return 404 Not Found if the device hasn't been registered
            return jsonify({"error": f"Monitor '{device_id}' not found"}), 404

        # Get the monitor's data dictionary from the store
        monitor = monitors[device_id]

        # Handle paused monitors, heartbeat acts as a resume signal
        if monitor["status"] == "paused":
            # Change status back to active
            monitor["status"] = "active"
            # Recalculate a fresh deadline from right now
            monitor["deadline"] = datetime.utcnow() + timedelta(seconds=monitor["timeout"])
            # Record this resume event in the history log
            add_history(device_id, "Monitor resumed via heartbeat")
            # Return 200 OK confirming the monitor has been resumed
            return jsonify({
                "message":      f"Monitor '{device_id}' resumed and timer reset.",
                "status":       "active",
                "new_deadline": monitor["deadline"].isoformat() + "Z" 
            }), 200

        # Handle already-down monitors. Can't be revived by a heartbeat
        if monitor["status"] == "down":
            # Return 409 Conflict. the state conflicts with the request
            return jsonify({
                "error": f"Monitor '{device_id}' is already DOWN. Re-register to restart."
            }), 409  # 409 = HTTP Conflict

        # Monitor is active, simply reset the deadline from right now
        # This is the normal heartbeat case device is alive, timer restarted
        monitor["deadline"] = datetime.utcnow() + timedelta(seconds=monitor["timeout"])

        # Record this heartbeat in the history log
        add_history(device_id, "Heartbeat received — timer reset")

    # Return 200 OK confirming the timer was reset
    return jsonify({
        "message":      f"Heartbeat received for '{device_id}'. Timer reset.",
        "id":           device_id,
        "status":       "active",
        "new_deadline": monitor["deadline"].isoformat() + "Z"  # show the new deadline
    }), 200  # 200 = HTTP OK


# ENDPOINT 3
# Pauses monitoring you know stops the timer so no alerts fire during maintenance
@app.route("/monitors/<device_id>/pause", methods=["POST"])
def pause_monitor(device_id): 

    err = run_security_checks()
    if err:
        return err  

   
    with store_lock:

        # Check if the device exists in our store
        if device_id not in monitors:
            return jsonify({"error": f"Monitor '{device_id}' not found"}), 404

        # Get the monitor's data dictionary
        monitor = monitors[device_id]

        # Can't pause a device that has already gone DOWN
        if monitor["status"] == "down":
            return jsonify({"error": f"Monitor '{device_id}' is already DOWN."}), 409

        # If already paused, just confirm — nothing to change
        if monitor["status"] == "paused":
            return jsonify({"message": f"Monitor '{device_id}' is already paused."}), 200

        # Set the status to paused — the watchdog scheduler will skip this device
        monitor["status"] = "paused"

        # Record the pause event in the history log
        add_history(device_id, "Monitor paused, no alerts will fire")

    # Return 200 OK confirming the monitor is now paused
    return jsonify({
        "message": f"Monitor '{device_id}' is now paused. No alerts will fire.",
        "id":      device_id,
        "status":  "paused"  # confirm the new status
    }), 200


# ENDPOINT 4
# Developer's Choice: Returns full status + complete event history for a device
@app.route("/monitors/<device_id>", methods=["GET"])  # responds to GET requests only
def get_monitor(device_id):  # device_id captured from the URL

    # Run security checks
    err = run_security_checks()
    if err:
        return err 

  
    with store_lock:

        # Return 404 if the device doesn't exist
        if device_id not in monitors:
            return jsonify({"error": f"Monitor '{device_id}' not found"}), 404

        # Get the monitor's data dictionary
        monitor = monitors[device_id]

        # Calculate how many seconds remain before the timer fires
        # Only meaningful if the monitor is actively counting down
        if monitor["status"] == "active":
            # Subtract current time from deadline to get remaining time
            # .total_seconds() converts the timedelta to a plain float
        
            remaining = max(0, round(
                (monitor["deadline"] - datetime.utcnow()).total_seconds(), 2
            ))
        else:
            # Paused or down. "seconds remaining" is not meaningful
            remaining = None

    # Return the full monitor snapshot as JSON
    return jsonify({
        "id":                device_id,           
        "status":            monitor["status"],   
        "timeout":           monitor["timeout"],  
        "alert_email":       monitor["alert_email"],  
        "created_at":        monitor["created_at"],   
        "deadline":          monitor["deadline"].isoformat() + "Z" if monitor["status"] == "active" else None,  
        "seconds_remaining": remaining,           
        "history":           monitor["history"]   
        }), 200  


# ENDPOINT 5: GET /monitors 
# Returns a summary list of ALL registered monitors and their current statuses
@app.route("/monitors", methods=["GET"])  
def list_monitors():

   
    err = run_security_checks()
    if err:
        return err  

    
    with store_lock:

        # Build a list of summary objects, One per device
        result = []

        # Loop through every device ID and monitor data in the store
        for device_id, monitor in monitors.items():

            # Calculate remaining seconds only if the monitor is active
            if monitor["status"] == "active":
                remaining = max(0, round(
                    (monitor["deadline"] - datetime.utcnow()).total_seconds(), 2
                ))
            else:
                remaining = None  

            # Append a summary dictionary for this device to the result list
            result.append({
                "id":                device_id,          
                "status":            monitor["status"],  
                "timeout":           monitor["timeout"], 
                "seconds_remaining": remaining,          
                "alert_email":       monitor["alert_email"]  
            })

    # Return the full list with a total count
    return jsonify({
        "total":    len(result),  # how many devices are registered
        "monitors": result        # the list of device summaries
    }), 200


#  ENDPOINT 6
# Permanently removes a monitor from the system
@app.route("/monitors/<device_id>", methods=["DELETE"])  # responds to DELETE requests
def delete_monitor(device_id):  
    
    
    err = run_security_checks()
    if err:
        return err  

    with store_lock:

        # Return 404 if the device doesn't exist
        if device_id not in monitors:
            return jsonify({"error": f"Monitor '{device_id}' not found"}), 404

        # Remove the device entry from the dictionary entirely
        # del removes the key-value pair permanently from monitors
        del monitors[device_id]

    # Return 200 OK confirming the deletion
    return jsonify({"message": f"Monitor '{device_id}' has been deleted."}), 200



# ENTRY POINT — runs when you execute: python main.py


# This block only executes when the file is run directly
# It does NOT run if the file is imported as a module
if __name__ == "__main__":

    # Start the background watchdog scheduler BEFORE the web server
    # This ensures timers are already running when the first request comes in
    start_scheduler()

    # Start the Flask web server
    app.run(debug=True, host="0.0.0.0", port=5000)
