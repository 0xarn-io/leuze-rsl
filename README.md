# leuze-rsl

Pure-Python driver for the **measurement data output** of the Leuze **RSL 235**
safety laser scanner — the **UDP data telegrams ("UDT")** used for AGV/AMR
navigation.

- No dependencies (Python ≥ 3.9, stdlib only), thread-based, type annotated
- Receives and reassembles the scanner's UDP push stream: distances [mm],
  signal strengths, beam angles, plus the safety **status profile** (OSSD
  states, field violations, contamination, …)
- Robust against lost datagrams and fragmented scans (never emits silently
  truncated scans), wrap-aware scan numbering
- Ships **protocol simulators** so everything works without hardware
- Bonus: a full client for the ROD-300-500 protocol (Leuze ROD x08
  navigation scanners), see [below](#the-rod-300-500-protocol-rod-x08)

**Verified against real RSL 235 hardware:** the device *pushes* UDP data
telegrams in the format of the Leuze *RSL 400 UDP specification* (document
50130122) to a destination configured in Sensor Studio — there is no TCP
command channel. The wire format is documented [below](#protocol-reference).

## Install

```bash
pip install leuze-rsl
```

Or from a checkout of this repository:

```bash
pip install .                      # from the repository root
# offline machine? avoid the PyPI round-trip:
pip install . --no-build-isolation
```

No install needed either: the package is pure Python — copy `src/leuze_rsl/`
next to your script (as `leuze_rsl/`), or run the examples straight from the
checkout.

## Scanner setup (Sensor Studio)

1. Open the scanner's configuration project, go to **SETTINGS → Data
   telegrams**.
2. **Activate the UDP telegram** and set the **destination**: the IP of the
   machine running this driver and a port (e.g. 3050).
3. Under **Measurement values in UDP telegram**, enable **measurement value
   transmission**; choose start/stop index, index interval and the data
   type — *Distance (ID 6)* or *Distance + signal strength (ID 3)*.
4. Transfer the configuration. The scanner starts pushing immediately.
5. Allow **inbound UDP** on that port in your firewall.

## Quickstart

```python
from leuze_rsl import RSL235Udt

with RSL235Udt(port=3050) as receiver:          # the port configured above
    scan = receiver.get_scan(timeout=5.0)       # one assembled scan cycle
    print(scan.scan_number,
          scan.distances_mm[:5],                # [mm], 0 = no echo
          scan.signal_strengths[:5],            # None for data type ID 6
          scan.angles_deg()[:5])                # beam angles

    status = receiver.latest_status             # safety status profile
    print(status.ossd_a, status.a_protective_violated, status.error)
```

Every `UdtScan` exposes:

| attribute | meaning |
|---|---|
| `distances_mm` / `distances_m` | distance per beam (0 = no valid echo) |
| `signal_strengths` | signal strength per beam [digits], or `None` |
| `beam_indices()` / `angles_deg()` | beam geometry from the measurement contour |
| `to_cartesian()` | `(x, y)` points in meters, invalid beams skipped |
| `scan_number`, `num_blocks`, `contour`, `status` | telegram metadata |

Constructor knobs: `bind_address`, `source_ip` (ignore datagrams from other
devices), `strict` (drop incomplete scans — default — or emit them short),
`scan_queue_size`, `on_scan` / `on_status` callbacks, `data_timeout`
(drives `receiver.is_receiving`). Diagnostics: `receiver.stats`.

### Examples

```bash
python3 examples/read_udt.py --port 3050 --count 10    # print scans + status
python3 examples/dump_udt.py --port 3050               # raw datagram decoder/hexdump
python3 examples/live_plot.py --port 3050              # polar live view (matplotlib)
```

All accept `--simulate` to run against the built-in simulator instead of
hardware. No checkout needed — the installed package also exposes a CLI that
reads straight from hardware:

```bash
python3 -m leuze_rsl --port 3050 --count 10             # read RSL 235 UDT (real hardware)
python3 -m leuze_rsl --rod 192.168.60.101               # read a ROD 308/508 over TCP
python3 -m leuze_rsl --simulate                         # no hardware: built-in simulator
```

The simulator also runs standalone:

```bash
python3 -m leuze_rsl.simulator --port 3050              # push UDT to 127.0.0.1:3050
```

### Angle convention

Beam *indices* step 0.1°; angles default to a 275° field of view centered on
the device front (`angle = index * 0.1° − 137.5°`; the RSL 400 spans 270°,
so use `angle_at_index0=-135.0` there). Verify against a known target and
pass your own offset to `angles_deg()` / `to_cartesian()` if needed.

## Protocol reference

As specified in the Leuze *RSL 400 UDP specification* (50130122) and
verified against RSL 235 hardware. Every datagram starts with a 20-byte
frame, **all fields little-endian**:

| offset | size | field | description |
|---|---|---|---|
| 0 | 4 | `total_length` | length of the whole datagram in bytes |
| 4 | 1 | `h1_size` | 8 |
| 5 | 1 | `follow_flag` | |
| 6 | 2 | `request_id` | |
| 8 | 4 | `header2` | internal |
| 12 | 2 | `telegram_id` | 1 = extended status profile, 6 = distance, 3 = distance + signal strength |
| 14 | 2 | `block` | fragment number within the scan (0…65535) |
| 16 | 4 | `scan_number` | scan cycle counter (wraps at 2³²) |

- **ID 1 — extended status profile** (sent once per scan cycle): 20-byte
  status profile (operating mode; ERROR/ALARM/contamination flags; OSSD A/B;
  protective/warning field violations and field-pair selections for
  functions A and B; embedded scan number) followed by the 8-byte
  **measurement contour description**: `start_index u16`, `stop_index u16`,
  `index_interval u16`, `reserved u16` → beams per scan
  `n = 1 + ceil((stop − start) / interval)`.
  *RSL 200 note:* the datagram is 56 bytes — 8 more than the RSL 400
  document describes — so the driver locates the contour adaptively and
  verifies it against the observed beam count.
- **ID 6 — distance**: n × `u16` distance [mm].
- **ID 3 — distance + signal strength**: n × (`u16` distance [mm] +
  `u16` signal strength [digits]).
- Large scans are split across datagrams with consecutive `block` numbers;
  all datagrams of one cycle share the `scan_number`.
- **No-echo sentinel:** real RSL 235 hardware reports **32767 mm** (0x7FFF)
  for beams without a valid echo (0 also counts as invalid). Use
  `scan.valid_mask()`; `to_cartesian()` skips these automatically. The
  RSL 235 measures 0.08…25 m.

A capture from real hardware (56-byte status + single 1104-byte
distance+signal datagram = 271 beams per cycle):

```
38 00 00 00 08 00 06 00 04 0b 01 32 01 00 00 00 ...   ID 1, 56 B
50 04 00 00 08 00 06 00 04 0b 01 32 03 00 00 00 ...   ID 3, 1104 B
```

---

## The ROD-300-500 protocol (ROD x08)

The package also contains a complete client for the protocol used by Leuze
**ROD 308 / ROD 508** navigation scanners (reverse engineered from Leuze's
official [RODx00 ROS2 driver](https://github.com/thesensorpeople/leuze_rod_ros2_drivers)):
an STX/ETX-framed **TCP command interface** (`cWN SendMDI`, `cRN GetRange`, …
default port 3050) plus big-endian `LEUZ`-sync **MDI packets** over UDP or
TCP.

```python
from leuze_rsl import RSL235

with RSL235("192.168.60.101") as scanner:   # TCP connect + config read
    scanner.start_measurement()              # sends "SendMDI"
    scan = scanner.get_scan(timeout=5.0)
    print(scanner.get_temperature(), scanner.get_status())
```

```bash
python3 examples/read_rod.py 192.168.60.101 --count 10   # scans (--simulate works)
python3 examples/read_status.py 192.168.60.101           # full status dump
python3 -m leuze_rsl.simulator --rod --port 3050          # ROD-protocol simulator
```

<details>
<summary>ROD-300-500 protocol reference (click to expand)</summary>

### TCP command interface

ASCII commands framed by `STX` (0x02) and `ETX` (0x03), e.g.
`<STX>cWN SendMDI<ETX>`. Replies echo the command name:
`<STX>cWA SendMDI<ETX>` resp. `<STX>cRA GetRange -13760 13760<ETX>`
(space-separated decimal values).

| Command | Reply values | Meaning |
|---|---|---|
| `cWN SendMDI` | – | start streaming measurement data |
| `cWN StopMDI` | – | stop streaming |
| `cRN GetProto` | 1 | MDI transport: 0 = UDP, 1 = TCP |
| `cRN GetPType` | 1 | 0 = distances only, 1 = distances + intensities |
| `cRN GetResol` | 1 | 0: 0.2°@80 Hz, 1: 0.1°@40 Hz, 2: 0.05°@20 Hz, 3: 0.025°@10 Hz, 4: 0.2°@50 Hz |
| `cRN GetDir` | 1 | data output direction: 0 = CW, 1 = CCW |
| `cRN GetRange` | 2 | scan angle min, max in 0.01° (−13760…13760) |
| `cRN GetSkip` | 1 | spots skipped between output measurements |
| `cRN GetCont` | 2 | contamination warning / error threshold [%] |
| `cRN GetWinStat` | 9 | contamination per window segment [%] |
| `cRN GetVer` | 7 | part number, HW version, SW version, 4 × undocumented |
| `cRN GetTem` | 1 | internal temperature [0.01 °C] |
| `cRN GetELog` | 21 | 1 undocumented value, then 10 × (error code, date) |
| `cRN GetHours` | 1 | operating hours |
| `cRN GetWCalib` | 1 | window calibration: 0 processing, 1 done, 3 failed |
| `cRN GetFilter` | 3 | filter type (0 median, 1 average, 2 max, 3 combo), historical spots, neighboring spots |
| `cRN GetECode` | 1 | currently active error code (0 = none) |
| `cRN GetTxMDI` | 1 | MDI stream running: 0/1 |

Startup sequence: TCP connect → `StopMDI` (handshake) → read settings →
bind the local UDP port (same number as the TCP port) → `SendMDI`. With
`GetProto == TCP` the MDI packets arrive interleaved with command replies
on the same TCP socket; the driver demultiplexes them.

### MDI measurement packets

One scan is split into `total_number` packets, each with a 31-byte header.
**All multi-byte fields big-endian.**

| offset | size | field | description |
|---|---|---|---|
| 0 | 4 | `sync` | `4C 45 55 5A` = `"LEUZ"` |
| 4 | 1 | `packet_type` | 0 = distances only, 1 = distances + intensities |
| 5 | 2 | `packet_size` | total packet size in bytes, incl. header |
| 7 | 6 | `reserve_a/b/c` | 3 × u16, reserved |
| 13 | 2 | `packet_number` | sequence number since power-up (wraps at 2¹⁶) |
| 15 | 1 | `total_number` | packets per full scan |
| 16 | 1 | `sub_number` | 1-based index of this packet within the scan |
| 17 | 2 | `scan_freq` | scan frequency [Hz] |
| 19 | 2 | `scan_spots` | number of spots in *this* packet |
| 21 | 4 | `first_angle` | i32, absolute angle of the first spot [1/1000°] |
| 25 | 4 | `delta_angle` | i32, angle between consecutive spots [1/1000°] |
| 29 | 2 | `timestamp` | [ms], wraps at 2¹⁶ |

Payload: `scan_spots` × u16 distances [mm], then `scan_spots` × u16
intensities (valid 32…4095) when `packet_type == 1`. Angles are scanner
native; Leuze's ROS driver negates them for REP-103. The reference C++
driver's weaknesses (infinite loop on `packet_size == 0`, command replies
lost across TCP segment boundaries, partial-scan emission, UDP bind race)
are fixed in this implementation.

</details>

## Tests

```bash
pip install -e .                       # the src layout needs an install first
python3 -m unittest discover -s tests -v
```

62 tests cover both wire formats, the scan assemblers (corruption, loss,
resync, fragmentation, wraparound) and the full receivers/drivers against
the simulators over real sockets — including frames replayed byte-for-byte
from an RSL 235 hardware capture.

## License

MIT — see [LICENSE](LICENSE). The ROD-300-500 protocol was reverse
engineered from Leuze's Apache-2.0 licensed ROS2 driver (© 2025 Leuze
electronic GmbH + Co. KG); the UDT format follows Leuze document 50130122.
No Leuze code is included. This project is not affiliated with or endorsed
by Leuze.
