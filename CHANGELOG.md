# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.0] — 2026-10-26

Result of a full audit against the Leuze *RSL 200 / RSL 400 UDP
specification* (50130122, EN 2024/10/01), Leuze's RSL 400 ROS driver and the
ROD x08 ROS2 driver. Read the **Changed** section before upgrading: scan
angles and status fields decode differently (correctly) for an RSL 235.

### Fixed

- **Status profile decoded with the wrong layout on RSL 200 / RSL 235**
  hardware. The RSL 200 series sends a 28-byte profile (type 21) with the
  scan number at bytes 16–19, the OSSD at byte 3 bit 7 and the measurement
  contour at payload offset 28 — the previous release applied the RSL 400
  table, so `scan_number`, `ossd_a`, `parked` and every field-violation flag
  were read from unrelated bytes. Both layouts are now decoded by profile
  type, and the contour is read at the offset the specification fixes
  (the heuristic search is only used for unknown profile types and is
  verified against the observed beam count).
- **Field-violation flags had inverted polarity** (`*_violated` was True when
  the field was free) for the RSL 400 layout.
- **Beam angles were compressed 2×** for the RSL 200 series: one index is
  0.2°, not 0.1° (the specification limits RSL 200 indices to 0…1350).
- Strict mode could emit truncated scans (lost first/last block, or no
  contour known yet) and could deliver a scan twice (late/duplicated
  datagram). Scans are now complete only when blocks 0…n are all present and
  the beam count equals the contour's; stale datagrams are rejected; a
  scanner restart (scan counter reset after a pause) is detected.
- `UdtScan.status` is now the status profile of the scan's own cycle (or
  `None` if that telegram was lost) instead of whatever arrived last.
- Pending scans are bounded (`max_pending` cycles, 64 fragments / 256 KiB
  per cycle; `scans_dropped_oversize`), so corrupted or foreign scan
  numbers can no longer grow memory without limit. A measurement datagram
  without a single beam is counted as a bad frame and never emitted.
- ROD client: a UDP receiver failure no longer clears the measuring state,
  so `stop_measurement()` / `close()` still send `StopMDI`; `get_scan()`
  reports the failure as `ScannerConnectionError` until then.
- `SO_REUSEADDR` removed from the UDP receive sockets: a second receiver on
  the same port now fails with `ScannerConnectionError` instead of silently
  stealing the datagram stream.
- `get_scan()` / `scans()` no longer block forever after `stop()`, `close()`
  or a lost connection; `get_scan(timeout=None)` is interruptible with
  Ctrl+C on Windows; scans buffered before a stop are not served after a
  restart; receiver threads never die silently (`receiver_errors` counter,
  waiters are woken with `ScannerConnectionError`).
- Socket bind failures raise `ScannerConnectionError` and close the socket.
- ROD client: after a lost TCP connection `connect()` on the same object
  works again and `start_measurement()` is no longer a silent no-op; the
  dead socket is closed; an orphaned reader thread cannot clobber a newer
  connection; commands may be issued from `on_scan` in TCP transport mode;
  the stream demultiplexer is linear in the buffer size and a truncated
  reply no longer destroys the next one; malformed replies fail the command
  immediately; late replies to timed-out commands are discarded; scans
  stitched from two rotations after a burst loss are detected
  (`packet_number` continuity); one corrupt UDP datagram can no longer
  swallow the following ones; TCP keepalive detects a silently dead scanner.
- `leuze_rsl.__version__` is the single source of the version (it said
  0.2.0 in the 0.3.0 release).
- CLI: validated arguments, clean exit on Ctrl+C (130), `--simulate` and
  `--udp-port` in `--rod` mode, correct labels, quiet by default (`-v`/`-vv`).
- Examples: wrong docstrings fixed, `live_plot` no longer crashes on a scan
  without valid beams, `dump_udt.py` gained `--simulate` and stays
  interruptible on Windows.
- Simulators emit spec-conformant datagrams (RSL 200 by default, RSL 400
  optional), can inject invalid measurements, and their threads report
  failures instead of dying silently.

### Changed

- **Angle convention.** `angles_deg()` / `to_cartesian()` default to the
  device family's geometry: RSL 200 `135.0° − 0.2°·index`, RSL 400
  `134.95° − 0.1°·index` (index 0 at the counter-clockwise edge, as in
  Leuze's RSL 400 ROS driver). Previously `index·0.1° − 137.5°`. Override
  via `angle_at_index0` / `index_resolution` if your mounting differs.
- `StatusProfile` gained many fields (`family`, `profile_length`,
  `warning_field_2_violated`, `restart_interlock`, `field_triple`, `inputs`,
  `outputs`, `temperature_c`, `signature`, `error_class`, `error_number`,
  RSL 400 `estop_*`, bank/field-pair selections, `configuration_signature`).
  Fields that do not exist for a family are `None` (`ossd_b`, `b_*` on the
  RSL 200).
- `UdtScan` gained `blocks`, `block_beams`, `complete`, `family`,
  `geometry`, `no_echo_mm`; `num_blocks` is derived. `valid_mask()` and
  `to_cartesian()` use the family's no-echo value (RSL 400: 65535).
- Scan timeouts raise `ScanTimeoutError` (a `TimeoutError` *and* an
  `RSL235Error`); a stopped receiver raises `ReceiverStoppedError`; parsers
  raise `ProtocolError` (a `ValueError`) instead of `struct.error` /
  `ValueError` on malformed input; usage errors raise `ValueError`.
- `distances_m`, `angles_deg`, `angles_rad` of the ROD `Scan` and
  `UdtScan.distances_m` are cached tuples instead of freshly built lists.
  `Scan.to_cartesian()` now also omits spots whose intensity is below 32
  (the reference driver's "undefined" range).
- `StatusProfile` is a decoded record with many required fields; build it
  with `StatusProfile.from_bytes()` rather than positionally.
- `RSL235Udt.start()` begins a fresh session: statistics, `latest_status`
  and `contour` are reset along with the scan queue.
- `INDEX_RESOLUTION_DEG` is now the *signed* default step (−0.2), so passing
  it together with `DEFAULT_ANGLE_AT_INDEX0_DEG` reproduces the default
  geometry.
- `RodSimulator.commands_received` is a bounded `collections.deque`.
- `MeasurementContour` validates its fields; `from_bytes()` returns `None`
  for an inactive (all-zero) contour.
- `UdtAssembler` requires a known contour to emit a scan in strict mode
  (lenient mode emits it with `complete=False`). A scan number far behind
  the stream (more than 256 cycles, or after a silence of more than 1 s)
  is treated as a scanner restart, never as stale data.
- `scan_queue_size <= 0` keeps the stdlib meaning (unbounded queue) and is
  now documented; `RodScanner` validates its other constructor arguments.
- ROD client renamed to `RodScanner`, simulator to `RodSimulator`;
  `RSL235` and `RSL235Simulator` remain as aliases. Module docstrings now
  say which device each half talks to.
- ROD client: `connect()` raises `ScannerConnectionError` (cause chained)
  when the `StopMDI` handshake or the configuration read fails;
  `start_measurement()` without a configuration raises `ValueError`;
  `ScannerConfig` gained `angle_min_cdeg` / `angle_max_cdeg` and computes
  `expected_spots` with the shared `protocol.expected_spots()` (floor);
  `stats` gained `mdi_packets_dropped`, `truncated_responses`,
  `late_responses`, `receiver_errors`; `tcp_keepalive` constructor option.
- `ScanAssembler.feed_datagram()` for whole UDP datagrams; `AssemblerStats`
  gained `packets_out_of_sequence`.
- ROD simulator: the native direction convention now follows Leuze's ROS
  node (clockwise output starts at the minimum angle and counts up,
  counter-clockwise starts at the maximum angle and counts down); new knobs
  `invalid_spot_every`, `no_echo_indices`, `SimulatorSettings.scan_period_s`.
- UDT simulator knobs: `family`, `profile_type`, `ossd`,
  `protective_field_free`, `warning_field_free`, `error`, `signature`,
  `no_echo_indices`; `status_extra_bytes` removed, `contour_offset` only
  together with an unknown `profile_type`.
- The UDT simulator's default contour is the spec-valid `(0, 1350, 5)`
  (still 271 beams); `contour_offset` / `status_extra_bytes` were replaced
  by `family` / `profile_type` knobs.
- Packaging: Python version classifiers, `Typing :: Typed`, CHANGELOG,
  CI workflow (Linux/macOS/Windows × Python 3.9–3.13, pyflakes, mypy
  --strict, build check); the publish workflow runs the tests first and
  checks that the release tag matches the version.

## [0.3.0]

- Package rename, README and CLI additions.

## [0.2.0]

- Initial public release.
