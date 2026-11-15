
#set page(paper: "a4", margin: (x: 2cm, y: 2.2cm), numbering: "1")
#set text(font: "New Computer Modern", size: 10pt, lang: "en")
#show raw: set text(font: "DejaVu Sans Mono")
#set par(justify: true, leading: 0.62em)
#set heading(numbering: "1.1")
#show heading: set text(fill: rgb("1a2a3a"))
#show figure.caption: set text(size: 9pt)
#show figure: set block(spacing: 1.2em)
#set list(spacing: 0.6em)
#set enum(spacing: 0.6em)

#align(center)[
  #text(16pt, weight: "bold")[COMPUTER NETWORKS LABORATORY] \
  #v(0.4em)
  #text(13pt, weight: "bold")[Assignment 4] \
  #v(0.4em)
  #text(15pt, weight: "bold")[CDMA with Walsh Codes] \
  #v(0.2em)
  #text(10.5pt, style: "italic", fill: rgb("444444"))[Code Division Multiple Access of a Common Channel by n Stations: Implementation, Verification and Performance Analysis]
]

#v(0.5em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.3em)
#grid(columns: (1.2fr, 1fr), row-gutter: 0.55em,
  [ *Name:* Asaduz Zaman ], [ *Class:* BCSE 3rd Year ],
  [ *Roll:* 002410501036 ], [ *Group:* A2 ],
  [ *Assignment Number:* 4 ], [],
)
#v(0.3em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.4em)

#heading(level: 2, numbering: none)[Problem Statement:]
- Implement *CDMA* for multiple access of a common channel by $n$ stations, using the same Channel / Sender / Receiver design as the previous assignments (independent processes over TCP sockets).
- Every sender encodes its data with a *unique code word taken from the Walsh set*, sends the chips across the shared channel, and the data of all $n$ stations must be *perfectly reconstructed* at the receiving side.
- Emulate the shared channel as an additive medium: the signals of all stations are summed chip by chip (optionally with Gaussian noise).
- Verify end-to-end integrity with a real file transfer: frames carry sequence numbers and CRC-32, and the rebuilt file must be bit-exact (`cmp text.txt received.txt`).
- Show with timestamps how every chunk moves through sender, channel and receiver, and evaluate the scheme: orthogonality, robustness against noise (bit error rate) and code-space efficiency for different $n$.

#v(0.5em)
#line(length: 100%, stroke: 0.8pt + luma(150))
#v(0.4em)
#grid(columns: (1.2fr, 1fr), row-gutter: 0.55em,
  [ *Submitted to:* Prof. Sarbani Roy ], [ *Department:* Computer Science and Engineering ],
  [ *Institution:* Jadavpur University ], [ *Submission Date:* 3 November 2026 ],
)
#v(0.3em)
#line(length: 100%, stroke: 0.8pt + luma(150))

#pagebreak()

= Design

== Purpose and Theoretical Motivation

When several stations share one medium, some multiple-access rule is needed. TDMA separates stations in time, FDMA in frequency, and *CDMA separates them by code*: all stations transmit at the same time on the same frequency, each multiplying its data by its own spreading code. The channel only adds the signals together. A receiver that knows the code of one station can pull exactly that station's data out of the sum, because the codes are chosen *orthogonal*.

The *Walsh codes* are the rows of the Walsh (Hadamard) matrix. They are $plus.minus 1$ sequences of length $L = 2^k$ with the property that the inner product of two different rows is exactly zero. This gives three properties used throughout this assignment:
+ *No interference* between stations: with perfect chip synchronisation the other stations cancel exactly in the correlator, not just on average.
+ *Spreading gain:* each bit is sent as $L$ chips, so noise power at the correlator output is reduced by a factor $L$.
+ *No collisions and no waiting:* unlike the CSMA schemes of Assignment 3, no station ever defers or backs off; all $n$ stations transmit in every round.

== System Architecture & Structure Diagram

The emulation keeps the structure of the earlier assignments: a shared channel emulator, a sender program that runs one independent OS process per station, and a destination receiver (@fig:arch).

#figure(
  image("architecture.png", width: 100%),
  caption: [System architecture. Station processes (`src/sender.py`) spread their chunks with Walsh codes and send the chips to the channel (`src/channel.py`), which adds them and forwards the composite signal to the receiver (`src/receiver.py`) where one decoder per station recovers the data.],
) <fig:arch>

- *Process isolation:* every station is a separate OS process with its own TCP connection and only knows its own Walsh row.
- *Lock-step rounds:* in round $r$ the channel asks every station for one frame, waits for all of them, adds the chip streams, sends the sum to the receiver and waits for the decode acknowledgement. This gives a clean timeline (@fig:timeline) and a deterministic emulation of "all stations transmit simultaneously".
- *Chunking:* `text.txt` is cut into chunks of 8 bytes; chunk $g$ is sent by station $g mod n$ in round $floor(g / n)$.

== Protocol & Wire Specification

All TCP messages are newline-terminated JSON objects.
- *Station / receiver to channel:* `{"type": "hello", "role": "sender" | "receiver", "station": i}`.
- *Channel to everybody:* `{"type": "welcome", "n": n, "size": L}`.
- *Channel to station:* `{"type": "go", "round": r}`. *Station reply:* `{"type": "frame", "round": r, "seq": g, "chips": [...]}` or `{"type": "done"}` when it has no chunk left.
- *Channel to receiver:* `{"type": "signal", "round": r, "chips": [...]}`; receiver replies `{"type": "decoded", "round": r, "results": [...]}`; at the end `{"type": "end"}` and the receiver answers with a summary.

*Frame format* (all stations use the same length, so frames stay aligned chip by chip):

#align(center)[
  #table(columns: (1fr, 0.7fr, 2fr, 1fr), stroke: 0.5pt + luma(180), align: center,
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    [*seq*], [*len*], [*payload (padded to 8 B)*], [*CRC-32*],
    [4 B], [1 B], [8 B], [4 B])
]
A frame is therefore 136 bits = 136 $times$ 4 = 544 chips when $n = 4$.



= Implementation

The implementation consists of exactly three modules in `src/`, run with Astral `uv`:

#figure(
  table(columns: (1.3fr, 2fr, 2.7fr), stroke: 0.5pt + luma(180),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    [*Module*], [*Key interface*], [*Responsibility*],
    [`src/channel.py`], [`serve()`, Walsh/CDMA library, `--report`], [Accepts $n$ stations and the receiver, runs the rounds, adds the chip streams (+ noise), logs every event with a timestamp, writes `events.json`, `run.json`, `summary.json`. Also contains the experiments and the report generator.],
    [`src/sender.py`], [`station_main(i)`], [One process per station: read file, chunk, build frame, spread with Walsh row $i$, send chips when asked.],
    [`src/receiver.py`], [`main()`], [One decoder per station: correlate with Walsh row $i$, threshold, parse frame, verify CRC-32 and sequence/station consistency, rebuild the file.],
  ),
  caption: [Modules and their responsibilities.],
) <tab:modules>

== Walsh Code Generation

#figure(
  image("walsh_orthogonality.png", width: 92%),
  caption: [(a) Walsh matrix for $L = 8$ generated by the code below; (b) its normalised Gram matrix $W W^T slash L$, which is exactly the identity: all codes are mutually orthogonal.],
) <fig:walsh>

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.5pt)
#raw("def walsh_matrix(n: int) -> np.ndarray:\n    \"\"\"Walsh matrix (Sylvester construction), size = smallest power of two >= n.\n\n    W(1) = [1];  W(2k) = [[W(k), W(k)], [W(k), -W(k)]].  Row i is station i's code.\n    \"\"\"\n    size = 1\n    while size < n:\n        size *= 2\n    w = np.array([[1]], dtype=int)\n    while w.shape[0] < size:\n        w = np.block([[w, w], [w, -w]])\n    return w", block: true, lang: "python")]

The recursion $W_(2k) = mat(delim: "[", W_k, W_k; W_k, -W_k)$ preserves orthogonality: if $W_k W_k^T = k I$ then $W_(2k) W_(2k)^T = mat(delim: "[", 2 W_k W_k^T, 0; 0, 2 W_k W_k^T) = 2k I$. Station $i$ uses row $i$. If $n$ is not a power of two the matrix is the next power of two and the surplus rows stay unused.

== Spreading and De-spreading

A data bit $b in {0, 1}$ is mapped to the symbol $s = 2b - 1 in {-1, +1}$ and transmitted as $s dot c_i$ (one code period, $L$ chips). The decoder correlates every bit period of the received signal with the code of its station and normalises by $L$:

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.5pt)
#raw("def encode(bits: np.ndarray, code: np.ndarray) -> np.ndarray:\n    \"\"\"Spread: bit 1 -> +code, bit 0 -> -code (bipolar), one code period per bit.\"\"\"\n    symbols = np.where(np.asarray(bits) == 1, 1, -1)\n    return (symbols[:, None] * code[None, :]).ravel()\n\ndef correlate(signal: np.ndarray, code: np.ndarray) -> np.ndarray:\n    \"\"\"De-spread: normalised inner product of each bit period with `code`.\n\n    Exactly +1 / -1 for the owner of `code` (0 if silent) when there is no noise.\n    \"\"\"\n    size = len(code)\n    usable = (len(signal) // size) * size\n    return np.asarray(signal[:usable], dtype=float).reshape(-1, size) @ code / size", block: true, lang: "python")]

== Framing and CRC-32

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.5pt)
#raw("def frame_bits(seq: int, payload: bytes, chunk: int) -> np.ndarray:\n    \"\"\"Frame = seq(4B) | len(1B) | payload padded to `chunk` | CRC-32(4B), as bits.\"\"\"\n    body = seq.to_bytes(4, \"big\") + bytes([len(payload)]) + payload.ljust(chunk, b\"\\0\")\n    raw = body + zlib.crc32(body).to_bytes(4, \"big\")\n    return np.unpackbits(np.frombuffer(raw, dtype=np.uint8))\n\ndef parse_frame(bits: np.ndarray) -> tuple[bool, int, bytes]:\n    raw = np.packbits(np.asarray(bits, dtype=np.uint8)).tobytes()\n    body, crc = raw[:-4], int.from_bytes(raw[-4:], \"big\")\n    seq, ln, chunk = int.from_bytes(body[:4], \"big\"), body[4], len(body) - 5\n    ok = zlib.crc32(body) == crc and ln <= chunk\n    return ok, seq, (body[5:5 + ln] if ok else b\"\")", block: true, lang: "python")]

The receiver additionally checks that a chunk with sequence number $g$ was recovered by decoder $g mod n$, which catches a frame decoded with the wrong code.



= Test Cases & Functional Verification

#figure(
  table(columns: (0.5fr, 1.7fr, 2.3fr, 2.3fr, 0.8fr),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    stroke: 0.5pt + luma(180), align: left + horizon,
    [*ID*],
    [*Test*],
    [*Configuration*],
    [*Observed*],
    [*Verdict*],
    [T1],
    [Walsh orthogonality],
    [W W^T = L I for L = 1 ... 64],
    [all exact],
    [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T2],
    [Framing and CRC-32],
    [round trip; one flipped bit],
    [flip detected],
    [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T3],
    [Noise-free separation],
    [n = 3, 4, 8, 16 stations at once],
    [max error 0.0e+00],
    [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T4],
    [File transfer, N = 4],
    [text.txt, 387 B, chunk 8],
    [cmp identical, 49 frames, 0 CRC errors],
    [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T5],
    [Single station],
    [N = 1 (L = 1)],
    [identical],
    [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T6],
    [N not a power of two],
    [N = 3 (L = 4, row 3 unused)],
    [identical],
    [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T7],
    [Larger system],
    [N = 8 (L = 8), chunk 16],
    [identical],
    [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T8],
    [Binary file, odd length],
    [1501 random bytes, N = 5 (L = 8), chunk 32],
    [identical (last round has idle stations)],
    [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T9],
    [Corruption is detected],
    [noise sigma = 3, N = 4],
    [52 CRC failures, none accepted silently],
    [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]],
    [T10],
    [Unused code row],
    [N = 3, decode with row 3 (nobody uses it)],
    [output exactly 0],
    [#text(fill: rgb("2e7d32"), weight: "bold")[PASS]]
  ),
  caption: [Functional test matrix. T4-T9 are real runs of the three processes over TCP sockets.],
) <tab:tests>

All tests use the same three programs; T4 to T9 start real processes that talk over TCP. T9 shows that the integrity layer works: under heavy noise the receiver reports 52 CRC failures (damaged frames, plus spurious detections on idle decoders) and drops them instead of writing wrong data into the file.

*Bit-exact file check (the `text.txt` / `received.txt` verification):*
#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.5pt)
#raw("$ uv run python src/channel.py --spawn --stations 4 --input text.txt\n$ cmp text.txt out/received.txt && echo \"Bit-exact match verified!\"\nBit-exact match verified!", block: true)]

*Live log with timestamps.* While the system runs, every process prints one line per event (`[HH:MM:SS.mmm] [who] round r EVENT ...`). The excerpt below is the real log of the demo run (rounds 0 and 1 only, sorted by timestamp; the full log is in `out/demo_log.txt`). It shows each station spreading its chunk, the channel receiving the four streams and adding them, and the receiver decoding the four chunks from the single sum:

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 6.2pt)
#raw("[10:38:13.536] [channel  ] listening on 127.0.0.1:5200, waiting for 4 stations + receiver (Walsh length L=4, noise sigma=0.0)\n[10:38:13.654] [channel  ] station 2 connected\n[10:38:13.654] [channel  ] station 0 connected\n[10:38:13.654] [channel  ] station 1 connected\n[10:38:13.655] [channel  ] station 3 connected\n[10:38:13.661] [channel  ] receiver connected\n...\n[10:38:13.663] [station 0] round   0 SPREAD     chunk seq=0 data='CSE/PC/B'  (136 bits x 4 chips = 544 chips)\n[10:38:13.665] [station 2] round   0 SPREAD     chunk seq=2 data='omputer '  (136 bits x 4 chips = 544 chips)\n[10:38:13.665] [channel  ] round   0 RX         station 0 chunk seq=0 (544 chips)\n[10:38:13.666] [station 1] round   0 SPREAD     chunk seq=1 data='/S/314 C'  (136 bits x 4 chips = 544 chips)\n[10:38:13.666] [station 3] round   0 SPREAD     chunk seq=3 data='Networks'  (136 bits x 4 chips = 544 chips)\n[10:38:13.667] [channel  ] round   0 RX         station 1 chunk seq=1 (544 chips)\n[10:38:13.667] [channel  ] round   0 RX         station 2 chunk seq=2 (544 chips)\n[10:38:13.667] [channel  ] round   0 RX         station 3 chunk seq=3 (544 chips)\n[10:38:13.667] [channel  ] round   0 SUM        4 stream(s) added -> 544 chips, level range [-4, +4] -> receiver\n[10:38:13.667] [receiver ] round   0 DECODE     station 0 -> seq=0 crc OK  data='CSE/PC/B'\n[10:38:13.667] [receiver ] round   0 DECODE     station 1 -> seq=1 crc OK  data='/S/314 C'\n[10:38:13.667] [receiver ] round   0 DECODE     station 2 -> seq=2 crc OK  data='omputer '\n[10:38:13.667] [receiver ] round   0 DECODE     station 3 -> seq=3 crc OK  data='Networks'\n[10:38:13.718] [station 2] round   1 SPREAD     chunk seq=6 data='t 4\\nCDMA'  (136 bits x 4 chips = 544 chips)\n[10:38:13.718] [station 0] round   1 SPREAD     chunk seq=4 data=' Lab - A'  (136 bits x 4 chips = 544 chips)\n[10:38:13.718] [channel  ] round   1 RX         station 0 chunk seq=4 (544 chips)\n[10:38:13.718] [station 1] round   1 SPREAD     chunk seq=5 data='ssignmen'  (136 bits x 4 chips = 544 chips)\n[10:38:13.719] [channel  ] round   1 RX         station 1 chunk seq=5 (544 chips)\n[10:38:13.719] [channel  ] round   1 RX         station 2 chunk seq=6 (544 chips)\n[10:38:13.719] [station 3] round   1 SPREAD     chunk seq=7 data=' with Wa'  (136 bits x 4 chips = 544 chips)\n[10:38:13.719] [channel  ] round   1 RX         station 3 chunk seq=7 (544 chips)\n[10:38:13.719] [channel  ] round   1 SUM        4 stream(s) added -> 544 chips, level range [-4, +4] -> receiver\n[10:38:13.719] [receiver ] round   1 DECODE     station 0 -> seq=4 crc OK  data=' Lab - A'\n[10:38:13.720] [receiver ] round   1 DECODE     station 1 -> seq=5 crc OK  data='ssignmen'\n[10:38:13.720] [receiver ] round   1 DECODE     station 2 -> seq=6 crc OK  data='t 4\\nCDMA'\n[10:38:13.720] [receiver ] round   1 DECODE     station 3 -> seq=7 crc OK  data=' with Wa'\n...\n[10:38:14.352] [receiver ] file rebuilt: 387 bytes -> /home/claude/out/received.txt (frames ok=49, bad=0, missing=0, dup=0)", block: true)]

#block(fill: luma(246), inset: 6pt, radius: 3pt, width: 100%)[#set text(size: 7.5pt)
#raw("=========== RESULT ===========\n            N (stations): 4\n          Walsh length L: 4\n             chunk bytes: 8\n             noise sigma: 0.0\n                  rounds: 13\n  frames sent / ok / bad: 49 / 49 / 0\n            missing seqs: 0\n        chips on channel: 7072\n           bits per chip: 0.4378\n   receiver verification: PASSED\n          file identical: YES", block: true)]



= Results & Performance Evaluation

== Demo Transfer: How the Chunks Move

The demo sends `text.txt` (387 bytes) with $n = 4$ stations, chunk size 8 B and a round delay of 50 ms (only to make the timeline readable). It needs 13 rounds for 49 frames; 0 CRC errors occurred; the file was reassembled bit-exact (`cmp`: identical).

#figure(
  image("timeline.png", width: 100%),
  caption: [Timeline of the whole transfer, from the timestamped events (`out/events.csv`). Each round: the four stations send chunks (circles, labelled with the chunk number), the channel adds them (square), the receiver decodes all four (triangles).],
) <fig:timeline>

#figure(
  table(columns: (0.6fr, 0.7fr, 0.7fr, 0.7fr, 0.7fr, 1.1fr, 1fr),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    stroke: 0.5pt + luma(180), align: left + horizon,
    [*Round*],
    [*Station 0*],
    [*Station 1*],
    [*Station 2*],
    [*Station 3*],
    [*Channel sum (ms)*],
    [*Decoded OK*],
    [0],
    [0],
    [1],
    [2],
    [3],
    [4.3],
    [4 / 4],
    [1],
    [4],
    [5],
    [6],
    [7],
    [56.6],
    [4 / 4],
    [2],
    [8],
    [9],
    [10],
    [11],
    [108.5],
    [4 / 4],
    [3],
    [12],
    [13],
    [14],
    [15],
    [160.5],
    [4 / 4],
    [4],
    [16],
    [17],
    [18],
    [19],
    [212.2],
    [4 / 4],
    [5],
    [20],
    [21],
    [22],
    [23],
    [264.3],
    [4 / 4],
    [6],
    [24],
    [25],
    [26],
    [27],
    [316.2],
    [4 / 4],
    [7],
    [28],
    [29],
    [30],
    [31],
    [368.0],
    [4 / 4],
    [8],
    [32],
    [33],
    [34],
    [35],
    [424.0],
    [4 / 4],
    [9],
    [36],
    [37],
    [38],
    [39],
    [476.0],
    [4 / 4],
    [10],
    [40],
    [41],
    [42],
    [43],
    [531.9],
    [4 / 4],
    [11],
    [44],
    [45],
    [46],
    [47],
    [583.8],
    [4 / 4],
    [12],
    [48],
    [-],
    [-],
    [-],
    [637.2],
    [1 / 1]
  ),
  caption: [Which chunk (sequence number) each station spread in each round of the demo transfer. Chunk g is sent by station g mod N; the last round has fewer chunks.],
) <tab:rounds>

== Spreading, Summation and Decoding at Chip Level

@fig:signals shows round 0 at chip level for bits 40 to 47 of the frame, i.e. the first payload byte. Station 0 sends the bits 01000011, which is the ASCII character 'C'. Every station's waveform is a $plus.minus$ copy of its own Walsh row; the red trace is what the channel really carries, the sum of all stations (values between $-4$ and $+4$). No station can be read off the sum by eye, but @fig:corr shows that each decoder recovers its own bits exactly: the correlator outputs are exactly $+1$ or $-1$, with no leakage from the other stations.

#figure(
  image("signals.png", width: 100%),
  caption: [Round 0: chips transmitted by the four stations (blue, orange, green, red) and the composite signal on the channel (bottom, crimson).],
) <fig:signals>

#figure(
  image("correlations.png", width: 100%),
  caption: [Output of the four decoders on the composite signal: exactly $plus.minus 1$ for every bit, the interference of the other stations is exactly zero.],
) <fig:corr>

== Robustness Against Noise

With channel noise of standard deviation $sigma$ per chip the experiment of `--experiment noise` simulates all $n$ stations transmitting and measures the bit error rate of station 0 (@fig:ber, @tab:ber).

#figure(
  image("ber_vs_noise.png", width: 70%),
  caption: [Bit error rate versus noise $sigma$ for $n = L = 2, 4, 8, 16$. Markers: simulation; lines: theory $Q(sqrt(L) slash sigma)$.],
) <fig:ber>

#figure(
  table(columns: (0.6fr, 1fr, 1.1fr, 1.1fr, 1.1fr, 1.1fr),
    fill: (col, row) => if row == 0 { rgb("eef2f7") } else { none },
    stroke: 0.5pt + luma(180), align: left + horizon,
    [*n = L*],
    [*Gain (dB)*],
    [*BER sim, s=1*],
    [*BER theory, s=1*],
    [*BER sim, s=2*],
    [*BER theory, s=2*],
    [2],
    [3.0],
    [0.0808],
    [0.0786],
    [0.2409],
    [0.2398],
    [4],
    [6.0],
    [0.0222],
    [0.0228],
    [0.1588],
    [0.1587],
    [8],
    [9.0],
    [0.0026],
    [0.0023],
    [0.0794],
    [0.0786],
    [16],
    [12.0],
    [0.0000],
    [0.0000],
    [0.0222],
    [0.0228]
  ),
  caption: [Bit error rate of station 0 (40000 bits per point) with all n stations active.],
) <tab:ber>

*Observations.* Simulation and theory agree. For the same noise level a longer code gives a much lower error rate (at $sigma = 1$: 0.0808 for $L = 2$, 0.0222 for $L = 4$, 0.0000 for $L = 16$), which is the processing gain $10 log_10 L$ (6.0 dB for $L = 4$, 12.0 dB for $L = 16$). Without noise the BER is exactly zero for every $n$, as measured by T3.

== Code-Space Efficiency

#figure(
  image("efficiency.png", width: 70%),
  caption: [Fraction of the Walsh code space that is used by $n$ stations, $n slash L$.],
) <fig:eff>

All $L$ codes are used when $n$ is a power of two ($100 percent$). For other $n$ the next larger matrix is needed: $n = 3$ uses 75 percent, $n = 5$ only 62.5 percent and $n = 9$ 56.2 percent of the codes, so the chips per bit are higher than strictly necessary. The demo transfer carried 0.438 information bits per chip on the channel (7072 chips for 387 bytes); the rest is the frame overhead (9 bytes per 8 byte chunk) and the partly filled last round.



= Theoretical Analysis & Discussion

== Why Perfect Separation Works

Let station $i$ send the symbol $b_i in {-1, +1}$ in a bit period using code $c_i$ (length $L$). The channel output is
$ y = sum_(i=1)^n b_i c_i + eta $
where $eta$ is channel noise (zero in the noise-free case). Decoder $j$ computes
$ d_j = 1/L (y dot c_j) = b_j + 1/L sum_(i != j) b_i (c_i dot c_j) + (eta dot c_j) / L = b_j + eta_j. $
Because $c_i dot c_j = 0$ for $i != j$, the multi-user interference term vanishes *exactly*; only $eta_j$ remains, and for white Gaussian noise $eta_j tilde cal(N)(0, sigma^2 slash L)$. A hard decision $hat(b)_j = "sign"(d_j)$ errs with probability
$ P_b = Q(sqrt(L) / sigma), quad Q(x) = 1/2 "erfc"(x / sqrt(2)), $
which is the curve plotted in @fig:ber. The improvement from spreading is the processing gain $G_p = 10 log_10 L$ dB.

== Capacity and Spreading

Each station sends one bit per $L$ chips. With chip rate $R_c$ the bit rate per station is $R_c slash L$ and the aggregate rate is $n R_c slash L <= R_c$ with equality for $n = L$. CDMA therefore trades bandwidth (chips) for the ability of $n$ stations to be active at the same instant without any coordination of access.

== Assumptions and Limitations

- *Chip synchronisation.* Walsh codes are orthogonal only when all stations are aligned to the chip. The emulator guarantees this by lock-step rounds. In a real uplink, time offsets produce non-zero cross-correlation; IS-95 therefore uses Walsh codes only on the synchronous downlink and long PN codes on the uplink.
- *Equal power.* If one station is received much stronger than the others (near-far problem) any residual non-orthogonality of the other codes is amplified. The emulator gives all stations the same amplitude.
- *Number of codes.* At most $L$ stations fit in a code length $L$; adding stations requires doubling $L$, i.e. halving every station's bit rate.
- *Noise.* The channel is additive; fading and multipath are not modelled.

= Implementation Simplifications & Engineering Recommendations

+ *Single destination process.* As in the earlier assignments the receiver is one process; it hosts $n$ logical decoders, one per Walsh row, so all $n$ stations' data is reconstructed independently.
+ *Lock-step rounds over TCP.* A synchronous round makes the chip alignment exact and the timeline reproducible, at the price that stations must wait for the slowest one.
+ *JSON line protocol.* Chips are sent as JSON lists of integers; this is simple and debuggable but not compact.
+ *Possible extensions:* add a long PN scrambling code to emulate an asynchronous uplink, model per-station time offsets and amplitudes (near-far), add forward error correction and ARQ to recover frames that fail the CRC, and use OVSF codes to give stations different data rates.

= Comments and Conclusion

- The Walsh-coded CDMA emulation reconstructs the data of all $n$ stations perfectly: every test with noise-free channel gave a bit-exact file and correlator outputs of exactly $plus.minus 1$, confirming that interference between stations is exactly zero when the codes are orthogonal and chip-synchronised.
- Spreading costs bandwidth (each bit becomes $L$ chips) but provides a processing gain of $10 log_10 L$ dB against noise, as the measured BER curves match $Q(sqrt(L) slash sigma)$.
- The CRC-32 and sequence layer detect every corrupted frame in the heavy-noise test, so errors are never written silently into `received.txt`.
- Compared with the CSMA schemes of Assignment 3, CDMA has no collisions, no sensing and no backoff: access is by code rather than by contention. Its limits are the number of codes and the need for synchronisation.
