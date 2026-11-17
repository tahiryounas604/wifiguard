# wifiguard

WiFi password security self-audit for **your own network**: capture
the WPA/WPA2 handshake, test it against a wordlist, and get a
plain-language verdict on whether your password survives.

Anyone in radio range of your home can capture your WiFi handshake
and crack it offline, at their leisure, with free tools. wifiguard
lets you run exactly that attack against yourself — guided, bounded,
and safety-gated — so you find out before someone else does.

> **Legal reminder: only audit networks you own or are explicitly
> authorized to test.** The tool enforces this in code (see
> [Safety design](#safety-design)).

## Features

- **`check`** — verifies the environment honestly before you start:
  Linux, root, the aircrack-ng suite, wireless interfaces, and
  whether any adapter actually advertises monitor mode (reported as
  "unknown" when it can't be determined — never guessed). Prints the
  exact `apt` command for anything missing.
- **`scan`** — passive, time-bounded (default 20s) airodump-ng scan
  rendered as a clean table: BSSID, ESSID (including `<hidden>`),
  channel, encryption, signal, connected clients.
- **`capture`** — targeted handshake capture for one BSSID/channel.
  Handshake presence is verified with aircrack-ng. An optional,
  capped `--deauth` burst can prompt your own device to reconnect.
  Always time-bounded.
- **`crack`** — wordlist attack on the capture with aircrack-ng, or
  with hashcat (mode 22000) when `hashcat` + `hcxpcapngtool` are
  installed. Reports found/not-found, time taken, and keys/sec.
- **`assess`** — pure-logic password strength assessor (no tools, no
  adapter needed): length, character classes, wordlist membership,
  common-pattern penalties (dictionary words incl. leetspeak,
  keyboard walks, repeats, year suffixes, phone-number shapes), an
  estimated offline crack time at a clearly stated rate assumption,
  and a Critical / Weak / Fair / Strong verdict with concrete fixes.
- **`report`** — combines capture + crack + assess results into
  `report.md` + `report.json` with remediation steps.
- **Standard library only.** wifiguard itself has no third-party
  dependencies; it drives the standard aircrack-ng / hashcat tools.

## Safety design

These are enforced in code (`src/wifiguard/safety.py` and the CLI),
not just written here:

- `capture` and `crack` **refuse to run** without the explicit
  `--i-own-this-network` flag.
- `--deauth` is opt-in (default 0 = passive only), **hard-capped at
  50 frames**, and can only target the BSSID you named — plus
  optionally one client MAC you supply (your own device).
- Captures (max 3600s) and scans (max 600s) are always time-bounded;
  nothing runs indefinitely.
- **No WPS attacks, no evil twin, no PMKID** — deliberately out of
  scope. This tool answers one question: "is my password strong
  enough?", nothing else.
- Every run prints a one-line legal reminder.

## Install

Python 3.11 or 3.12, on Linux, plus the system tools:

```bash
sudo apt install aircrack-ng          # required
sudo apt install hashcat hcxtools     # optional, faster cracking
git clone https://github.com/tahiryounas604/wifiguard.git
cd wifiguard
pip install .
# or run without installing:
PYTHONPATH=src python3 -m wifiguard --help
```

You also need a WiFi adapter that supports monitor mode, and root
(`sudo`) for scan/capture. Run `wifiguard check` first — it tells
you exactly what you have and what is missing.

## Usage

```bash
# 1. Verify the machine can do this at all
wifiguard check

# 2. See nearby networks (put the adapter in monitor mode first,
#    e.g. `sudo airmon-ng start wlan0`)
sudo wifiguard scan --interface wlan0mon --duration 20

# 3. Capture YOUR network's handshake
#    (the ownership flag is required — the tool refuses without it)
sudo wifiguard capture --bssid 8C:42:6D:6A:2F:70 --channel 6 \
    --interface wlan0mon --i-own-this-network --json-out capture.json
# If no device reconnects on its own, prompt your own phone:
#   ... --deauth 10 --client <your phone's MAC>

# 4. Try to crack it (wordlists: rockyou.txt is the classic;
#    SecLists has smaller, faster lists)
wifiguard crack wifiguard-capture-01.cap --wordlist rockyou.txt \
    --i-own-this-network --json-out crack.json

# 5. Assess a password directly — no capture needed
wifiguard assess --wordlist rockyou.txt --json-out assess.json
# (prompts without echo; or pass --password, noting shell history)

# 6. Combine everything into an audit report
wifiguard report --capture-json capture.json --crack-json crack.json \
    --assess-json assess.json --out-dir ./my-audit
```

Example `assess` output for a weak password:

```
Verdict: Critical  (score 5/100)
Length: 11   Classes: lowercase, digits
Estimated offline crack time: about a second (estimate at an
assumed 2,000,000 guesses/sec for WPA2 on a high-end GPU rig)
Issues:
  - Built on the common word 'pakistan' — dictionary attacks try
    such words with digits/symbols added.
Advice:
  - Change this password. Use at least 16 characters — for example
    3 random words plus a number and a symbol
    (e.g. 'lantern-river-42-giraffe!').
```

## Architecture

```
src/wifiguard/
├── safety.py     Ownership gate, deauth/duration caps, legal text
├── envcheck.py   `check`: tool/interface/monitor-mode probing
├── scanparse.py  airodump-ng CSV parsing (pure) + table rendering
├── scanner.py    `scan`: bounded airodump-ng run
├── capture.py    `capture`: targeted capture, handshake detection
├── crack.py      `crack`: aircrack-ng / hashcat 22000, result parsing
├── strength.py   `assess`: scoring, patterns, crack-time estimate
├── report.py     `report`: report.md / report.json generation
└── cli.py        argparse CLI wiring the subcommands together
```

Every parser (airodump CSV, handshake detection, `KEY FOUND!`,
hashcat `--show`) is a pure function, and every subprocess call is
injectable — so the full test suite passes on a machine with **no**
aircrack-ng installed.

## Tests

```bash
python -m pytest -q
```

65 tests, covering: airodump CSV parsing (hidden ESSIDs, ESSIDs containing
commas, the station section, unassociated stations), handshake
detection parsing, `KEY FOUND!` / not-found parsing, hashcat
parsing, the strength scorer (known-bad passwords score Critical;
strong passphrases score Strong), report generation, environment
checks with mocked tools, and the CLI safety paths — capture/crack
without `--i-own-this-network` exit non-zero with the refusal
message, and the deauth cap is enforced.

## Honest limits

- **Linux, root, and a monitor-mode-capable adapter are required**
  for scan/capture. Many built-in laptop adapters cannot do monitor
  mode (or cannot inject, which `--deauth` needs). `wifiguard check`
  reports what your hardware advertises before you waste time.
- **Cracking speed depends entirely on your hardware.** aircrack-ng
  on a laptop CPU manages thousands of guesses/sec; a GPU hashcat
  rig manages millions. The same password can take minutes or
  centuries depending on who is attacking it — the `assess` estimate
  states its rate assumption (2M guesses/sec) explicitly.
- **"Not found" means "not in this wordlist" — never "uncrackable".**
  A bigger wordlist, rule-based mutations, or a longer run may
  still find a short or patterned password.
- **WPA3-SAE is not susceptible to this method.** SAE's handshake
  cannot be taken offline and dictionary-attacked the way WPA2's
  can. If the scan shows WPA3, this tool's crack step does not
  apply — which is precisely why the report recommends WPA3.
- **Reports can contain your recovered password.** That is the
  point of the audit — and why you should keep `report.md` /
  `report.json` private and delete them when done.
- **Your network only.** Capturing handshakes from, or
  deauthenticating, networks you do not own is illegal in most
  jurisdictions. The ownership flag is a deliberate speed bump, not
  a legal shield — the responsibility is yours.

## License

GPL-3.0 — see [LICENSE](LICENSE).

## Author

Tahir Younas — Tytechlabs — https://www.linkedin.com/in/tahiryounas604
