# Hybrid IDS — the short version

*No jargon. If you want the engineering detail, read
[how_it_works.md](../Aalok/how_it_works.md) instead.*

---

## The problem

Right now, any computer connected to the internet is being scanned dozens of
times a day by automated tools looking for a way in. It is constant, and it is
invisible to the person using the machine.

Antivirus does not help much with this. Antivirus works from a wanted list — it
only recognises threats that somebody has already reported and catalogued. That
means it reacts *after* the damage, and it means the quiet attacks walk straight
past:

- someone trying every door handle on your network, one at a time, slowly enough
  that nothing looks unusual in any single moment
- someone guessing passwords all night
- malware that has already got in, quietly sending your files back out disguised
  as ordinary web traffic

The tools that *do* catch those exist. They cost thousands of dollars a year and
they need a trained analyst to sit in front of them and interpret the output.
That puts them out of reach of exactly the people with no other line of defence:
households, small businesses, anyone without an IT department.

Industry figures put the average time to identify and contain a breach at **258
days**, at an average cost of **US$4.88 million** (IBM Cost of a Data Breach
Report 2024, global averages).

---

## What we built

One system that watches your network traffic live, using two independent methods
at the same time.

**The first method** is the wanted list — a set of rules describing what known
attacks look like. It is fast and exact, and it never misses something it has
seen before.

**The second method** never saw that list. It was trained on what a normal day on
a network looks like, so it flags behaviour that is simply *wrong* — including
attacks nobody has catalogued yet.

Both examine the same traffic every two seconds. When they disagree, the system
takes the more serious answer. Rules alone miss anything new; a model alone is
noisy. Running both and trusting the worse verdict gives you coverage without
giving up accuracy.

---

## What makes it different

Most detection tools produce a wall of alerts that only an expert can act on.
This one is built for the person who is not an expert. Every alert comes with:

- **a threat score from 0 to 100**, and a risk band from Normal to Critical
- **the behaviour that triggered it**, written in plain English
- **what to do about it**
- **one button that blocks the source**, which really does change your firewall

It installs in about two minutes. On Windows it is a single file you double-click
— no Python, no configuration, no command line. It runs entirely on your own
machine; nothing is sent to a cloud service.

---

## Does it actually work

We attacked our own test network six different ways from a Kali Linux machine —
fast port scan, slow stealth scan, SYN flood, sustained low-rate flood, UDP
flood, and traffic to a known-malicious address.

**It caught all six.** Every alert appeared on screen in under four seconds. Each
one was caught by a different part of the system, which is the point of building
it in layers.

The full record of those tests, including what was launched and what the system
said about it, is in [TEST_RESULTS.md](../Aalok/TEST_RESULTS.md).

We also publish a report of every feature marked as working, partly working, or
broken — [FEATURE-TEST-REPORT.md](../FEATURE-TEST-REPORT.md). A project that only
reports its successes is not telling you much.

---

## What it costs

Nothing. No licence, no subscription, no per-device fee, no analyst to hire. The
source code is in this repository and the Windows app is a free download.

The 258-day industry blind spot becomes about four seconds, on hardware you
already own.

---

## The honest limitations

- **It watches one machine's traffic**, not a whole corporate network. It is
  built for a laptop, a home network, or a small office — not as a replacement
  for enterprise infrastructure.
- **It needs administrator rights** to capture packets. That is a real
  requirement, not a shortcut we took.
- **The firewall-block button is Windows-only.** On macOS and Linux it reports
  itself as unsupported rather than pretending to work.
- **It has no login screen.** It is only reachable from the machine it runs on,
  and that is the only thing keeping it private. See
  [SECURITY.md](../SECURITY.md).
- **Some of our headline accuracy numbers are agreement scores, not independent
  ones**, and we say so on the slides, in the report, and in the README. The
  genuinely independent evidence is the six live attacks.

---

## Where to go next

| | |
|---|---|
| Install it | [INSTALL.md](INSTALL.md) |
| Use it | [USAGE.md](USAGE.md) |
| Understand the engineering | [how_it_works.md](../Aalok/how_it_works.md) |
| Run it safely | [SECURITY.md](../SECURITY.md) |
