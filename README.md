# smart-fuzz

Content discovery over a list of URLs, sized by what each one runs.

Point it at `httpx` output and it works out what each target is, picks the
extensions worth asking that target about, and sweeps directories and files
on separate axes instead of multiplying one by the other.

```bash
git clone https://github.com/kalinathalie/smart-fuzz
cd smart-fuzz
python3 smart-fuzz.py urls.txt --dry-run
```

The wordlists download themselves on the first run. The only dependency is
[ffuf](https://github.com/ffuf/ffuf) on `PATH`, and Python 3.9+.

## Why not just `ffuf -w big-list.txt -e .php,.bak`

Three measurements, each of which changed the design.

**Directories and files are different vocabularies.** Of the 25,152 distinct
filename stems in `raft-large-files`, 68% do not appear in
`raft-large-directories` at all. A directory list with `-e` does not cover
what a file list covers — it generates guesses like `wp-content.php` while
missing `wp-login.php`. So both lists are used, each on its own axis,
neither multiplied by the other.

**A third of the usual wordlist is numbers.** `directory-list-2.3-medium` is
220,545 terms, of which 69,239 are pure digits. With a dozen extensions that
is 830,000 requests per host asking for `1.php`, `2.php`, `3.php`. They are
dropped when the base list is built.

**Extensions belong to the target, not to the scan.** One request at the
root says whether a host is IIS, PHP or Java, and the file list is filtered
to match: an IIS host takes the 7,832 `.asp`/`.aspx`/`.config` entries and
not the 11,484 `.php` ones. Between 67% and 98% of that list is dropped
depending on the stack.

The fingerprint table is ordered by what actually turns up rather than by
habit. Across 1040 fingerprinted hosts on four engagements, ASP.NET and IIS
came to about 305 of them and PHP to 194 — so a PHP-shaped default would
have been wrong.

## What it sends

Two sweeps per target.

| sweep | wordlist | what it finds |
|---|---|---|
| directories | merged, cleaned, shared between targets | `/admin`, `/backup`, `/api` |
| files | per stack: real filenames, then stems × extensions | `config.bak`, `admin.aspx`, `db.sql` |

Roughly 180k requests for the first and 3–13k for the second, depending on
the stack. At the default 300 req/s that is about ten minutes a host.

Both use `-mc all -fc 404`: listing the codes you expect is how you miss the
one you did not. Autocalibration is on, the interactive console is off, and
every sweep has its own output file named with the scheme, because `httpx`
reports `http://host:80` and `https://host:443` for the same host and one
would otherwise overwrite the other.

## Usage

```
python3 smart-fuzz.py urls.txt [options]

  --dry-run      fingerprint every target, print the plan and the commands,
                 send no requests. Worth running first, always.
  --concurrency N  hosts to work on at once (default 10)
  --rate N       ceiling for requests per second per host (default 300);
                 each host gets less if it earns less
  --no-calibrate do not probe for a workable rate, just scale --rate by
                 the host's latency
  --threads N    concurrent threads (default 40)
  --maxtime N    cap per sweep in seconds (default: twice what the list
                 needs at the host's rate, plus two minutes)
  --dirs-only    skip the file sweep
  --keep-case    do not fold /Admin into /admin
  --wordlists D  use lists from D instead of downloading
  --out D        where results go (default: fuzz-<timestamp>/)
  --generate D   build D/report.html from an output directory that already
                 exists, finished or still running, and exit. Sends nothing.
  --recheck D    ask every hit in D that has no status code for one, a
                 single request each, then rebuild the report and exit.
```

`urls.txt` is `httpx` output: one absolute URL per line, scheme and port
already resolved.

```
http://127.0.0.1:80
https://wiki.intranet.local:443
```

### Three options worth thinking about

**`--concurrency`** works on ten hosts at once by default. Never two sweeps
against the same host, though: `--rate` is per sweep, so running
`http://x:80` and `https://x:443` together would quietly double the rate
against one machine, which on a list full of appliances is the opposite of
what the rate limit is for. URLs sharing a hostname go to one worker and
run in order.

**`--rate`** is a ceiling, not a setting. Each host gets the rate it earns,
in three steps. One request is timed on a connection that is already open,
and the rate that follows is ten requests in flight over that latency --
300/s for a host answering in 20 ms, 5/s for one taking two seconds. The
handshakes are left out on purpose: the sweep pays them once per
connection, not per word, and on a VPN they are most of a cold request. A
cold timing rated an entire /24 at 40/s once, because it was measuring the
tunnel.

Then a 300-word burst checks whether that holds. ffuf stops with "spurious
errors" when requests start failing, and its error log says how. A host
refusing or resetting connections is asking for less, so the rate halves
and the burst goes again until it sticks. A host that is not answering at
all is not asking for anything, and is written off on the first burst with
`no answer within 10s`. The two used to read the same, and a dead host cost
six bursts to be told "refuses even 5/s".

Then the sweep itself. A host that falls over halfway -- a printer whose
https ports cannot take the rate its http port passed calibration at --
gets the same treatment: the rate halves, that sweep runs again, and the
lower rate stays for the rest of the host. Refused twice, the sweep is
reported as refused at the rate it fell at and the host keeps dropping,
down to the floor.

URLs that did not answer the fingerprint do not get swept. The plan says
`unreachable  timed out -- skipped`, or `connection refused`, and that is
that; sweeping them cost ninety seconds each to learn the same thing.

That is what a separate reconnaissance run used to be for, at three hundred
requests a host instead of a hundred and eighty thousand. Printers, iDRACs
and switches end up at single digits without anyone having to list them.

**`--maxtime`** is a cap, not a budget, and it is derived rather than fixed:
twice what the list needs at the host's rate, plus two minutes. It is
there for a host that quietly stops answering without failing outright. A
fixed hour was the wrong unit: at 40/s the directory list needs 74 minutes,
and on an estate rated at 40/s every sweep was cut at 81% and reported as
`0 hit(s) in 3600s`, which looks exactly like a finished sweep. A cut sweep
now says so, and says how much went out:

```
dirs: cut off after 3600s with roughly 144,000 of 176,699 sent, 0 hit(s) so far
```

**`--keep-case`** matters on Linux, where `/Admin` and `/admin` are different
paths. The default folds them, which is right for IIS and loses about 11,000
terms elsewhere.

## Output

```
fuzz-20260101-120000/
  report.html           start here
  run.jsonl             what the terminal was told, one line each
  lists/
    base.txt            the merged directory list, built once
    extras-0.txt        one per distinct stack, not per target
  http_10.0.0.20_8080-dirs.json
  http_10.0.0.20_8080-dirs.log
  http_10.0.0.20_8080-dirs.errors
  http_10.0.0.20_8080-files.json
  http_10.0.0.20_8080-files.log
```

**`report.html`** is one page with nothing fetched from anywhere, so it
opens on the box the scan ran from. The host is the unit: a sticky list
of hosts on the left, each with a bar of what it answered by status
class, and down the page one section per host with its ports as cards,
each card's hits grouped by status code with size, type and redirect.
The status counts at the top filter everything, and so does the search
box. Every card says what became of its sweeps, so `nothing found` and
`never finished` do not read the same there either, and the targets that
found nothing sit in one table at the end rather than between the ones
that did. A host that answers everything is summarised as `catch-all:
123,556 of 176,699 words answered` rather than listed, because listing it
would be listing the wordlist.

`--generate DIR` builds the report again from a directory that already
exists, including one written before the report did. The `run.jsonl` is
the journal it is built from; without one, the same is pieced together
from the files below. Hits from a run made with ffuf older than 2.2 come
back with status `?`: that ffuf printed each hit and then, given `-or`,
never wrote the JSON. The words survived on stdout in the `.log`; the
status codes did not. `-or` is no longer passed for that reason, and
`--recheck DIR` fills the codes in after the fact: one request per `?`
path, one in flight per host, written to the journal and read by the
next report. Nothing is swept again.

The rest is evidence. ffuf's own JSON, one file per sweep. The `.log` is what ffuf said on the way out, which is how
you tell a cut sweep from a finished one after the fact. The `.errors` is
one line per failed request with the reason, kept only when something
failed -- it is the evidence behind `refused` and `no answer`, and the
file to read when either looks wrong.

## Wordlists

Downloaded on first run into `wordlists/`, and reused after that.

| list | source | required |
|---|---|---|
| `raft-large-directories.txt` | SecLists | yes |
| `raft-large-files.txt` | SecLists | yes |
| `big.txt` | SecLists | yes |
| `directory-list-2.3-medium.txt` | a mirror, SecLists dropped it | no |

Each is checked after it arrives: a file below its expected line count, or
one that turns out to be an HTML error page, is rejected and fetched again.
Downloads land on a temporary name and are moved into place only once they
pass, so an interrupted run cannot leave half a list looking complete.

This matters more than it sounds. A wordlist that arrives at a tenth of its
size does not fail — it quietly shrinks the scan, and the run looks fine.

## Authorisation

It sends tens of thousands of requests at every host in the file. Have
permission for all of them.
