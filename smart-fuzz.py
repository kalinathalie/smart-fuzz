#!/usr/bin/env python3
"""Content discovery over a list of URLs, sized by what each one runs.

Takes httpx output -- one absolute URL per line, scheme and port already
resolved, e.g. http://127.0.0.1:80.

Three things make it cheaper than pointing ffuf at a big list with -e:

  Directories and files are different vocabularies. Measured on SecLists:
  of 25,152 distinct filename stems in raft-large-files, 68% do not appear
  in raft-large-directories at all. So a directory list with -e does not
  cover what a file list covers -- it generates guesses like
  wp-content.php while missing wp-login.php. Both lists are used, each on
  its own axis, neither multiplied by the other.

  Extensions are chosen per target. One HEAD/GET at the root says whether
  it is IIS, PHP or Java, and the file list is filtered to match. An IIS
  host takes the 7,832 .asp/.aspx/.config entries and not the 11,484 .php
  ones -- between 67% and 98% of that list is dropped depending on the
  stack.

  The numbers come out. directory-list-2.3-medium is 31.4% pure numbers:
  69,239 of its 220,545 terms. With a dozen extensions that is 830,000
  requests per host asking for 1.php, 2.php, 3.php.

Wordlists are prepared once and cached, not per target.

Usage:
    python3 smart-fuzz.py urls.txt
    python3 smart-fuzz.py --generate fuzz-20260101-120000/

The wordlists download themselves on the first run, into a wordlists/
directory beside this script, and are reused after that. Every run ends
with a report.html over its output directory; --generate builds the same
report from a directory that already exists, without sending anything.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import html
import http.client
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

USER_AGENT = ("Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36")

#: Worth trying whatever the target runs: a forgotten backup or an editor's
#: leftover is not a property of the stack.
ALWAYS = ("bak", "old", "orig", "save", "swp", "txt", "log", "zip", "sql",
          "json", "xml", "yml", "conf", "ini")

#: Matched as lowercase substrings against the banner, headers, cookies and
#: a slice of the body. Ordered by what actually turns up: across 1040
#: fingerprinted hosts on four engagements, ASP.NET and IIS came to about
#: 305 of them and PHP to 194.
BY_STACK = (
    # Markers are substrings, so each one has to be distinctive on its own:
    # a bare "iis" matches ordinary words, and a bare "java" matches
    # "text/javascript" on any page with a script tag -- which fingerprinted
    # a static site as Tomcat and bought it 5,531 useless .jsp terms.
    (("asp.net", "microsoft-iis", "microsoft-httpapi", "aspsessionid",
      "asp.net_sessionid", "sharepoint", "sitecore", "umbraco", "kentico",
      "x-aspnet-version"),
     ("aspx", "asmx", "ashx", "axd", "asp", "config", "cshtml", "svc")),
    (("php", "phpsessid", "wordpress", "wp-content", "drupal", "joomla",
      "magento", "laravel", "symfony", "typo3", "x-powered-by: php"),
     ("php", "php5", "php7", "phps", "phtml", "inc")),
    (("tomcat", "jsessionid", "jboss", "wildfly", "jetty", "weblogic",
      "websphere", "coldfusion", "struts", "liferay", "servlet",
      "java/1.", "apache-coyote"),
     ("jsp", "jspx", "do", "action", "jar", "war", "cfm")),
    (("x-powered-by: express", "next.js", "nuxt", "node_modules",
      "webpack", "connect.sid"),
     ("map", "mjs", "cjs")),
    (("django", "flask", "gunicorn", "werkzeug", "wsgi", "csrftoken",
      "sessionid=.*django"),
     ("py", "pyc", "wsgi")),
    (("rails", "puma", "passenger", "_session_id", "phusion"),
     ("rb", "erb")),
)

#: Stems that earn an extension each. Short on purpose: these get
#: multiplied, and the measured reason they are worth it is that on one
#: engagement a 47-entry curated list produced 53 findings while 20,443
#: generic words produced 469 -- about 29 times the yield per word.
STEMS = """
config configuration settings env environment secret secrets credential
credentials password connection connectionstring appsettings application app
web site server local default backup backups bak old orig original copy new
temp tmp save archive release dist build db database data dump export import
sql mysql mssql postgres users user customers clients accounts members
employees staff payroll orders invoices transactions payments contacts
subscribers emails index main home admin administrator adm manage manager
console dashboard panel control login logon signin auth register signup
account profile upload uploads download downloads file files document
documents doc docs report reports log logs error errors debug trace test
tests dev development staging stage prod production demo sample example
phpinfo info status health version changelog readme license todo notes
package composer bower gulpfile gruntfile webpack makefile pom gradle
requirements pipfile gemfile yarn npm docker dockerfile compose nginx apache
httpd htaccess htpasswd robots sitemap crossdomain clientaccesspolicy
security vhost ssl cert certificate key keys private
""".split()

#: Paths worth one request each on every target, whatever it runs. These
#: carry their own extension and are not multiplied.
CURATED = """
.git/config .git/HEAD .git/index .svn/entries .hg/requires
.env .env.local .env.production .DS_Store .htaccess .htpasswd .npmrc
web.config appsettings.json elmah.axd trace.axd clientaccesspolicy.xml
crossdomain.xml server-status server-info phpinfo.php
swagger.json swagger/index.html openapi.json api-docs v2/api-docs
actuator actuator/env actuator/health actuator/heapdump
composer.lock package-lock.json yarn.lock Dockerfile docker-compose.yml
backup.zip backup.tar.gz db.sql dump.sql config.php.bak wp-config.php.bak
robots.txt sitemap.xml security.txt .well-known/security.txt
""".split()


#: Where the lists live when nobody says otherwise. Beside the script, so
#: it stays self-contained and a second run costs nothing.
CACHE = Path(__file__).resolve().parent / "wordlists"

SECLISTS = ("https://raw.githubusercontent.com/danielmiessler/SecLists/"
            "master/Discovery/Web-Content/")

#: name -> (url, smallest believable line count, required)
#:
#: The floor matters as much as the URL. GitHub answers a missing file with
#: a short HTML page and a 404 that urllib raises on, but a proxy, a
#: captive portal or a truncated transfer all produce a file that exists
#: and is wrong. A list that arrives at a tenth of its size would quietly
#: shrink the scan instead of failing it -- which is exactly how
#: directory-list-2.3-medium, dropped from SecLists, turned into a silent
#: four-hundred-fold reduction elsewhere.
WORDLISTS = {
    "raft-large-directories.txt": (SECLISTS + "raft-large-directories.txt",
                                   50_000, True),
    "raft-large-files.txt": (SECLISTS + "raft-large-files.txt", 30_000, True),
    "big.txt": (SECLISTS + "big.txt", 15_000, True),
    # Not on SecLists any more; this mirror still carries it. Optional
    # because it is 2.2 MB for terms the raft lists mostly already have,
    # and a third of it is pure numbers that get dropped anyway.
    "directory-list-2.3-medium.txt": (
        "https://raw.githubusercontent.com/dustyfresh/dictionaries/"
        "refs/heads/master/DirBuster-Lists/directory-list-2.3-medium.txt",
        200_000, False),
}


def usable(path: Path, floor: int) -> bool:
    """Whether a file on disk is the wordlist it claims to be."""
    try:
        if path.stat().st_size < 1024:
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if text.lstrip()[:400].lower().startswith(("<!doctype", "<html", "404:")):
        return False
    return sum(1 for line in text.splitlines() if line.strip()) >= floor


def fetch(name: str, url: str, floor: int, into: Path, timeout: int = 120) -> bool:
    """Download one list, and keep it only if it arrives whole.

    Written to a temporary name and moved into place, so an interrupted
    download cannot leave a half list that looks present on the next run.
    """
    target = into / name
    if usable(target, floor):
        return True

    partial = target.with_suffix(target.suffix + ".part")
    print(f"[*] fetching {name} ...", end=" ", flush=True)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            partial.write_bytes(response.read())
    except Exception as error:  # noqa: BLE001
        print(f"failed ({type(error).__name__})")
        partial.unlink(missing_ok=True)
        return False

    if not usable(partial, floor):
        n = sum(1 for _ in partial.open(encoding="utf-8", errors="replace"))
        print(f"rejected: {n:,} lines, expected at least {floor:,}")
        partial.unlink(missing_ok=True)
        return False

    partial.replace(target)
    lines = sum(1 for line in target.read_text(encoding="utf-8",
                                               errors="replace").splitlines()
                if line.strip())
    print(f"ok ({lines:,} terms)")
    return True


def ensure_wordlists(into: Path) -> Path:
    """Make sure every list this needs is on disk, and say so if not."""
    into.mkdir(parents=True, exist_ok=True)
    missing = []
    for name, (url, floor, required) in WORDLISTS.items():
        if fetch(name, url, floor, into):
            continue
        if required:
            missing.append(name)
        else:
            print(f"    carrying on without {name}")
    if missing:
        sys.exit("[!] could not get: " + ", ".join(missing) +
                 f"{chr(10)}    download them into {into} by hand and run again")
    return into


_PRINT = threading.Lock()


def say(line: str) -> None:
    """Print one line, whole. Ten workers writing at once otherwise tear
    each other's output in half."""
    with _PRINT:
        print(line, flush=True)


class Journal:
    """Everything the terminal was told, one JSON object per line.

    The terminal is the only place a run used to explain itself: which
    targets were skipped and why, which sweeps were cut or refused, at
    what rate. Once it scrolled off, the directory was a pile of files
    with no story. This is the story, appended as it happens, and the
    report is built from it. A path of None writes nothing (--dry-run).
    """

    def __init__(self, path: "Path | None") -> None:
        self.path = path
        self.lock = threading.Lock()

    def add(self, **fields) -> None:
        if self.path is None:
            return
        line = json.dumps(fields, ensure_ascii=False)
        with self.lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def host_of(url: str) -> str:
    """What counts as one machine for the purpose of not hammering it.

    The hostname alone, deliberately. http://x:80 and https://x:443 are
    usually the same service answering twice, and running both at once
    would double the rate against it while the pool still thinks it is
    being polite.
    """
    return (urlsplit(url).hostname or url).lower()


def _tls() -> ssl.SSLContext:
    """Talk to whatever certificate the target has. Discovery is not the
    place to be refusing self-signed appliances."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _why(error: BaseException) -> str:
    """A few words on why a request failed, for the person reading the plan."""
    if isinstance(error, urllib.error.URLError) and isinstance(error.reason,
                                                               BaseException):
        error = error.reason
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timed out"
    if isinstance(error, ConnectionRefusedError):
        return "connection refused"
    if isinstance(error, ConnectionResetError):
        return "connection reset"
    if isinstance(error, ssl.SSLError):
        return f"tls: {error.reason or type(error).__name__}"
    return str(error) or type(error).__name__


def warm_latency(url: str, timeout: int = 10) -> float:
    """How long one request takes once the connection is already up.

    The sweep runs over keep-alive connections, so TCP and TLS are paid
    once and not per word -- and on a VPN those handshakes are most of a
    cold request. Connect first, untimed; then time the request up to the
    first byte of the response. Raises on anything, and the caller falls
    back to the cold number it already has.
    """
    parts = urlsplit(url)
    host = parts.hostname or url
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(host, parts.port or 443,
                                           timeout=timeout, context=_tls())
    else:
        conn = http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)
    try:
        conn.connect()
        started = time.monotonic()
        conn.request("GET", parts.path or "/", headers={"User-Agent": USER_AGENT})
        conn.getresponse()
        return time.monotonic() - started
    finally:
        conn.close()


@dataclasses.dataclass
class Look:
    """What one URL looked like when asked."""
    url: str
    label: str              # the stack markers seen, "unknown", or "unreachable"
    extensions: set
    latency: float          # seconds per request on a warm connection
    why: str = ""           # when unreachable: what went wrong, in a few words


def fingerprint(url: str, timeout: int = 10) -> Look:
    """What the target looks like it runs, and how fast it answers.

    Two requests. The first is cold, through urllib, which follows
    redirects; its headers, cookies and first 8 KB of body are what the
    stack is read from. The second times one request on a connection that
    is already open, which is what each word of the sweep will cost. The
    cold timing used to stand in for it, and on a VPN it rated every host
    on the estate at 40/s -- it was measuring the path, not the host.

    Anything going wrong on the first request means unreachable, with a
    few words on why; nothing is guessed. The second one failing is not
    fatal, the cold number stands in.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    signals: list[str] = []
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=_tls()) as response:
            for key, value in response.headers.items():
                signals.append(f"{key}: {value}".lower())
            signals.append(response.read(8192).decode("utf-8", "replace").lower())
    except urllib.error.HTTPError as error:
        for key, value in (error.headers or {}).items():
            signals.append(f"{key}: {value}".lower())
    except Exception as error:  # noqa: BLE001 -- unreachable is not a stack
        return Look(url, "unreachable", set(ALWAYS), 0.0, _why(error))
    cold = time.monotonic() - started

    try:
        latency = warm_latency(url, timeout)
    except Exception:  # noqa: BLE001
        latency = cold

    haystack = " ".join(signals)
    found = set(ALWAYS)
    seen: list[str] = []
    for markers, extensions in BY_STACK:
        if any(marker in haystack for marker in markers):
            found.update(extensions)
            seen.append(markers[0])
    return Look(url, "+".join(seen) or "unknown", found, latency)


#: How many requests a host should have in flight at once. The rate that
#: follows from it is concurrency over latency: a box answering in 50 ms
#: takes 200 a second to keep ten in flight, one answering in two seconds
#: takes five. It is the same politeness either way, which a fixed rate is
#: not.
IN_FLIGHT = 10

#: Below this there is no point continuing; the host is not going to be
#: swept today whatever we do.
RATE_FLOOR = 5

#: How many words the calibration burst spends finding out.
PROBE_WORDS = 300


def rate_from_latency(latency: float, ceiling: int) -> int:
    """A first guess at what this host will take."""
    if latency <= 0:
        return ceiling
    return max(RATE_FLOOR, min(ceiling, int(IN_FLIGHT / latency)))


def time_cap(n: int, rate: int, explicit: "int | None") -> int:
    """How long a sweep of n words at this rate may run before it is cut.

    Twice what the list needs at the rate, plus two minutes: room for a
    host that slows down halfway, none for one that has quietly stopped.
    The two minutes are not padding -- ffuf takes six timeouts, ninety
    seconds, to decide a host is not answering, and a cap shorter than
    that would cut the sweep before it could say so.

    A fixed hour was the wrong unit. At 40/s the directory list needs 74
    minutes, and on an estate rated at 40/s every sweep was cut at 81%
    and reported as finished with nothing found.
    """
    if explicit:
        return explicit
    return int(n / max(rate, 1)) * 2 + 120


#: What ffuf's error log says when a request got no answer in time, as
#: opposed to a connection that was refused, reset or closed.
TIMEOUT_MARKS = ("timeout", "deadline exceeded")


def failures(errors: Path) -> list[str]:
    """The request errors in ffuf's debug log, one line each.

    The log also gets a note about a missing ~/.ffufrc on every run and
    the odd line about itself; a request error is the only kind that
    quotes a URL, so that is what is kept.
    """
    try:
        text = errors.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [line for line in text.splitlines() if '"http' in line]


def why_failed(errors: Path) -> str:
    """What kind of failure ffuf's debug log is full of.

    "timeout" when most failed requests simply got no answer; "refused"
    when the host closed or refused connections -- the only one of the two
    a lower rate can do anything about. Empty when no request failed.
    """
    lines = failures(errors)
    if not lines:
        return ""
    timeouts = sum(1 for line in lines
                   if any(mark in line.lower() for mark in TIMEOUT_MARKS))
    return "timeout" if timeouts * 2 >= len(lines) else "refused"


def tidy(errors: Path) -> None:
    """Drop the debug log when no request failed, which is the usual case."""
    if not failures(errors):
        errors.unlink(missing_ok=True)


def slug_of(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", url.replace("://", "_"))


def calibrate(url: str, wordlist: Path, start: int, threads: int,
              workdir: Path, dry: bool) -> tuple[int, str]:
    """The rate this host actually tolerates, found by asking it.

    A short burst at the candidate rate. ffuf says "spurious errors" and
    stops when requests start failing, and its error log says how. A host
    refusing or resetting connections is asking for less: halve and ask
    again. One that is not answering at all is not asking for anything,
    and no rate will change that, so it is written off on the first burst
    rather than the sixth -- which is what seven dead hosts on one
    engagement each cost, six minutes apiece to be told "refuses even
    5/s" when the truth was "does not answer".

    Returns (rate, "") when a rate stuck, (0, why) when the host is not
    having it.

    This is what the separate --dirs-only reconnaissance run was for. It
    costs about three hundred requests a host instead of a hundred and
    eighty thousand.
    """
    if dry:
        return start, ""

    probe = workdir / "probe.txt"
    try:
        sample = words(wordlist)[:PROBE_WORDS]
        probe.write_text("\n".join(sample) + "\n", encoding="utf-8")
    except OSError:
        return start, ""
    errors = workdir / f"{slug_of(url)}-probe.errors"

    rate = start
    while rate >= RATE_FLOOR:
        errors.unlink(missing_ok=True)
        argv = [
            "ffuf", "-u", f"{url}/FUZZ", "-w", f"{probe}:FUZZ",
            "-mc", "all", "-fc", "404", "-ac",
            "-t", str(threads), "-rate", str(rate), "-timeout", "10",
            "-maxtime-job", str(time_cap(len(sample), rate, None)),
            "-ic", "-se", "-noninteractive", "-s",
            "-H", f"User-Agent: {USER_AGENT}",
            "-debug-log", str(errors),
        ]
        try:
            done = subprocess.run(argv, capture_output=True, text=True,
                                  errors="replace")
        except OSError:
            return 0, "could not run ffuf"
        if "spurious errors" not in (done.stdout or "") + (done.stderr or ""):
            errors.unlink(missing_ok=True)
            return rate, ""
        if why_failed(errors) == "timeout":
            return 0, "no answer within 10s"
        rate //= 2
    return 0, f"refuses even {RATE_FLOOR}/s"


def words(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [w.strip() for w in lines if w.strip() and not w.startswith("#")]


def build_base(wordlists: Path, out: Path, keep_case: bool) -> Path:
    """The directory sweep: every directory list there is, cleaned once.

    Pure numbers go: directory-list-2.3-medium is 31.4% of them, and with
    extensions that is most of a million requests per host spent asking
    for 1.php. Case-duplicates go too unless --keep-case, which matters on
    Linux where /Admin and /admin are different paths.
    """
    if out.exists():
        return out
    seen, merged = set(), []
    sources = ["raft-large-directories.txt", "big.txt",
               "directory-list-2.3-medium.txt", "common.txt"]
    used = []
    for name in sources:
        found = words(wordlists / name)
        if not found:
            continue
        used.append(f"{name} ({len(found):,})")
        for word in found:
            if word.isdigit():
                continue
            key = word if keep_case else word.lower()
            if key in seen:
                continue
            seen.add(key)
            merged.append(word)
    if not merged:
        sys.exit(f"no directory wordlists found under {wordlists}")
    for word in CURATED:
        key = word if keep_case else word.lower()
        if key not in seen:
            seen.add(key)
            merged.append(word)
    out.write_text("\n".join(merged) + "\n", encoding="utf-8")
    print(f"[*] base: {len(merged):,} terms from {', '.join(used)} + curated")
    return out


def build_extras(wordlists: Path, out: Path, extensions: set[str],
                 base: set[str]) -> Path:
    """The file sweep for one stack: real filenames, then stems.

    raft-large-files already carries extensions, so it is filtered by the
    target's rather than multiplied. The stems are multiplied, because
    that is what they are for.
    """
    chosen: list[str] = []
    for name in words(wordlists / "raft-large-files.txt"):
        if "." not in name:
            continue
        if name.rsplit(".", 1)[1].lower() in extensions:
            chosen.append(name)
    for stem in STEMS:
        chosen += [f"{stem}.{ext}" for ext in sorted(extensions)]
    seen, kept = set(), []
    for word in chosen:
        key = word.lower()
        if key in seen or key in base:
            continue
        seen.add(key)
        kept.append(word)
    out.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return out


@dataclasses.dataclass
class Outcome:
    """What became of one ffuf pass."""
    status: str             # "ok", "cut", "refused", "timeout", "dry", "error"
    summary: str            # the one line that reaches the terminal
    hits: int = 0


def sweep(url: str, wordlist: Path, out: Path, rate: int, threads: int,
          maxtime: "int | None", dry: bool, label: str = "") -> Outcome:
    """One ffuf pass, and what became of it.

    ffuf's own output is captured rather than inherited. With ten workers
    it arrives as a column of bare words -- "images", "config", "api" --
    with nothing saying which host any of them came from, which is worse
    than no live output at all. It goes to a log beside the results, and
    what reaches the terminal is one attributed line per sweep.

    Three ways to end that are not "done", and each has to read
    differently from "done, nothing found", because for a long time one of
    them did not. Cut off by the time cap: reported with how much of the
    list went out. Refused: the host closed connections, and should be
    asked more slowly. Timed out: the host is not answering, and no rate
    will help.
    """
    total = len(words(wordlist))
    errors = out.with_suffix(".errors")
    argv = [
        "ffuf", "-u", f"{url}/FUZZ", "-w", f"{wordlist}:FUZZ",
        # Everything except the one code that is certainly noise. Listing
        # what you expect is how you miss the 423 and the 502 you did not.
        "-mc", "all", "-fc", "404",
        "-ac",
        "-t", str(threads), "-rate", str(rate), "-timeout", "15",
        "-maxtime-job", str(time_cap(total, rate, maxtime)),
        "-ic", "-se", "-noninteractive", "-s",
        "-H", f"User-Agent: {USER_AGENT}",
        # No -or. It asks ffuf to skip the file when nothing hit, and every
        # ffuf before 2.2 took it as "skip the file", full stop: a run of
        # fifty-nine targets came back with its hits on stdout only and not
        # one JSON on disk. An empty results file costs nothing.
        "-o", str(out), "-of", "json",
        # One line per failed request, with the reason. Empty on a good day.
        "-debug-log", str(errors),
    ]
    if dry:
        say("      " + " ".join(argv))
        return Outcome("dry", "dry")

    errors.unlink(missing_ok=True)
    started = time.monotonic()
    try:
        done = subprocess.run(argv, capture_output=True, text=True,
                              errors="replace")
    except OSError as error:
        return Outcome("error", f"could not run ffuf: {error}")
    took = time.monotonic() - started

    noise = (done.stdout or "") + (done.stderr or "")
    why = why_failed(errors)
    tidy(errors)

    hits = 0
    if out.exists():
        try:
            found = json.loads(out.read_text(encoding="utf-8"))
            hits = len(found.get("results") or [])
        except (json.JSONDecodeError, OSError):
            hits = 0

    # ffuf says this and stops when requests start failing in a burst.
    if "spurious errors" in noise:
        if why == "timeout":
            outcome = Outcome("timeout", f"{label}no answer within 15s, "
                                         f"gave up after {took:.0f}s", hits)
        else:
            outcome = Outcome("refused", f"{label}refused at {rate}/s "
                                         f"after {took:.0f}s", hits)
    # And this, only on stderr and only in the log, when the cap hits. It
    # read as "0 hit(s) in 3600s" for thirty sweeps running before anyone
    # noticed none of them had finished.
    elif "Maximum running time" in noise:
        sent = min(total, int(rate * took))
        outcome = Outcome("cut", f"{label}cut off after {took:.0f}s with "
                                 f"roughly {sent:,} of {total:,} sent, "
                                 f"{hits} hit(s) so far", hits)
    else:
        outcome = Outcome("ok", f"{label}{hits} hit(s) in {took:.0f}s", hits)

    # The summary goes in first, above ffuf's own words, so a report built
    # later reads the same line the terminal did.
    out.with_suffix(".log").write_text(outcome.summary + "\n" + noise,
                                       encoding="utf-8")
    return outcome


#: One HTML file over an output directory. Self-contained: no stylesheet,
#: script or font fetched from anywhere, so it opens on the box the scan
#: ran from. Built from the journal when there is one, and pieced together
#: from the files when there is not.

def unslug(stem: str) -> str:
    """Back from a result filename to a URL, for directories written
    before the journal existed. Exact for scheme://host[:port], which is
    what httpx hands over; a path in the URL comes back with its slashes
    as underscores, and that is as good as it gets."""
    match = re.match(r"^(https?)_(.+?)(?:_(\d{1,5}))?$", stem)
    if not match:
        return stem
    scheme, host, port = match.groups()
    return f"{scheme}://{host}" + (f":{port}" if port else "")


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def outcome_of(log: Path, errors: Path, kind: str, hits: int) -> "dict | None":
    """What became of one sweep, read back from its log.

    New logs start with the summary line the terminal got. Older ones
    hold only ffuf's parting words, and those still say whether the cap
    hit or the host stopped answering; the error log, when kept, says
    which of the two the latter was.
    """
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    first = text.split("\n", 1)[0]
    if first.startswith(f"{kind}: "):
        summary = first[len(kind) + 2:]
        status = ("cut" if summary.startswith("cut off") else
                  "refused" if summary.startswith("refused") else
                  "timeout" if summary.startswith("no answer") else "ok")
        return {"status": status, "summary": summary, "hits": hits}
    if "Maximum running time" in text:
        return {"status": "cut", "hits": hits,
                "summary": f"cut off by the time cap, {hits} hit(s) so far"}
    if "spurious errors" in text:
        if why_failed(errors) == "timeout":
            return {"status": "timeout", "hits": hits, "summary": "no answer"}
        return {"status": "refused", "hits": hits, "summary": "refused"}
    return {"status": "ok", "hits": hits, "summary": f"{hits} hit(s)"}


#: ffuf's parting words, which end the stdout part of a sweep's log.
NOTICES = ("No results and -or defined", "Receiving spurious errors",
           "Maximum running time", "Encountered an error")

#: Above this share of the list answering something other than 404, the
#: host is answering everything, and listing it would be listing the
#: wordlist. One such host put 123,556 "hits" in a log.
CATCHALL = 0.1


def printed(log: Path) -> list[str]:
    """What ffuf printed to stdout in silent mode: the matched words, one a
    line, before its parting notice.

    ffuf before 2.2 never wrote the JSON when -or was given, whatever hit,
    and for runs made with it this is the only record of what did. The
    status codes went with the JSON; the words did not.
    """
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found = []
    for line in text.splitlines():
        if line.startswith(("dirs: ", "files: ")):
            continue
        if line.startswith(NOTICES):
            break
        if line:
            found.append(line)
    return found


def gather(out: Path) -> tuple[list[dict], dict, list[dict]]:
    """What happened in one output directory: the targets in order, what
    became of each sweep, and every hit."""
    targets: dict[str, dict] = {}
    sweeps: dict[tuple, dict] = {}
    written_off: dict[str, str] = {}
    journal = out / "run.jsonl"
    if journal.is_file():
        for line in journal.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            event = record.get("event")
            if event == "target":
                targets[record["url"]] = record
            elif event == "sweep":
                sweeps[(record["url"], record["kind"])] = record
            elif event == "host" and record.get("skipped"):
                written_off[record["host"]] = record["note"]
    by_slug = {t["slug"]: t["url"] for t in targets.values()}

    # The lists each sweep drew from, to tell a hit from calibration noise
    # and a host with findings from a host answering everything.
    base = set(words(out / "lists" / "base.txt"))
    extras = [set(words(p)) for p in sorted((out / "lists").glob("extras-*.txt"))]

    hits: list[dict] = []
    stems = {(p.stem.rsplit("-", 1)[0], p.stem.rsplit("-", 1)[1])
             for p in out.iterdir()
             if p.is_file() and p.suffix in (".json", ".log", ".errors")
             and p.stem.endswith(("-dirs", "-files"))}
    for stem, kind in sorted(stems):
        found = read_json(out / f"{stem}-{kind}.json")
        url = by_slug.get(stem)
        if url is None:
            url = (found.get("config") or {}).get("url", "").replace("/FUZZ", "")
            url = url or unslug(stem)
            targets.setdefault(url, {"url": url, "slug": stem, "stack": "",
                                     "skipped": ""})

        if found:
            results = [{
                "target": url,
                "word": (hit.get("input") or {}).get("FUZZ", ""),
                "status": int(hit.get("status") or 0),
                "url": hit.get("url") or f"{url}/{(hit.get('input') or {}).get('FUZZ', '')}",
                "host": hit.get("host") or host_of(url),
                "length": int(hit.get("length") or 0),
                "type": (hit.get("content-type") or "").split(";")[0].strip(),
                "redirect": hit.get("redirectlocation") or "",
            } for hit in found.get("results") or []]
        else:
            results = [{"target": url, "word": w, "status": 0, "url": f"{url}/{w}",
                        "host": host_of(url), "length": 0, "type": "",
                        "redirect": ""} for w in printed(out / f"{stem}-{kind}.log")]
        pool: set = base
        if kind == "files" and extras:
            pool = max(extras, key=lambda s: sum(r["word"] in s for r in results))
        if pool and not found:
            results = [r for r in results if r["word"] in pool]

        if (url, kind) not in sweeps:
            seen = outcome_of(out / f"{stem}-{kind}.log",
                              out / f"{stem}-{kind}.errors", kind, len(results))
            if seen is not None:
                sweeps[(url, kind)] = seen
        if pool and len(results) > CATCHALL * len(pool):
            seen = sweeps.setdefault((url, kind), {"status": "ok", "summary": "",
                                                   "hits": len(results)})
            seen["summary"] = (f"catch-all: {len(results):,} of {len(pool):,} "
                               f"words answered, not listed")
            continue
        hits.extend(results)

    for url, target in targets.items():
        note = written_off.get(host_of(url))
        if note and (url, "dirs") not in sweeps and not target.get("skipped"):
            target["skipped"] = note
    hits.sort(key=lambda h: (h["status"], h["host"], h["url"]))
    return list(targets.values()), sweeps, hits


REPORT_STYLE = r"""
:root{color-scheme:light;--page:#f9f9f7;--card:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--mute:#898781;
--line:#e1e0d9;--ring:rgba(11,11,11,.10);--on:#0b0b0b;--onfg:#fcfcfb;--link:#1c5cab;
--c2:#1baf7a;--c3:#2a78d6;--c4:#eb6834;--c5:#6250d6;--c0:#898781}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--page:#0d0d0d;--card:#1a1a19;--ink:#f0efec;
--ink2:#c3c2b7;--mute:#898781;--line:#2c2c2a;--ring:rgba(255,255,255,.10);--on:#f0efec;--onfg:#1a1a19;
--link:#86b6ef;--c2:#199e70;--c3:#3987e5;--c4:#d95926;--c5:#9085e9;--c0:#898781}}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.top{padding:20px 24px 14px;border-bottom:1px solid var(--line);background:var(--card)}
.brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--mute)}
h1{font-size:20px;font-weight:650;margin:2px 0 16px}
.tiles{display:flex;flex-wrap:wrap;gap:28px;margin-bottom:16px}
.tile .v{display:block;font-size:24px;font-weight:650;line-height:1.1}
.tile .l{font-size:12px;color:var(--ink2)}
nav{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
nav button{font:inherit;font-size:13px;border:1px solid var(--line);background:var(--card);color:var(--ink);
padding:3px 10px;border-radius:999px;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
nav button b{font-weight:600;color:var(--ink2)}
nav button.on{background:var(--on);color:var(--onfg);border-color:var(--on)}nav button.on b{color:inherit}
nav input{font:inherit;font-size:13px;border:1px solid var(--line);background:var(--card);color:var(--ink);
padding:4px 10px;border-radius:999px;margin-left:auto;min-width:220px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex:none}
.c2{background:var(--c2)}.c3{background:var(--c3)}.c4{background:var(--c4)}.c5{background:var(--c5)}.c0{background:var(--c0)}
.note{margin:10px 0 0;font-size:12.5px;color:var(--ink2)}
.layout{display:grid;grid-template-columns:240px 1fr;gap:28px;padding:20px 24px;align-items:start}
aside{position:sticky;top:12px;max-height:calc(100vh - 24px);overflow:auto;font-size:13px}
aside .hd{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mute);margin:0 0 6px 8px}
aside a{display:grid;grid-template-columns:1fr auto;gap:3px 8px;padding:6px 8px;border-radius:8px;color:var(--ink)}
aside a:hover{background:var(--card);text-decoration:none}
aside a .n{color:var(--ink2);font-variant-numeric:tabular-nums}
aside a .bar{grid-column:1/3;height:4px}aside a.dim{opacity:.35}aside a.quiet{color:var(--ink2)}
.bar{display:flex;gap:2px;height:8px;border-radius:0 4px 4px 0;overflow:hidden}.bar i{display:block;min-width:2px}
section.host{margin-bottom:30px}
section.host>header{display:flex;flex-wrap:wrap;align-items:center;gap:4px 14px;margin:0 0 10px;padding-bottom:8px;border-bottom:1px solid var(--line)}
h2{font-size:16px;font-weight:650;margin:0}
.meta{color:var(--ink2);font-size:13px}
section.host>header .bar{flex:1 1 160px;max-width:320px}
details.target{background:var(--card);border:1px solid var(--ring);border-radius:10px;padding:0 14px;margin-bottom:10px}
details.target>summary{display:flex;flex-wrap:wrap;align-items:center;gap:4px 12px;padding:10px 0;cursor:pointer;list-style:none}
details.target>summary::-webkit-details-marker{display:none}
details.target>summary::before{content:"\25B8";color:var(--mute);width:10px;flex:none}
details.target[open]>summary::before{content:"\25BE"}
details.target>summary .url{font-weight:600}details.target>summary .bar{flex:0 0 120px;height:6px}
details.target.quiet{background:none;border-style:dashed;margin-bottom:8px}
details.target.quiet>summary{cursor:default;padding:7px 0}details.target.quiet>summary::before{content:"";width:0}
details.target.quiet>summary .url{font-weight:500;color:var(--ink2)}
table{border-collapse:collapse;width:100%;margin-bottom:10px}
.gh th{text-align:left;font-size:12.5px;font-weight:600;color:var(--ink2);padding:12px 0 4px}
.gh th .dot{margin-right:6px;vertical-align:1px}.gh th b{font-weight:400;color:var(--mute)}
td{padding:3px 10px 3px 0;vertical-align:top;border-top:1px solid var(--line);word-break:break-all}
.gh+tr td{border-top:0}
td.n{text-align:right;white-space:nowrap;color:var(--ink2);font-variant-numeric:tabular-nums;width:1%}
td.w{white-space:nowrap;color:var(--ink2);width:1%}td.r{color:var(--ink2)}
section.quiet td{border-top:1px solid var(--line)}section.quiet tr:first-child td{border-top:0}
section.quiet table{background:var(--card);border:1px solid var(--ring);border-radius:10px;padding:4px 14px}
.hidden{display:none}
@media(max-width:860px){.layout{grid-template-columns:1fr}aside{position:static;max-height:none}}
""".strip()

REPORT_SCRIPT = r"""
const rows=[...document.querySelectorAll('.grp tr:not(.gh)')],grps=[...document.querySelectorAll('.grp')],
tgts=[...document.querySelectorAll('details.target')],hosts=[...document.querySelectorAll('section.host:not(.quiet)')],
navs=[...document.querySelectorAll('aside a[data-h]')],q=document.getElementById('q'),
btns=[...document.querySelectorAll('nav button')];let st='';
function apply(){const t=q.value.toLowerCase(),on=!!(st||t);
for(const r of rows){const u=r.closest('details.target').dataset.t.toLowerCase();
r.classList.toggle('hidden',(st&&r.dataset.s!==st)||(t&&!(u+r.textContent.toLowerCase()).includes(t)))}
for(const g of grps)g.classList.toggle('hidden',!g.querySelector('tr:not(.gh):not(.hidden)'));
for(const d of tgts){const live=d.classList.contains('quiet')?!st&&(!t||d.dataset.t.toLowerCase().includes(t)):!!d.querySelector('.grp:not(.hidden)');
d.classList.toggle('hidden',!live);if(live&&on&&!d.classList.contains('quiet'))d.open=true}
for(const h of hosts)h.classList.toggle('hidden',!h.querySelector('details.target:not(.hidden)'));
for(const a of navs)a.classList.toggle('dim',document.getElementById(a.dataset.h).classList.contains('hidden'))}
for(const b of btns)b.onclick=()=>{st=b.dataset.s;btns.forEach(x=>x.classList.toggle('on',x===b));apply()};
q.oninput=apply;
""".strip()

#: Status class -> colour slot. Five fixed slots in a fixed order, validated
#: against both surfaces with the dataviz palette checks; "?" is the
#: muted ink, not a colour, because it is not a result.
CLASS_OF = {2: "c2", 3: "c3", 4: "c4", 5: "c5"}


def slot(status: int) -> str:
    return CLASS_OF.get(status // 100, "c0") if status else "c0"


def bar(counts: dict, extra: str = "") -> str:
    """A stacked bar of hits by status class, segments in fixed order,
    2px of surface between them, data end rounded."""
    total = sum(counts.values())
    if not total:
        return ""
    segments, title = [], []
    for cls in (2, 3, 4, 5, 0):
        n = sum(v for k, v in counts.items() if (k // 100 if k else 0) == cls)
        if n:
            segments.append(f'<i class="{CLASS_OF.get(cls, "c0")}" style="flex:{n}"></i>')
            title.append(f"{cls}xx {n:,}" if cls else f"? {n:,}")
    return (f'<div class="bar{extra}" title="{" · ".join(title)}">'
            f'{"".join(segments)}</div>')


def address_key(url: str) -> tuple:
    """Sort order for targets: numeric for IPs, so .5 comes before .10
    and the ports of one machine sit together."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    pieces = host.split(".")
    as_ip = tuple(int(p) for p in pieces) if pieces and all(p.isdigit() for p in pieces) else ()
    return (0 if as_ip else 1, as_ip, host, parts.port or 0, parts.scheme, url)


def report(out: Path) -> Path:
    """Write out/report.html and return its path.

    The host is the unit, because it is what the operator thinks in: one
    machine, its ports down the page, each port's hits grouped by status.
    A sticky list of hosts on the left, each with a bar of what it
    answered, is the map. Targets that found nothing go in one folded
    table at the end rather than between the ones that did, and every
    target says what became of its sweeps, so "nothing found" and "never
    finished" do not read the same here either.
    """
    targets, sweeps, hits = gather(out)
    esc = html.escape

    by_target: dict[str, list[dict]] = {}
    for hit in hits:
        by_target.setdefault(hit["target"], []).append(hit)
    by_host: dict[str, list[dict]] = {}
    for target in targets:
        by_host.setdefault(host_of(target["url"]), []).append(target)

    counts: dict[int, int] = {}
    for hit in hits:
        counts[hit["status"]] = counts.get(hit["status"], 0) + 1
    chips = [f'<button class="on" data-s="">all <b>{len(hits):,}</b></button>']
    for status in sorted(counts):
        chips.append(f'<button data-s="{status}"><i class="dot {slot(status)}"></i>'
                     f'{status or "?"} <b>{counts[status]:,}</b></button>')
    # Status 0 is a hit ffuf printed but never wrote to its JSON: every
    # ffuf before 2.2 dropped the file when -or was given. The word
    # survived on stdout; the status, size and type did not.
    note = ('<p class="note">? = hit printed by ffuf but never written to its '
            'JSON (ffuf before 2.2 with -or); status, size and type unknown. '
            'A run with the current script records them.</p>' if 0 in counts else "")
    tiles = "".join(f'<div class="tile"><span class="v">{v:,}</span><span class="l">{l}</span></div>'
                    for v, l in ((len(by_host), "hosts"), (len(targets), "targets"),
                                 (len(by_target), "targets with hits"), (len(hits), "hits")))

    def came_to(url: str) -> str:
        """One muted line on what the sweeps of a target amounted to."""
        target = next((t for t in targets if t["url"] == url), {})
        if target.get("skipped"):
            return "skipped: " + target["skipped"].replace(" -- skipped", "")
        parts = []
        for kind in ("dirs", "files"):
            seen = sweeps.get((url, kind))
            if seen:
                parts.append(f"{kind}: {seen['summary']}")
            elif kind == "files" and (sweeps.get((url, "dirs")) or {}).get("status") in ("refused", "timeout"):
                parts.append("files: skipped")
        return " · ".join(parts) or "not swept"

    def stack_of(url: str) -> str:
        return next((t.get("stack") or "" for t in targets if t["url"] == url), "")

    nav, sections, quiet = [], [], []
    for host in sorted(by_host, key=lambda h: address_key(f"x://{h}")):
        mine = sorted(by_host[host], key=lambda t: address_key(t["url"]))
        host_hits = [h for t in mine for h in by_target.get(t["url"], [])]
        if not host_hits:
            quiet.extend(mine)
            continue
        hid = "h-" + re.sub(r"[^A-Za-z0-9]+", "-", host)
        hcounts: dict[int, int] = {}
        for hit in host_hits:
            hcounts[hit["status"]] = hcounts.get(hit["status"], 0) + 1
        nav.append(f'<a href="#{hid}" data-h="{hid}"><span class="mono">{esc(host)}</span>'
                   f'<span class="n">{len(host_hits):,}</span>{bar(hcounts)}</a>')

        cards = []
        for target in mine:
            url = target["url"]
            th = by_target.get(url, [])
            stack = stack_of(url)
            head = (f'<a class="url mono" href="{esc(url, quote=True)}">{esc(url)}</a>'
                    + (f'<span class="meta">{esc(stack)}</span>' if stack else ""))
            if not th:
                cards.append(f'<details class="target quiet" data-t="{esc(url, quote=True)}">'
                             f'<summary>{head}<span class="meta">{esc(came_to(url))}</span></summary></details>')
                continue
            tcounts: dict[int, int] = {}
            for hit in th:
                tcounts[hit["status"]] = tcounts.get(hit["status"], 0) + 1
            groups = []
            for status in sorted(tcounts):
                rows = []
                for hit in (h for h in th if h["status"] == status):
                    path = hit["url"][len(url):] if hit["url"].startswith(url) else hit["url"]
                    size = f'{hit["length"]:,}' if status else ""
                    where = f"→ {esc(hit['redirect'])}" if hit["redirect"] else ""
                    rows.append(f'<tr data-s="{status}"><td class="mono"><a href="{esc(hit["url"], quote=True)}">'
                                f'{esc(path or "/")}</a></td><td class="n">{size}</td>'
                                f'<td class="w">{esc(hit["type"])}</td><td class="r mono">{where}</td></tr>')
                # One table per target, a tbody per status: the columns line
                # up across groups, which separate tables do not.
                groups.append(f'<tbody class="grp" data-s="{status}"><tr class="gh"><th colspan="4">'
                              f'<i class="dot {slot(status)}"></i>{status or "?"} <b>{len(rows):,}</b>'
                              f'</th></tr>{"".join(rows)}</tbody>')
            cards.append(f'<details class="target" data-t="{esc(url, quote=True)}"{" open" if len(th) <= 50 else ""}>'
                         f'<summary>{head}<span class="meta">{len(th):,} hits</span>{bar(tcounts)}'
                         f'<span class="meta">{esc(came_to(url))}</span></summary>'
                         f'<table>{"".join(groups)}</table></details>')
        sections.append(f'<section class="host" id="{hid}"><header><h2 class="mono">{esc(host)}</h2>'
                        f'<span class="meta">{len(mine)} target{"s" if len(mine) != 1 else ""} · '
                        f'{len(host_hits):,} hits</span>{bar(hcounts)}</header>{"".join(cards)}</section>')

    if quiet:
        nav.append(f'<a href="#quiet" class="quiet"><span>nothing found</span><span class="n">{len(quiet)}</span></a>')
        rows = "".join(f'<tr><td class="mono"><a href="{esc(t["url"], quote=True)}">{esc(t["url"])}</a></td>'
                       f'<td class="w">{esc(t.get("stack") or "")}</td><td class="r">{esc(came_to(t["url"]))}</td></tr>'
                       for t in sorted(quiet, key=lambda t: address_key(t["url"])))
        sections.append(f'<section class="host quiet" id="quiet"><header><h2>Nothing found</h2>'
                        f'<span class="meta">{len(quiet)} targets, and what became of each</span></header>'
                        f'<table>{rows}</table></section>')

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>smart-fuzz · {esc(out.name)}</title>
<style>{REPORT_STYLE}</style></head><body>
<header class="top"><div class="brand">smart-fuzz · {time.strftime('%Y-%m-%d %H:%M')}</div>
<h1>{esc(out.name)}</h1>
<div class="tiles">{tiles}</div>
<nav>{"".join(chips)}<input type="search" id="q" placeholder="filter paths, hosts"></nav>{note}
</header>
<div class="layout"><aside><p class="hd">Hosts</p>{"".join(nav)}</aside>
<main>{"".join(sections) or '<p class="meta">no targets</p>'}</main></div>
<script>{REPORT_SCRIPT}</script>
</body></html>
"""
    path = out / "report.html"
    path.write_text(page, encoding="utf-8")
    return path


def _by_host(plan: list) -> dict:
    """The plan grouped by machine, which is the unit of everything here:
    one rate, one worker, one calibration."""
    groups: dict[str, list] = {}
    for item in plan:
        groups.setdefault(host_of(item[0]), []).append(item)
    return groups


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("urls", type=Path, nargs="?",
                        help="httpx output, one URL per line")
    parser.add_argument("--generate", type=Path, metavar="DIR",
                        help="build DIR/report.html from an output directory "
                             "that already exists, finished or still running, "
                             "and exit. Sends nothing")
    parser.add_argument("--wordlists", type=Path, default=CACHE,
                        help=f"where the lists live; downloaded on first run "
                             f"(default: {CACHE})")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--rate", type=int, default=300,
                        help="ceiling for requests per second per host "
                             "(default: 300). Each host gets less than this "
                             "if it answers slowly or refuses the burst")
    parser.add_argument("--threads", type=int, default=40,
                        help="ffuf threads within one sweep (default: 40)")
    parser.add_argument("--no-calibrate", action="store_true",
                        help="do not probe each host for a rate it will "
                             "take; use --rate scaled by its latency and "
                             "nothing more")
    parser.add_argument("--concurrency", type=int, default=10,
                        help="how many hosts to work on at once (default: 10). "
                             "Never two sweeps against the same host: the "
                             "rate limit is per sweep, so that would double "
                             "it against one machine")
    parser.add_argument("--maxtime", type=int, default=None,
                        help="cap in seconds per sweep (default: twice what "
                             "the list needs at the host's rate, plus two "
                             "minutes)")
    parser.add_argument("--keep-case", action="store_true",
                        help="do not fold /Admin into /admin (Linux targets)")
    parser.add_argument("--dirs-only", action="store_true",
                        help="skip the file sweep, to measure the ground first")
    parser.add_argument("--dry-run", action="store_true",
                        help="fingerprint and print the commands, send nothing")
    args = parser.parse_args()

    if args.generate:
        if not args.generate.is_dir():
            return print(f"can't find {args.generate}") or 2
        print(f"[*] report at {report(args.generate)}")
        return 0
    if args.urls is None:
        parser.error("urls is required unless --generate is given")
    if not args.dry_run and shutil.which("ffuf") is None:
        return print("ffuf is not on PATH") or 1
    if not args.urls.is_file():
        return print(f"can't find {args.urls}") or 2
    ensure_wordlists(args.wordlists)

    out = args.out or Path(f"fuzz-{time.strftime('%Y%m%d-%H%M%S')}")
    (out / "lists").mkdir(parents=True, exist_ok=True)

    base = build_base(args.wordlists, out / "lists" / "base.txt", args.keep_case)
    base_set = {w.lower() for w in words(base)}

    targets = words(args.urls)
    print(f"[*] {len(targets)} target(s), up to {args.rate} req/s each")

    # Grouped by host from here on. Everything for one host happens in one
    # worker, in order; different hosts go in parallel.
    groups: dict[str, list[str]] = {}
    for url in targets:
        groups.setdefault(host_of(url), []).append(url.rstrip("/"))

    workers = max(1, min(args.concurrency, len(groups)))
    print(f"[*] {len(targets)} URL(s) across {len(groups)} host(s), "
          f"{workers} at a time")

    def look(host: str) -> list[Look]:
        found = []
        for url in groups[host]:
            looked = fingerprint(url)
            if looked.label == "unreachable":
                # Once more. One lost packet is not a dead host; two
                # timeouts in a row is as good as this gets.
                looked = fingerprint(url)
            found.append(looked)
        return found

    seen: list[Look] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for found in pool.map(look, list(groups)):
            seen.extend(found)

    # One extras list per stack, not per target: hosts running the same
    # thing get the same list, and building it is not free. Built here,
    # single-threaded, so two workers cannot write the same file at once.
    by_stack: dict[frozenset, Path] = {}
    plan = []
    slowest: dict[str, float] = {}
    journal = Journal(None if args.dry_run else out / "run.jsonl")
    for target in seen:
        url, label, latency = target.url, target.label, target.latency
        journal.add(event="target", url=url, slug=slug_of(url),
                    stack="" if label == "unreachable" else label,
                    skipped=target.why)
        if label == "unreachable":
            # The fingerprint is this tool's own evidence. Sweeping a URL it
            # could not reach costs ninety seconds to learn the same thing,
            # and calibrating a host of them cost six minutes to say
            # "refuses even 5/s" about a box that was not answering.
            print(f"    {url:<44} unreachable    {target.why} -- skipped")
            continue
        # The slowest answer from a host governs it: one service on it
        # being quick says nothing about the one that is not.
        host = host_of(url)
        slowest[host] = max(slowest.get(host, 0.0), latency)
        key = frozenset(target.extensions)
        if key not in by_stack and not args.dirs_only:
            name = out / "lists" / f"extras-{len(by_stack)}.txt"
            by_stack[key] = build_extras(args.wordlists, name, target.extensions,
                                         base_set)
        plan.append((url, label, by_stack.get(key)))
        extra = len(words(by_stack[key])) if key in by_stack else 0
        guess = rate_from_latency(latency, args.rate)
        print(f"    {url:<44} {label:<14} +{extra:>6,} terms  "
              f"{latency * 1000:>5.0f} ms -> {guess}/s")

    total = sum(len(words(base)) + (len(words(p)) if p else 0)
                for _, _, p in plan)
    # Per host at its own rate, then divided by the workers. Quoting the
    # ceiling here would be a lie by a factor of twenty on an estate of
    # slow appliances, and the estimate is the number someone decides
    # whether to start on.
    seconds = 0.0
    for host, items in _by_host(plan).items():
        rate = max(1, rate_from_latency(slowest.get(host, 0.0), args.rate))
        n = sum(len(words(base)) + (len(words(p)) if p else 0)
                for _, _, p in items)
        seconds += n / rate
    hours = seconds / 3600 / workers
    print(f"[*] {total:,} requests in total, roughly {hours:.1f} h "
          f"across {workers} worker(s), each host at its own rate")

    by_host = _by_host(plan)

    done = [0]

    def work(host: str) -> None:
        # One rate for the host, found once and then lowered whenever the
        # host says so: the latency gives a first guess, a short burst
        # says whether it holds, and a refused sweep says it no longer
        # does. This is what a separate --dirs-only run used to be for, at
        # three hundred requests instead of a hundred and eighty thousand.
        first = by_host[host][0][0]
        guess = rate_from_latency(slowest.get(host, 0.0), args.rate)
        if args.no_calibrate:
            rate, why = guess, ""
        else:
            rate, why = calibrate(first, base, guess, args.threads,
                                  out / "lists", args.dry_run)
        if rate == 0:
            say(f"    {host}  {why} -- skipped")
            journal.add(event="host", host=host, note=f"{why} -- skipped",
                        skipped=True)
            return
        if rate != guess:
            say(f"    {host}  settled at {rate}/s (asked for {guess}/s)")
            journal.add(event="host", host=host, note=f"settled at {rate}/s")

        def run(url: str, wordlist: Path, into: Path, kind: str) -> Outcome:
            result = sweep(url, wordlist, into, rate, args.threads,
                           args.maxtime, args.dry_run, f"{kind}: ")
            say(f"    {url}  {result.summary}")
            journal.add(event="sweep", url=url, kind=kind, rate=rate,
                        status=result.status, hits=result.hits,
                        summary=result.summary[len(kind) + 2:])
            return result

        def attempt(url: str, wordlist: Path, into: Path, kind: str) -> Outcome:
            # A refused sweep is the host saying "less", in the only way it
            # can. Halve, run this one again, and keep the lower rate for
            # the rest of the host. The printer whose https ports fell
            # over at the rate its http port had passed calibration at
            # was told "lower --rate" twice and swept at the same rate
            # both times; the one with the number is this script.
            nonlocal rate
            result = run(url, wordlist, into, kind)
            if result.status == "refused" and rate // 2 >= RATE_FLOOR:
                rate //= 2
                say(f"    {host}  dropping to {rate}/s for the rest of this host")
                journal.add(event="host", host=host, note=f"dropping to {rate}/s")
                result = run(url, wordlist, into, kind)
            if result.status == "refused":
                rate //= 2
            return result

        for url, _label, extras in by_host[host]:
            slug = slug_of(url)
            with _PRINT:
                done[0] += 1
                position = done[0]
            say(f"[*] {position}/{len(plan)}  {url}")
            dirs = attempt(url, base, out / f"{slug}-dirs.json", "dirs")
            if dirs.status in ("refused", "timeout"):
                # The file sweep is the same host at the same rate, and
                # sending it would be the same answer a second time.
                say(f"    {url}  skipping the file sweep")
            elif extras is not None:
                attempt(url, extras, out / f"{slug}-files.json", "files")
            if rate < RATE_FLOOR:
                note = f"refuses even {RATE_FLOOR}/s -- skipping the rest of this host"
                say(f"    {host}  {note}")
                journal.add(event="host", host=host, note=note, skipped=True)
                return

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(work, list(by_host)))

    if args.dry_run:
        print(f"[*] done. nothing sent; commands above")
        return 0
    print(f"[*] done. results in {out}/, report at {report(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
