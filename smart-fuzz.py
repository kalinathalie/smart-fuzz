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

The wordlists download themselves on the first run, into a wordlists/
directory beside this script, and are reused after that.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

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


def fingerprint(url: str, timeout: int = 10) -> tuple[str, set[str]]:
    """What the target looks like it runs, as a set of extensions.

    One request. Everything it can go wrong with -- TLS, timeout, a reset --
    means the universal set, which is the honest answer rather than a
    guessed stack.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    signals: list[str] = []
    try:
        import ssl

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=context) as response:
            for key, value in response.headers.items():
                signals.append(f"{key}: {value}".lower())
            signals.append(response.read(8192).decode("utf-8", "replace").lower())
    except urllib.error.HTTPError as error:
        for key, value in (error.headers or {}).items():
            signals.append(f"{key}: {value}".lower())
    except Exception:  # noqa: BLE001 -- unreachable is not a stack
        return "unreachable", set(ALWAYS)

    haystack = " ".join(signals)
    found = set(ALWAYS)
    seen: list[str] = []
    for markers, extensions in BY_STACK:
        if any(marker in haystack for marker in markers):
            found.update(extensions)
            seen.append(markers[0])
    return ("+".join(seen) or "unknown"), found


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


def sweep(url: str, wordlist: Path, out: Path, rate: int, threads: int,
          maxtime: int, dry: bool) -> None:
    argv = [
        "ffuf", "-u", f"{url}/FUZZ", "-w", f"{wordlist}:FUZZ",
        # Everything except the one code that is certainly noise. Listing
        # what you expect is how you miss the 423 and the 502 you did not.
        "-mc", "all", "-fc", "404",
        "-ac",
        "-t", str(threads), "-rate", str(rate), "-timeout", "15",
        "-maxtime-job", str(maxtime),
        "-ic", "-se", "-noninteractive", "-s",
        "-H", f"User-Agent: {USER_AGENT}",
        "-o", str(out), "-of", "json", "-or",
    ]
    if dry:
        print("      " + " ".join(argv))
        return
    subprocess.run(argv, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("urls", type=Path, help="httpx output, one URL per line")
    parser.add_argument("--wordlists", type=Path, default=CACHE,
                        help=f"where the lists live; downloaded on first run "
                             f"(default: {CACHE})")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--rate", type=int, default=300,
                        help="requests per second per target (default: 300). "
                             "Lower it hard if the list has appliances in it")
    parser.add_argument("--threads", type=int, default=40)
    parser.add_argument("--maxtime", type=int, default=3600,
                        help="seconds per sweep (default: 3600)")
    parser.add_argument("--keep-case", action="store_true",
                        help="do not fold /Admin into /admin (Linux targets)")
    parser.add_argument("--dirs-only", action="store_true",
                        help="skip the file sweep, to measure the ground first")
    parser.add_argument("--dry-run", action="store_true",
                        help="fingerprint and print the commands, send nothing")
    args = parser.parse_args()

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
    print(f"[*] {len(targets)} target(s), {args.rate} req/s each")

    # One extras list per stack, not per target: hosts running the same
    # thing get the same list, and building it is not free.
    by_stack: dict[frozenset, Path] = {}
    plan = []
    for url in targets:
        url = url.rstrip("/")
        label, extensions = fingerprint(url)
        key = frozenset(extensions)
        if key not in by_stack and not args.dirs_only:
            name = out / "lists" / f"extras-{len(by_stack)}.txt"
            by_stack[key] = build_extras(args.wordlists, name, extensions, base_set)
        plan.append((url, label, by_stack.get(key)))
        extra = len(words(by_stack[key])) if key in by_stack else 0
        print(f"    {url:<48} {label:<16} +{extra:,} file terms")

    total = sum(len(words(base)) + (len(words(p)) if p else 0)
                for _, _, p in plan)
    print(f"[*] {total:,} requests in total, "
          f"roughly {total / args.rate / 3600:.1f} h at {args.rate}/s")

    for n, (url, _label, extras) in enumerate(plan, 1):
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", url.replace("://", "_"))
        print(f"[*] {n}/{len(plan)}  {url}")
        sweep(url, base, out / f"{slug}-dirs.json", args.rate, args.threads,
              args.maxtime, args.dry_run)
        if extras is not None:
            sweep(url, extras, out / f"{slug}-files.json", args.rate,
                  args.threads, args.maxtime, args.dry_run)

    print(f"[*] done. results in {out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
