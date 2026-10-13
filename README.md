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
  --rate N       requests per second per target (default 300)
  --threads N    concurrent threads (default 40)
  --maxtime N    seconds per sweep (default 3600)
  --dirs-only    skip the file sweep
  --keep-case    do not fold /Admin into /admin
  --wordlists D  use lists from D instead of downloading
  --out D        where results go (default: fuzz-<timestamp>/)
```

`urls.txt` is `httpx` output: one absolute URL per line, scheme and port
already resolved.

```
http://127.0.0.1:80
https://wiki.intranet.local:443
```

### Two options worth thinking about

**`--rate`** defaults to 300, which suits a robust application on a network
you own. Printers, iDRACs, switches and other appliances with a web server
fall over well below that. If the list has any of those in it, start at 50.

**`--keep-case`** matters on Linux, where `/Admin` and `/admin` are different
paths. The default folds them, which is right for IIS and loses about 11,000
terms elsewhere.

## Output

```
fuzz-20260101-120000/
  lists/
    base.txt            the merged directory list, built once
    extras-0.txt        one per distinct stack, not per target
  http_10.0.0.20_8080-dirs.json
  http_10.0.0.20_8080-files.json
```

ffuf's own JSON, one file per sweep. Nothing is written for a sweep that
found nothing.

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
