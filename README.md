# b01lers CTF 2026 — Writeups

Writeups and exploit scripts for challenges from **b01lers CTF 2026**.

Each challenge lives in `<category>/<challenge>/` with:

- `README.md` — the writeup (TL;DR, recon, vulnerability, exploit walkthrough)
- `solve.py` / `exploit.*` — the working exploit, where applicable
- `flag.txt` — captured flag
- Original challenge artifacts (source, binaries, configs) where useful for context

Flag format: `bctf{...}`

---

## Index

### Crypto

| Challenge | Difficulty | Writeup |
|---|---|---|
| Sporadic Logarithms | Medium-Hard | [crypto/sporadic-logarithms](crypto/sporadic-logarithms/) |
| qss (Quantum Secret Sharing) | Hard | [crypto/qss](crypto/qss/) |

### Pwn

| Challenge | Difficulty | Writeup |
|---|---|---|
| Priority Queue | Medium-Hard | [pwn/priority-queue](pwn/priority-queue/) |
| Through The Wall (kernel) | Hard — unsolved (writeup of attempt) | [pwn/through-the-wall](pwn/through-the-wall/) |

### Reversing

| Challenge | Difficulty | Writeup |
|---|---|---|
| Shakespears Revenge | Hard | [rev/shakespears-revenge](rev/shakespears-revenge/) |
| tiles+ai | Hard | [rev/tiles-ai](rev/tiles-ai/) |
| Favorite Potato | Medium-Hard | [rev/favorite-potato](rev/favorite-potato/) |
| Piano | Hard (2 solves) | [rev/piano](rev/piano/) |
| Indirect Memory Access | Hard | [rev/indirect-memory-access](rev/indirect-memory-access/) |

### Web

| Challenge | Difficulty | Writeup |
|---|---|---|
| venmo me 67 | Medium | [web/venmo-me-67](web/venmo-me-67/) |
| clankers-market | Beginner | [web/clankers-market](web/clankers-market/) |

### Misc

| Challenge | Difficulty | Writeup |
|---|---|---|
| Reflections | Hard | [misc/reflections](misc/reflections/) |
| KOTH — Polyglot | Medium | [misc/koth-polyglot](misc/koth-polyglot/) |
| KOTH — Pickelang | Hard | [misc/koth-pickelang](misc/koth-pickelang/) |
| KOTH — Brainfuck | Medium-Hard | [misc/koth-brainfuck](misc/koth-brainfuck/) |

### Jail

| Challenge | Difficulty | Writeup |
|---|---|---|
| blazinglyfast | Hard | [jail/blazinglyfast](jail/blazinglyfast/) |

---

## Repo Layout

```
.
├── crypto/
├── jail/
├── misc/
├── pwn/
├── rev/
└── web/
```

## Running the Exploits

Most solve scripts target the live remote service from the CTF and will not work post-event. Where local source/Docker is provided in the challenge, the script can be pointed at a local instance.

Python solves typically need:

```bash
pip install pwntools pycryptodome requests
```

SageMath solves (where applicable) use SageMath 10.7.

## License

MIT — see [LICENSE](LICENSE).
