# Story Town — open proof-of-authorship checker

Checks a Story Town proof of authorship (a proof package `.zip`, a `.storytown` project file, or an `authorship/`
folder) on your own computer. It doesn't contact Story Town.

```
npm install
npm run check -- "Film - proof of authorship.zip"
# also confirm the Bitcoin blocks with block sources YOU choose:
npm run check -- "Film - proof of authorship.zip" --headers https://mempool.space/api --headers https://blockstream.info/api
```

It checks that every decision is chained to the one before, that each seal is signed by the creator's device key,
that Story Town's witness signatures are genuine, that the OpenTimestamps proofs lead to the Bitcoin blocks they name,
and that the creator's signed credit (name + title) matches its sealed fingerprint.

What it shows: when the decisions were recorded and that nothing changed since. The name is the creator's own signed
claim; it is evidence supporting that claim, not proof of who sat at the keyboard.

Format: `docs/authorship-ledger-v1.md`. Test vectors: `src/lib/authorship/vectors/`.
Exit codes: 0 checks out · 1 failed · 2 couldn't check (e.g. a block source didn't answer).

License: MIT (this checker and the format only; the Story Town app itself is not open source).
Online version: https://storytown.us/verify (runs in your browser; nothing is uploaded).
