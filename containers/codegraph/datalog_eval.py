#!/usr/bin/env python3
"""Tiny stratified Datalog (stdlib). Runs a Souffle-subset program so the same
file works under `souffle`. Usage: datalog_eval.py prog.dl FACTS_DIR OUT_DIR
Supports: .decl/.input/.output lines, rules `h(X,Y) :- a(X,Z), !b(Z), X != Y.`,
string constants "x", wildcard _, = and !=. Facts: FACTS_DIR/<rel>.facts (TSV).
Naive-per-stratum evaluation: fine up to ~100k edges; use souffle beyond that."""

import re, sys, csv, os
from collections import defaultdict

prog = open(sys.argv[1], encoding="utf-8").read()
prog = re.sub(r"//.*", "", prog)
prog = re.sub(r"/\*.*?\*/", "", prog, flags=re.S)
outs = re.findall(r"\.output\s+(\w+)", prog)
ins = re.findall(r"\.input\s+(\w+)", prog)
body = "\n".join(l for l in prog.splitlines() if not l.strip().startswith("."))


def term(t):
    t = t.strip()
    return ("c", t[1:-1]) if t.startswith('"') else ("w", None) if t == "_" else ("v", t)


rules = []
for stmt in re.split(r"\.\s*(?:\n|$)", body):
    stmt = stmt.strip()
    if not stmt or ":-" not in stmt:
        continue
    h, b = stmt.split(":-", 1)
    hm = re.match(r"\s*(\w+)\s*\((.*)\)\s*$", h.strip(), re.S)
    head = (hm.group(1), [term(x) for x in hm.group(2).split(",")])
    lits = []
    for m in re.finditer(r"(!?)\s*(\w+)\s*\(([^()]*)\)|([\w\"]+)\s*(!=|=)\s*([\w\"]+)", b):
        if m.group(2):
            lits.append(
                (
                    "neg" if m.group(1) else "pos",
                    m.group(2),
                    [term(x) for x in m.group(3).split(",")],
                )
            )
        else:
            lits.append(("cmp", m.group(5), [term(m.group(4)), term(m.group(6))]))
    rules.append((head, lits))

db = defaultdict(set)
for r in ins:
    p = os.path.join(sys.argv[2], r + ".facts")
    if os.path.exists(p):
        for row in csv.reader(open(p, encoding="utf-8"), delimiter="\t"):
            db[r].add(tuple(row))

idb = {h[0] for h, _ in rules}
# stratify: a rule with !q needs q fully computed first
deps = {r: set() for r in idb}
neg = {r: set() for r in idb}
for h, lits in rules:
    for k, n, _ in lits:
        if k in ("pos", "neg") and n in idb:
            deps[h[0]].add(n)
            if k == "neg":
                neg[h[0]].add(n)
stratum = {r: 0 for r in idb}
for _ in range(len(idb) + 1):
    for r in idb:
        for d in deps[r]:
            stratum[r] = max(stratum[r], stratum[d] + (1 if d in neg[r] else 0))
if any(stratum[r] > len(idb) for r in idb):
    sys.exit("unstratifiable negation")


def val(t, env):
    return t[1] if t[0] == "c" else env.get(t[1])


def solve(lits, env, i=0):
    if i == len(lits):
        yield env
        return
    k, n, args = lits[i]
    if k == "cmp":
        a, b = val(args[0], env), val(args[1], env)
        if n == "!=" and a is not None and b is not None and a != b:
            yield from solve(lits, env, i + 1)
        elif n == "=":
            if a is None and b is not None:
                yield from solve(lits, {**env, args[0][1]: b}, i + 1)
            elif b is None and a is not None:
                yield from solve(lits, {**env, args[1][1]: a}, i + 1)
            elif a is not None and a == b:
                yield from solve(lits, env, i + 1)
        return
    if k == "neg":
        for row in db[n]:
            if all(t[0] == "w" or val(t, env) == x for t, x in zip(args, row)):
                return
        yield from solve(lits, env, i + 1)
        return
    for row in list(db[n]):
        e = dict(env)
        ok = True
        for t, x in zip(args, row):
            if t[0] == "w":
                continue
            v = val(t, e)
            if v is None:
                e[t[1]] = x
            elif v != x:
                ok = False
                break
        if ok:
            yield from solve(lits, e, i + 1)


for s in range(max(stratum.values(), default=0) + 1):
    rs = [r for r in rules if stratum[r[0][0]] == s]
    # order literals: positives first so negation/comparison vars are bound
    rs = [(h, sorted(l, key=lambda x: {"pos": 0, "cmp": 1, "neg": 2}[x[0]])) for h, l in rs]
    changed = True
    while changed:
        changed = False
        for h, lits in rs:
            for env in solve(lits, {}):
                row = tuple(val(t, env) for t in h[1])
                if None in row:
                    continue
                if row not in db[h[0]]:
                    db[h[0]].add(row)
                    changed = True

os.makedirs(sys.argv[3], exist_ok=True)
for r in outs:
    with open(os.path.join(sys.argv[3], r + ".csv"), "w", encoding="utf-8") as f:
        for row in sorted(db[r]):
            f.write("\t".join(row) + "\n")
