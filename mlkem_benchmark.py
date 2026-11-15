"""
ML-KEM benchmark for the article "CRYSTALS-Kyber (ML-KEM) in Practice" (N. Essayed).
Runs experiments E1-E5 and writes everything into the folder "results/".
Usage: python mlkem_benchmark.py   (full run)   |   python mlkem_benchmark.py --quick   (short test)
"""
import argparse, csv, json, os, platform, statistics, subprocess, sys, time
from datetime import datetime, timezone

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend as ossl_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
try:
    from cryptography.hazmat.primitives.asymmetric import mlkem
except ImportError:
    sys.exit("This version of 'cryptography' has no ML-KEM. Run: pip install --upgrade cryptography")

ns = time.perf_counter_ns
ENC, PUB = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def cpu_name():
    try:
        if sys.platform == "win32":
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-CimInstance Win32_Processor).Name"],
                                 capture_output=True, text=True, timeout=20).stdout.strip()
            if out:
                return out
        elif sys.platform == "darwin":
            return subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                  capture_output=True, text=True).stdout.strip()
        else:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("model name"):
                        return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def ram_gb():
    try:
        if sys.platform == "win32":
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"],
                                 capture_output=True, text=True, timeout=20).stdout.strip()
            return round(int(out) / 1024 ** 3, 1)
    except Exception:
        pass
    return None


def system_info(a):
    return {"date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "os": platform.platform(), "os_version": platform.version(),
            "machine": platform.machine(), "cpu": cpu_name(), "ram_gb": ram_gb(),
            "logical_cpus": os.cpu_count(), "python": sys.version.split()[0],
            "cryptography": cryptography.__version__,
            "openssl": ossl_backend.openssl_version_text(),
            "runs": a.runs, "iterations": a.iters, "rsa_keygen_iterations": a.rsa_keygen_iters,
            "correctness_pairs_per_run": a.pairs, "warmup": a.warmup}


def hkdf(secret):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mlkem-bench").derive(secret)


def timed(fn, n, warmup):
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(n):
        t0 = ns(); fn(); out.append(ns() - t0)
    return out


# ---------------- E1 primitives
def e1_primitives(n, n_rsa_kg, warmup):
    res = {}
    for name, cls in (("ML-KEM-768", mlkem.MLKEM768PrivateKey), ("ML-KEM-1024", mlkem.MLKEM1024PrivateKey)):
        sk = cls.generate(); pk = sk.public_key(); _, ct = pk.encapsulate()
        res[(name, "KeyGen")] = timed(cls.generate, n, warmup)
        res[(name, "Encaps")] = timed(pk.encapsulate, n, warmup)
        res[(name, "Decaps")] = timed(lambda: sk.decapsulate(ct), n, warmup)
    peer = x25519.X25519PrivateKey.generate(); peer_pub = peer.public_key()
    eph_pub = x25519.X25519PrivateKey.generate().public_key()
    res[("X25519", "KeyGen")] = timed(x25519.X25519PrivateKey.generate, n, warmup)
    res[("X25519", "Encaps")] = timed(lambda: x25519.X25519PrivateKey.generate().exchange(peer_pub), n, warmup)
    res[("X25519", "Decaps")] = timed(lambda: peer.exchange(eph_pub), n, warmup)
    curve = ec.SECP256R1()
    peer = ec.generate_private_key(curve); peer_pub = peer.public_key()
    eph_pub = ec.generate_private_key(curve).public_key()
    res[("ECDH P-256", "KeyGen")] = timed(lambda: ec.generate_private_key(curve), n, warmup)
    res[("ECDH P-256", "Encaps")] = timed(lambda: ec.generate_private_key(curve).exchange(ec.ECDH(), peer_pub), n, warmup)
    res[("ECDH P-256", "Decaps")] = timed(lambda: peer.exchange(ec.ECDH(), eph_pub), n, warmup)
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    for bits in (2048, 3072):
        name = f"RSA-{bits} OAEP"
        res[(name, "KeyGen")] = timed(lambda: rsa.generate_private_key(65537, bits), n_rsa_kg, 1)
        sk = rsa.generate_private_key(65537, bits); pk = sk.public_key()
        ct = pk.encrypt(os.urandom(32), oaep)
        res[(name, "Encaps")] = timed(lambda: pk.encrypt(os.urandom(32), oaep), n, warmup)
        res[(name, "Decaps")] = timed(lambda: sk.decrypt(ct, oaep), n, warmup)
    return res


# ---------------- E2 / E3 full exchange
def exchange_x25519():
    c = x25519.X25519PrivateKey.generate(); c_pub = c.public_key().public_bytes(ENC, PUB)
    s = x25519.X25519PrivateKey.generate(); s_pub = s.public_key().public_bytes(ENC, PUB)
    k_s = hkdf(s.exchange(x25519.X25519PublicKey.from_public_bytes(c_pub)))
    k_c = hkdf(c.exchange(x25519.X25519PublicKey.from_public_bytes(s_pub)))
    assert k_c == k_s
    return len(c_pub), len(s_pub)


def exchange_mlkem768():
    c = mlkem.MLKEM768PrivateKey.generate(); ek = c.public_key().public_bytes(ENC, PUB)
    ss_s, ct = mlkem.MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
    k_s = hkdf(ss_s); k_c = hkdf(c.decapsulate(ct))
    assert k_c == k_s
    return len(ek), len(ct)


def exchange_hybrid():
    c_kem = mlkem.MLKEM768PrivateKey.generate(); c_x = x25519.X25519PrivateKey.generate()
    c_share = c_kem.public_key().public_bytes(ENC, PUB) + c_x.public_key().public_bytes(ENC, PUB)
    ek, cx = c_share[:1184], c_share[1184:]
    ss_kem_s, ct = mlkem.MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
    s_x = x25519.X25519PrivateKey.generate()
    ss_x_s = s_x.exchange(x25519.X25519PublicKey.from_public_bytes(cx))
    s_share = ct + s_x.public_key().public_bytes(ENC, PUB)
    k_s = hkdf(ss_kem_s + ss_x_s)
    k_c = hkdf(c_kem.decapsulate(s_share[:1088]) + c_x.exchange(x25519.X25519PublicKey.from_public_bytes(s_share[1088:])))
    assert k_c == k_s
    return len(c_share), len(s_share)


EXCHANGES = {"X25519": exchange_x25519, "ML-KEM-768": exchange_mlkem768, "X25519MLKEM768": exchange_hybrid}


# ---------------- E4 correctness / implicit rejection
def e4_correctness(pairs):
    sk = mlkem.MLKEM768PrivateKey.generate(); pk = sk.public_key()
    failures = 0
    for _ in range(pairs):
        ss, ct = pk.encapsulate()
        if sk.decapsulate(ct) != ss:
            failures += 1
    ss, ct = pk.encapsulate()
    bad = bytearray(ct); bad[0] ^= 1; bad = bytes(bad)
    try:
        r1 = sk.decapsulate(bad); r2 = sk.decapsulate(bad); err = None
    except Exception as exc:
        r1 = r2 = None; err = repr(exc)
    return {"pairs": pairs, "failures": failures, "modified_ct_raised_error": err,
            "modified_ct_differs_from_original_secret": r1 is not None and r1 != ss,
            "modified_ct_deterministic": r1 is not None and r1 == r2}


# ---------------- E5 rejection timing (interleaved)
def e5_rejection_timing(n, warmup):
    sk = mlkem.MLKEM768PrivateKey.generate(); _, ct = sk.public_key().encapsulate()
    bad = bytearray(ct); bad[0] ^= 1; bad = bytes(bad)
    for _ in range(warmup):
        sk.decapsulate(ct); sk.decapsulate(bad)
    valid, modified = [], []
    for i in range(n):
        for c in ((ct, bad) if i % 2 == 0 else (bad, ct)):
            t0 = ns(); sk.decapsulate(c); dt = ns() - t0
            (valid if c is ct else modified).append(dt)
    return {("ML-KEM-768", "Decaps valid"): valid, ("ML-KEM-768", "Decaps modified"): modified}


def pct(v, p):
    k = (len(v) - 1) * p; f = int(k); c = min(f + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)


def summarize(vals):
    us = sorted(x / 1000 for x in vals)
    return {"n": len(us), "median_us": statistics.median(us), "mean_us": statistics.fmean(us),
            "sd_us": statistics.stdev(us) if len(us) > 1 else 0.0, "p5_us": pct(us, .05),
            "p95_us": pct(us, .95), "min_us": us[0], "max_us": us[-1]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5); ap.add_argument("--iters", type=int, default=3000)
    ap.add_argument("--rsa-keygen-iters", type=int, default=30); ap.add_argument("--pairs", type=int, default=10000)
    ap.add_argument("--warmup", type=int, default=200); ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    if a.quick:
        a.runs, a.iters, a.rsa_keygen_iters, a.pairs, a.warmup = 2, 200, 3, 500, 20
    os.makedirs(a.out, exist_ok=True)
    info = system_info(a); print(json.dumps(info, indent=2))
    json.dump(info, open(os.path.join(a.out, "system_info.json"), "w"), indent=2)

    raw_path = os.path.join(a.out, "raw_timings.csv"); rows, corr = [], []
    with open(raw_path, "w", newline="") as fr:
        w = csv.writer(fr); w.writerow(["run", "experiment", "algorithm", "operation", "iteration", "time_ns"])
        for run in range(1, a.runs + 1):
            print(f"\n=== Run {run}/{a.runs} ===")
            blocks = []
            t = time.time(); blocks.append(("E1", e1_primitives(a.iters, a.rsa_keygen_iters, a.warmup))); print(f"E1 done ({time.time()-t:.0f}s)")
            t = time.time(); blocks.append(("E2", {(k, "Exchange"): timed(f, a.iters, a.warmup) for k, f in EXCHANGES.items()})); print(f"E2 done ({time.time()-t:.0f}s)")
            t = time.time(); blocks.append(("E5", e5_rejection_timing(a.iters, a.warmup))); print(f"E5 done ({time.time()-t:.0f}s)")
            c = e4_correctness(a.pairs); c["run"] = run; corr.append(c); print(f"E4 done: {c['failures']} failures")
            for exp, res in blocks:
                for (alg, op), vals in res.items():
                    for i, v in enumerate(vals):
                        w.writerow([run, exp, alg, op, i, v])
                    rows.append({"run": run, "experiment": exp, "algorithm": alg, "operation": op, **summarize(vals)})

    keys = ["run", "experiment", "algorithm", "operation", "n", "median_us", "mean_us", "sd_us", "p5_us", "p95_us", "min_us", "max_us"]
    with open(os.path.join(a.out, "summary.csv"), "w", newline="") as f:
        dw = csv.DictWriter(f, fieldnames=keys); dw.writeheader(); dw.writerows(rows)

    final = {}
    for r in rows:
        final.setdefault((r["experiment"], r["algorithm"], r["operation"]), []).append(r["median_us"])
    bw = {k: dict(zip(("c_to_s", "s_to_c"), f())) for k, f in EXCHANGES.items()}
    with open(os.path.join(a.out, "final_table.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["experiment", "algorithm", "operation", "median_of_run_medians_us", "min_run_median_us", "max_run_median_us"])
        for (exp, alg, op), m in final.items():
            w.writerow([exp, alg, op, f"{statistics.median(m):.3f}", f"{min(m):.3f}", f"{max(m):.3f}"])
        for alg, b in bw.items():
            w.writerow(["E3", alg, "bytes C->S", b["c_to_s"], "", ""]); w.writerow(["E3", alg, "bytes S->C", b["s_to_c"], "", ""])

    tot = sum(c["failures"] for c in corr)
    json.dump({"total_pairs": a.pairs * a.runs, "total_failures": tot, "per_run": corr},
              open(os.path.join(a.out, "correctness.json"), "w"), indent=2)

    pooled = {"valid": [], "modified": []}
    with open(raw_path) as f:
        for row in csv.DictReader(f):
            if row["experiment"] == "E5":
                pooled["valid" if row["operation"].endswith("valid") else "modified"].append(int(row["time_ns"]))
    e5 = {k: summarize(v) for k, v in pooled.items()}
    e5["median_difference_percent"] = 100 * (e5["modified"]["median_us"] - e5["valid"]["median_us"]) / e5["valid"]["median_us"]
    json.dump(e5, open(os.path.join(a.out, "rejection_timing.json"), "w"), indent=2)

    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        algs = ["ML-KEM-768", "ML-KEM-1024", "X25519", "ECDH P-256"]
        fig, ax = plt.subplots(figsize=(6.6, 4.2), dpi=200)
        for j, op in enumerate(["KeyGen", "Encaps", "Decaps"]):
            bars = ax.bar([i + (j - 1) * .25 for i in range(4)], [statistics.median(final[("E1", g, op)]) for g in algs], .25, label=op)
            ax.bar_label(bars, fmt="%.1f", fontsize=6)
        ax.set_xticks(range(4), algs); ax.set_ylabel("Median latency (us)"); ax.legend(frameon=False)
        ax.spines[["top", "right"]].set_visible(False); fig.tight_layout(); fig.savefig(os.path.join(a.out, "fig2_latency.png"))
        fig, ax = plt.subplots(figsize=(6.6, 3.8), dpi=200)
        names = list(bw); cs = [bw[k]["c_to_s"] for k in names]; sc = [bw[k]["s_to_c"] for k in names]
        ax.bar(names, cs, label="Client to server"); ax.bar(names, sc, bottom=cs, label="Server to client")
        for i in range(len(names)):
            ax.text(i, cs[i] + sc[i] + 30, f"{cs[i] + sc[i]:,} B", ha="center", fontsize=8)
        ax.set_ylabel("Bytes on the wire"); ax.legend(frameon=False)
        ax.spines[["top", "right"]].set_visible(False); fig.tight_layout(); fig.savefig(os.path.join(a.out, "fig3_bandwidth.png"))
    except ImportError:
        print("matplotlib not installed: figures skipped")

    print("\n========== RESULTS (median of run medians, us) ==========")
    for (exp, alg, op), m in final.items():
        print(f"{exp:3} {alg:16} {op:16} {statistics.median(m):12.3f}")
    print("Bandwidth:", bw)
    print(f"E4: {tot} failures / {a.pairs * a.runs} pairs")
    print(f"E5: valid {e5['valid']['median_us']:.3f} us vs modified {e5['modified']['median_us']:.3f} us ({e5['median_difference_percent']:+.2f} %)")
    print(f"\nFiles written to: {os.path.abspath(a.out)}")


if __name__ == "__main__":
    main()