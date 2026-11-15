# ML-KEM (CRYSTALS-Kyber) Benchmark

Supplementary code and experimental datasets for the review article:

> **CRYSTALS-Kyber (ML-KEM) in Practice: A Review of Implementation Security, Cryptanalysis, Protocol Integration and Applications, with an Experimental Comparison to Classical Key Establishment**  
> Neder Essayed — M.Sc. in Cybersecurity, Instituto Superior Politécnico Gaya (ISPGAYA), Vila Nova de Gaia, Portugal (November 2026)

## Experiments (`mlkem_benchmark.py`)
- **E1 – Primitive latency:** `KeyGen`, `Encaps`, and `Decaps` for `ML-KEM-768`, `ML-KEM-1024`, `X25519`, `ECDH P-256`, `RSA-2048 OAEP`, and `RSA-3072 OAEP`.
- **E2 – Complete key exchange:** End-to-end key agreement with `HKDF-SHA256` (`X25519`, `ML-KEM-768`, and hybrid `X25519MLKEM768`).
- **E3 – Bandwidth:** Client-to-server and server-to-client wire sizes (bytes).
- **E4 – Correctness & implicit rejection:** 50,000 encapsulation–decapsulation pairs and single-bit ciphertext mutation verification (FIPS 203).
- **E5 – Rejection timing:** Interleaved timing distribution comparison between valid and modified ciphertexts.

## Usage
```bash
pip install cryptography matplotlib
python mlkem_benchmark.py          # Full benchmark (5 runs x 3,000 iterations)
python mlkem_benchmark.py --quick  # Quick verification run
