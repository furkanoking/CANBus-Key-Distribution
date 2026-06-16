// Tekil islem sureleri: her kripto operasyonu AYRI AYRI olculur. Olcum
// REPS kez tekrarlanip min / ortalama / max / stddev raporlanir.
//
// Kullanim:
//   cankeydist_bench_ops          -> okunabilir tablo
//   cankeydist_bench_ops --csv    -> CSV (cizim icin)

#include "BenchUtil.h"
#include "CANKeyDistrb.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    const bool csv = (argc > 1 && std::strcmp(argv[1], "--csv") == 0);
    constexpr std::size_t REPS = 20;
    constexpr std::size_t ITERS = 30000;

    CANKeyDistrb kd;
    kd.setNonce(0x0A, 1);
    volatile std::uint8_t sink = 0;

    const auto kbkdf = bench::measureRepeated(REPS, ITERS, [&] {
        auto k = kd.calculateSessionKeyKBKDF();
        sink ^= k[0];
    });
    const auto hkdf = bench::measureRepeated(REPS, ITERS, [&] {
        auto k = kd.calculateSessionKeyHKDF();
        sink ^= k[0];
    });

    kd.calculateSessionKeyKBKDF();                 // bilinen, sabit K_S
    const auto tag = kd.calculateSessionKeyTag(2, 555);

    const auto hash = bench::measureRepeated(REPS, ITERS, [&] {
        auto h = kd.calculateHASH();
        sink ^= h[0];
    });
    const auto tagGen = bench::measureRepeated(REPS, ITERS, [&] {
        auto t = kd.calculateSessionKeyTag(2, 555);
        sink ^= t[0];
    });

    bench::Stats verify;
    {
        bench::SuppressStdout guard;               // verify [LOG] satirlarini sustur
        verify = bench::measureRepeated(REPS, ITERS, [&] {
            bool ok = kd.checkSessionKeyIsCorrect(tag, 2, 555);
            sink ^= ok ? 1 : 0;
        });
    }

    const auto us = [](double ns) { return ns / 1000.0; };

    // Tcomp = KDF + HMAC tag. Bagimsiz varsayimiyla stddev'leri karekok-kareler ile birlestiriyoruz.
    const auto comb = [](const bench::Stats& a, const bench::Stats& b) {
        bench::Stats s;
        s.min = a.min + b.min;
        s.mean = a.mean + b.mean;
        s.max = a.max + b.max;
        s.stddev = std::sqrt(a.stddev * a.stddev + b.stddev * b.stddev);
        return s;
    };
    const bench::Stats tcompKbkdf = comb(kbkdf, tagGen);
    const bench::Stats tcompHkdf = comb(hkdf, tagGen);

    if (csv) {
        std::printf("operation,min_us,mean_us,max_us,stddev_us\n");
        const auto line = [&](const char* name, const bench::Stats& s) {
            std::printf("%s,%.4f,%.4f,%.4f,%.4f\n", name, us(s.min), us(s.mean), us(s.max), us(s.stddev));
        };
        line("KBKDF", kbkdf);
        line("HKDF", hkdf);
        line("SHA-256", hash);
        line("HMAC tag", tagGen);
        line("Verify", verify);
        line("Tcomp (KBKDF+tag)", tcompKbkdf);
        line("Tcomp (HKDF+tag)", tcompHkdf);
        (void)sink;
        return 0;
    }

    std::printf("=== Tekil islem sureleri (us/op, %zu tekrar x %zu iterasyon) ===\n\n", REPS, ITERS);
    std::printf("  %-22s %9s %9s %9s %9s\n", "Islem", "min", "mean", "max", "stddev");
    const auto row = [&](const char* name, const bench::Stats& s) {
        std::printf("  %-22s %9.4f %9.4f %9.4f %9.4f\n", name, us(s.min), us(s.mean), us(s.max), us(s.stddev));
    };
    row("KBKDF", kbkdf);
    row("HKDF", hkdf);
    row("SHA-256", hash);
    row("HMAC tag", tagGen);
    row("Verify", verify);

    std::printf("\n=== Nihai toplam: Tcomp = KDF + HMAC tag ===\n\n");
    row("Tcomp (KBKDF+tag)", tcompKbkdf);
    row("Tcomp (HKDF+tag)", tcompHkdf);
    std::printf("  KBKDF / HKDF orani (mean): %.2fx\n", kbkdf.mean / hkdf.mean);

    (void)sink;
    return 0;
}
