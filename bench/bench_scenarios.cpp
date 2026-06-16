// Best-case / worst-case senaryolar, N ECU icin Master'in kripto maliyeti.
// Her olcum REPS kez tekrarlanip min / ortalama / max raporlanir.
//
//   Best  : her ECU ilk denemede ACK verir.
//           Master: 1 KBKDF (kendi K_S) + N tag dogrulama.  Mesaj = N + 2.
//   Worst : her ECU R kez retry sonra ACK verir (R = MAX_TOTAL_RETRY_COUNTER).
//           Master: 1 KBKDF + N*(R+1) dogrulama.            Mesaj = (R+1)*N + 2.
//
// Kullanim:
//   cankeydist_bench_scenarios          -> okunabilir tablo
//   cankeydist_bench_scenarios --csv    -> CSV (cizim icin)

#include "BenchUtil.h"
#include "CANKeyDistrb.h"
#include "Mods.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

int main(int argc, char** argv) {
    const bool csv = (argc > 1 && std::strcmp(argv[1], "--csv") == 0);
    const std::vector<int> Ns = {1, 10, 50, 100, 200};
    constexpr std::size_t REPS = 10;
    constexpr std::size_t ITERS = 200;
    const int R = MAX_TOTAL_RETRY_COUNTER;   // 3

    CANKeyDistrb kd;
    kd.setNonce(0x0A, 1);
    kd.calculateSessionKeyKBKDF();
    const auto tag = kd.calculateSessionKeyTag(2, 555);

    volatile std::uint8_t sink = 0;

    struct Row { int n; bench::Stats best; bench::Stats worst; };
    std::vector<Row> rows;

    for (const int N : Ns) {
        bench::Stats best;
        bench::Stats worst;
        {
            bench::SuppressStdout guard;
            best = bench::measureRepeated(REPS, ITERS, [&] {
                kd.calculateSessionKeyKBKDF();
                for (int i = 0; i < N; ++i) {
                    bool ok = kd.checkSessionKeyIsCorrect(tag, 2, 555);
                    sink ^= ok ? 1 : 0;
                }
            });
            worst = bench::measureRepeated(REPS, ITERS, [&] {
                kd.calculateSessionKeyKBKDF();
                for (int i = 0; i < N * (R + 1); ++i) {
                    bool ok = kd.checkSessionKeyIsCorrect(tag, 2, 555);
                    sink ^= ok ? 1 : 0;
                }
            });
        }
        rows.push_back({N, best, worst});
    }

    const auto us = [](double ns) { return ns / 1000.0; };

    if (csv) {
        std::printf("N,best_min,best_mean,best_max,worst_min,worst_mean,worst_max,best_msg,worst_msg\n");
        for (const auto& r : rows) {
            std::printf("%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d\n",
                        r.n, us(r.best.min), us(r.best.mean), us(r.best.max),
                        us(r.worst.min), us(r.worst.mean), us(r.worst.max),
                        r.n + 2, (R + 1) * r.n + 2);
        }
        (void)sink;
        return 0;
    }

    std::printf("=== Senaryolar: Master kripto maliyeti (us, %zu tekrar) ===\n\n", REPS);
    std::printf("  Best  = 1 KBKDF + N dogrulama        | Worst = 1 KBKDF + N*(R+1) (R=%d)\n\n", R);
    std::printf("  %5s %26s %26s %10s %10s\n",
                "N", "best (min/mean/max)", "worst (min/mean/max)", "best msg", "worst msg");
    for (const auto& r : rows) {
        std::printf("  %5d   %7.1f /%7.1f /%7.1f   %7.1f /%7.1f /%7.1f %10d %10d\n",
                    r.n, us(r.best.min), us(r.best.mean), us(r.best.max),
                    us(r.worst.min), us(r.worst.mean), us(r.worst.max),
                    r.n + 2, (R + 1) * r.n + 2);
    }

    (void)sink;
    return 0;
}
