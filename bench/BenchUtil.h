#ifndef CANXL_BENCH_BENCHUTIL_H
#define CANXL_BENCH_BENCHUTIL_H

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

namespace bench {

// Olcum sirasinda metotlarin bastigi [LOG] satirlarini susturmak icin
// stdout'u gecici olarak /dev/null'a yonlendirir (RAII: scope bitince geri gelir).
class SuppressStdout {
public:
    SuppressStdout() {
        std::fflush(stdout);
        m_saved = ::dup(fileno(stdout));
        m_devnull = ::open("/dev/null", O_WRONLY);
        if (m_devnull != -1) {
            ::dup2(m_devnull, fileno(stdout));
        }
    }
    ~SuppressStdout() {
        std::fflush(stdout);
        if (m_saved != -1) {
            ::dup2(m_saved, fileno(stdout));
            ::close(m_saved);
        }
        if (m_devnull != -1) {
            ::close(m_devnull);
        }
    }
    SuppressStdout(const SuppressStdout&) = delete;
    SuppressStdout& operator=(const SuppressStdout&) = delete;

private:
    int m_saved{-1};
    int m_devnull{-1};
};

// fn()'i once isitma (warmup) sonra `iters` kez calistirir; cagri basina
// ortalama nanosaniye dondurur. Tek bir kripto cagrisi cok kisa surdugu icin
// tek olcum guvenilmez -> binlerce kez tekrarlayip ortalama aliyoruz.
template <typename F>
double measureNs(std::size_t iters, F&& fn) {
    using clock = std::chrono::steady_clock;
    const std::size_t warmup = iters / 10 + 1;
    for (std::size_t i = 0; i < warmup; ++i) {
        fn();
    }
    const auto t0 = clock::now();
    for (std::size_t i = 0; i < iters; ++i) {
        fn();
    }
    const auto t1 = clock::now();
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    return static_cast<double>(ns) / static_cast<double>(iters);
}

// Cagri basina ns istatistikleri (hepsi ns cinsinden).
struct Stats {
    double min{};
    double mean{};
    double max{};
    double stddev{};
};

// Olcumu `reps` kez tekrarlar (her tekrar = `iters` cagrilik bir batch'in
// ortalamasi), tekrarlar arasi min/mean/max/stddev dondurur. Boylece sistem
// seviyesi degiskenligi (frekans olcekleme, zamanlama) yakalanir.
template <typename F>
Stats measureRepeated(std::size_t reps, std::size_t iters, F&& fn) {
    std::vector<double> samples;
    samples.reserve(reps);
    const std::size_t warmup = iters / 10 + 1;
    for (std::size_t i = 0; i < warmup; ++i) {
        fn();
    }
    for (std::size_t r = 0; r < reps; ++r) {
        samples.push_back(measureNs(iters, fn));
    }
    Stats s;
    s.min = *std::min_element(samples.begin(), samples.end());
    s.max = *std::max_element(samples.begin(), samples.end());
    double sum = 0.0;
    for (const double v : samples) sum += v;
    s.mean = sum / static_cast<double>(samples.size());
    double var = 0.0;
    for (const double v : samples) var += (v - s.mean) * (v - s.mean);
    s.stddev = std::sqrt(var / static_cast<double>(samples.size()));
    return s;
}

} // namespace bench

#endif
