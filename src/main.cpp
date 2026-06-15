#include "CANKeyDistrb.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

static void printKey(const char* name, const std::array<uint8_t, 16>& key) {
    std::printf("%s: ", name);
    for (const auto byte : key) {
        std::printf("%02x", byte);
    }
    std::printf("\n");
}

// Tamamlanma callback'i: tum ECU'lar K_S'yi onaylayinca cagrilir.
// Sadece log basar. setOnAllConfirmed'e isimli fonksiyon olarak verilir
// (std::function lambda'yi da, normal fonksiyonu da kabul eder).
static void onAllEcusConfirmed() {
    std::printf(">>> [APP] All ECUs confirmed the session key — AES-GCM communication can start.\n");
}

static std::string toHex8(const std::array<uint8_t, 8>& tag) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (const auto b : tag) {
        s.push_back(d[(b >> 4) & 0x0F]);
        s.push_back(d[b & 0x0F]);
    }
    return s;
}

static const char* stateName(ECU_State s) {
    switch (s) {
    case ECU_State::INITIAL_STATE:         return "INITIAL_STATE";
    case ECU_State::WAITING_THE_RESPONSE:  return "WAITING_THE_RESPONSE";
    case ECU_State::RECEIVED_THE_RESPONSE: return "RECEIVED_THE_RESPONSE";
    case ECU_State::RESENT_THE_INPUTS:     return "RESENT_THE_INPUTS";
    }
    return "?";
}

static void printEcuTable(const CANKeyDistrb& kd) {
    std::printf("  ECU tablosu (%zu adet):\n", kd.getECUTable().size());
    for (const auto& [id, mode] : kd.getECUTable()) {
        std::printf("    ECU-%-2u  durum=%-22s retry=%d\n",
                    id, stateName(mode.ecu_state), mode.retry_counter);
    }
}

int main() {
    CANKeyDistrb keyDist;
    printKey("K_M (master)        ", keyDist.getMasterKey());

    // --- Tazelik: ayni ECU, FARKLI Counter -> FARKLI K_S ---
    keyDist.setNonce(10, 1);
    printKey("K_S (ECU=10, ctr=1) ", keyDist.calculateSessionKeyKBKDF());

    keyDist.setNonce(10, 2);
    printKey("K_S (ECU=10, ctr=2) ", keyDist.calculateSessionKeyKBKDF());

    // --- Determinizm: AYNI nonce -> AYNI K_S (her ECU ayni anahtari turetir) ---
    keyDist.setNonce(10, 1);
    printKey("K_S (ECU=10, ctr=1) ", keyDist.calculateSessionKeyKBKDF());  // ilkiyle ayni olmali

    // --- KBKDF vs HKDF ayni nonce'la farkli sonuc verir ---
    printKey("K_S (HKDF, same)    ", keyDist.calculateSessionKeyHKDF());
    printKey("HASH(K_S)           ", keyDist.calculateHASH());

    // --- ECU tablosu ---
    std::printf("\n=== ECU tablosu ===\n");
    std::printf("\n[Baslangic] varsayilan 10 ECU:\n");
    printEcuTable(keyDist);

    std::printf("\n[Master ECU-3 ve ECU-7'ye parametre yolladi]\n");
    keyDist.markDataSent(3);
    keyDist.markDataSent(7);
    printEcuTable(keyDist);

    // Master kendi K_S'sini turetir; dogru bir ECU'nun yollayacagi tag'i uretebilir.
    keyDist.setNonce(0x0A, 1);
    keyDist.calculateSessionKeyKBKDF();
    const auto goodTag3 = keyDist.calculateSessionKeyTag(3, 333);   // ECU-3'un dogru tag'i
    std::array<uint8_t, 8> badTag7 = keyDist.calculateSessionKeyTag(7, 777);
    badTag7[0] ^= 0xFF;                                             // ECU-7'nin BOZUK tag'i

    std::printf("\n[ECU-3 dogru tag yolladi -> KABUL; ECU-7 bozuk tag -> RED]\n");
    keyDist.markResponseReceived(3, goodTag3, 333);  // dogru -> RECEIVED
    keyDist.markResponseReceived(7, badTag7, 777);   // bozuk -> reddedilir, ECU-7 WAITING kalir
    printEcuTable(keyDist);

    std::printf("\n[ECU-10 cikarildi, ECU-99 eklendi]\n");
    keyDist.removeECU(10);
    keyDist.addECU(99);
    printEcuTable(keyDist);

    // --- Retry limiti + abort (checkECUs'u dogrudan cagirarak, thread'siz) ---
    std::printf("\n[ECU-7 hala cevapsiz: checkECUs'u 4 kez calistir -> 3 retry sonra ABORT]\n");
    for (int round = 1; round <= 4; ++round) {
        std::printf("--- tur %d ---\n", round);
        keyDist.checkECUs();
    }
    std::printf("ECU-7 son durum: %s, retry=%d\n",
                stateName(keyDist.getECUState(7)), keyDist.getRetryCounter(7));

    // --- Session key dogrulama (key confirmation) ---
    std::printf("\n=== Session Key Dogrulama ===\n");

    // Master ile bir ECU AYNI nonce ile K_S turetir (iki ayri nesne).
    CANKeyDistrb master;
    CANKeyDistrb ecu2;
    master.setNonce(0x0A, 1);
    ecu2.setNonce(0x0A, 1);
    master.calculateSessionKeyKBKDF();
    ecu2.calculateSessionKeyKBKDF();

    // ECU-2 kendi ACK nonce'u (counter=555) ile tag'ini uretir.
    const std::uint64_t ackNonce = 555;
    auto tag = ecu2.calculateSessionKeyTag(2, ackNonce);
    std::printf("[ECU-2 uretti] ecuId=2 nonce=%llu tag = %s\n",
                (unsigned long long)ackNonce, toHex8(tag).c_str());

    // Master, ACK'ten gelen ayni nonce ile dogrular.
    std::printf("\n[Dogru tag + dogru nonce] -> ");
    bool ok = master.checkSessionKeyIsCorrect(tag, 2, ackNonce);
    std::printf("    sonuc: %s\n", ok ? "KABUL" : "RED");

    // Bozulma: tag'in bir byte'ini degistir -> reddedilmeli.
    auto tampered = tag;
    tampered[0] ^= 0xFF;
    std::printf("\n[Bozulmus tag] -> ");
    bool bad = master.checkSessionKeyIsCorrect(tampered, 2, ackNonce);
    std::printf("    sonuc: %s\n", bad ? "KABUL" : "RED");

    // Yanlis nonce: Master farkli bir nonce ile dogrularsa tag tutmaz.
    std::printf("\n[Dogru tag ama yanlis nonce] -> ");
    bool wrongNonce = master.checkSessionKeyIsCorrect(tag, 2, 999);
    std::printf("    sonuc: %s\n", wrongNonce ? "KABUL" : "RED");

    // --- Tamamlanma callback'i: tum ECU'lar onaylaninca BIR kez tetiklenir ---
    std::printf("\n=== Tamamlanma callback'i ===\n");
    CANKeyDistrb fleet;
    fleet.setNonce(0x0A, 1);
    fleet.calculateSessionKeyKBKDF();
    fleet.setOnAllConfirmed(onAllEcusConfirmed);   // isimli fonksiyonu callback olarak ver
    for (std::uint32_t id = 1; id <= 10; ++id) {
        fleet.markDataSent(id);
        const auto t = fleet.calculateSessionKeyTag(id, 200 + id);
        fleet.markResponseReceived(id, t, 200 + id);
    }

    return 0;
}
