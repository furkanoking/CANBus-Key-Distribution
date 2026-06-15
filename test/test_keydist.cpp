// CANKeyDistrb icin basit, bagimsiz test (cerceve gerektirmez).
// Her test bir ozelligi DOGRULAR ve PASS/FAIL basar; herhangi biri kalirsa
// program 1 ile cikar, boylece `ctest` de hatayi gorur.

#include "CANKeyDistrb.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

namespace {

int g_failures = 0;

std::string hex(const std::array<uint8_t, 16>& key) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    for (const auto b : key) {
        s.push_back(digits[(b >> 4) & 0x0F]);
        s.push_back(digits[b & 0x0F]);
    }
    return s;
}

void check(const char* name, bool condition) {
    std::printf("    [%s] %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) {
        ++g_failures;
    }
}

} // namespace

int main() {
    std::printf("=== CANKeyDistrb testleri ===\n\n");

    // [1] MUTABAKAT — iki AYRI ECU nesnesi, ayni nonce -> AYNI K_S.
    // Bu, "dagitik ECU'lar ayni anahtari turetir" garantisinin testidir
    // (ve eski projedeki rastgele-salt bug'inin regresyon testi).
    std::printf("[1] Mutabakat: iki farkli ECU nesnesi ayni nonce ile ayni K_S turetmeli\n");
    {
        CANKeyDistrb ecuA;            // ECU-A : kendi K_M kopyasi
        CANKeyDistrb ecuB;            // ECU-B : ayni K_M, ama ayri nesne
        ecuA.setNonce(10, 5);
        ecuB.setNonce(10, 5);
        const auto keyA = ecuA.calculateSessionKeyKBKDF();
        const auto keyB = ecuB.calculateSessionKeyKBKDF();
        std::printf("    ECU-A K_S = %s\n", hex(keyA).c_str());
        std::printf("    ECU-B K_S = %s\n", hex(keyB).c_str());
        check("iki ECU ayni K_S'yi turetti", keyA == keyB);
    }

    // [2] TAZELIK — ayni ECU, farkli Counter -> FARKLI K_S (key rotation).
    std::printf("\n[2] Tazelik: counter degisince K_S degismeli\n");
    {
        CANKeyDistrb ecu;
        ecu.setNonce(10, 1);
        const auto k1 = ecu.calculateSessionKeyKBKDF();
        ecu.setNonce(10, 2);
        const auto k2 = ecu.calculateSessionKeyKBKDF();
        check("ctr=1 ve ctr=2 farkli K_S verdi", k1 != k2);
    }

    // [3] AYRISTIRMA — farkli ECU_ID -> farkli K_S (ECU_ID nonce'a giriyor).
    std::printf("\n[3] Farkli ECU_ID farkli K_S vermeli\n");
    {
        CANKeyDistrb e1;
        CANKeyDistrb e2;
        e1.setNonce(10, 1);
        e2.setNonce(11, 1);
        check("ECU 10 ve ECU 11 farkli K_S",
              e1.calculateSessionKeyKBKDF() != e2.calculateSessionKeyKBKDF());
    }

    // [4] DETERMINIZM — ayni nonce iki kez -> ayni sonuc.
    std::printf("\n[4] Determinizm: ayni nonce hep ayni K_S\n");
    {
        CANKeyDistrb ecu;
        ecu.setNonce(7, 99);
        const auto a = ecu.calculateSessionKeyKBKDF();
        ecu.setNonce(7, 99);
        const auto b = ecu.calculateSessionKeyKBKDF();
        check("ayni nonce -> ayni K_S", a == b);
    }

    // [5] ALGORITMA FARKI — ayni nonce, KBKDF vs HKDF -> farkli K_S.
    std::printf("\n[5] KBKDF ve HKDF ayni nonce'la farkli sonuc vermeli\n");
    {
        CANKeyDistrb ecu;
        ecu.setNonce(10, 1);
        const auto kbkdf = ecu.calculateSessionKeyKBKDF();
        const auto hkdf = ecu.calculateSessionKeyHKDF();
        check("KBKDF != HKDF", kbkdf != hkdf);
    }

    // --- Key confirmation (checkSessionKeyIsCorrect) testleri ---

    std::printf("\n[6] Key confirmation: dogru tag KABUL edilmeli\n");
    {
        CANKeyDistrb master;
        CANKeyDistrb ecu;
        master.setNonce(0x0A, 1);
        ecu.setNonce(0x0A, 1);            // ayni KDF nonce -> ayni K_S
        master.calculateSessionKeyKBKDF();
        ecu.calculateSessionKeyKBKDF();
        const auto tag = ecu.calculateSessionKeyTag(2, 555);   // ACK nonce = 555
        check("dogru tag + dogru nonce kabul edildi",
              master.checkSessionKeyIsCorrect(tag, 2, 555));
    }

    std::printf("\n[7] Key confirmation: bozulmus tag REDDEDILMELI\n");
    {
        CANKeyDistrb master;
        CANKeyDistrb ecu;
        master.setNonce(0x0A, 1);
        ecu.setNonce(0x0A, 1);
        master.calculateSessionKeyKBKDF();
        ecu.calculateSessionKeyKBKDF();
        auto tag = ecu.calculateSessionKeyTag(2, 555);
        tag[0] ^= 0xFF;                  // tek byte bozulmasi
        check("bozulmus tag reddedildi", !master.checkSessionKeyIsCorrect(tag, 2, 555));
    }

    std::printf("\n[8] Key confirmation: yanlis nonce REDDEDILMELI\n");
    {
        CANKeyDistrb master;
        CANKeyDistrb ecu;
        master.setNonce(0x0A, 1);
        ecu.setNonce(0x0A, 1);
        master.calculateSessionKeyKBKDF();
        ecu.calculateSessionKeyKBKDF();
        const auto tag = ecu.calculateSessionKeyTag(2, 555);
        check("yanlis nonce ile dogrulama reddedildi",
              !master.checkSessionKeyIsCorrect(tag, 2, 999));
    }

    std::printf("\n[9] Key confirmation: YANLIS K_S turetmis ECU REDDEDILMELI\n");
    {
        CANKeyDistrb master;
        CANKeyDistrb ecu;
        master.setNonce(0x0A, 1);        // master K_S (KDF ctr=1)
        ecu.setNonce(0x0A, 2);           // ecu FARKLI K_S (KDF ctr=2)
        master.calculateSessionKeyKBKDF();
        ecu.calculateSessionKeyKBKDF();
        const auto tag = ecu.calculateSessionKeyTag(2, 555);   // ayni ACK nonce
        check("yanlis K_S turetmis ECU reddedildi",
              !master.checkSessionKeyIsCorrect(tag, 2, 555));
    }

    std::printf("\n[10] markResponseReceived: dogru tag -> RECEIVED, bozuk tag -> WAITING kalir\n");
    {
        CANKeyDistrb master;
        master.setNonce(0x0A, 1);
        master.calculateSessionKeyKBKDF();

        master.markDataSent(3);          // ECU-3 WAITING
        master.markDataSent(7);          // ECU-7 WAITING

        const auto goodTag = master.calculateSessionKeyTag(3, 333);
        auto badTag = master.calculateSessionKeyTag(7, 777);
        badTag[0] ^= 0xFF;

        master.markResponseReceived(3, goodTag, 333);   // gecerli
        master.markResponseReceived(7, badTag, 777);    // bozuk

        check("dogru tag -> RECEIVED_THE_RESPONSE",
              master.getECUState(3) == ECU_State::RECEIVED_THE_RESPONSE);
        check("bozuk tag -> WAITING_THE_RESPONSE'ta kalir",
              master.getECUState(7) == ECU_State::WAITING_THE_RESPONSE);
    }

    std::printf("\n[11] checkECUs retry limiti: 3 denemeden sonra ABORT, retry sabit kalir\n");
    {
        CANKeyDistrb master;
        master.markDataSent(5);          // ECU-5 WAITING, hic cevap vermeyecek

        for (int i = 0; i < 6; ++i) {    // limitin uzerinde tur
            master.checkECUs();
        }
        check("retry_counter MAX'ta durur (3)", master.getRetryCounter(5) == MAX_TOTAL_RETRY_COUNTER);
        check("ECU-5 RESENT_THE_INPUTS'ta (basarisiz)",
              master.getECUState(5) == ECU_State::RESENT_THE_INPUTS);
    }

    std::printf("\n[12] checkECUs INITIAL durumdaki ECU'ya dokunmaz\n");
    {
        CANKeyDistrb master;          // 10 default ECU, hepsi INITIAL
        master.checkECUs();
        check("INITIAL ECU'nun retry'si artmaz", master.getRetryCounter(4) == 0);
        check("INITIAL ECU INITIAL kalir", master.getECUState(4) == ECU_State::INITIAL_STATE);
    }

    std::printf("\n[13] Replay korumasi: ayni/eski counter RED, yuksek counter KABUL\n");
    {
        CANKeyDistrb master;
        master.setNonce(0x0A, 1);
        master.calculateSessionKeyKBKDF();

        master.markDataSent(3);                              // ECU-3 WAITING
        const auto tag333 = master.calculateSessionKeyTag(3, 333);
        master.markResponseReceived(3, tag333, 333);         // ilk ACK -> kabul, last=333
        check("ilk ACK (333) kabul edildi",
              master.getECUState(3) == ECU_State::RECEIVED_THE_RESPONSE);

        // Yeni tur: ECU-3 tekrar cevap bekliyor (last hala 333).
        master.markDataSent(3);                              // -> WAITING
        master.markResponseReceived(3, tag333, 333);         // ESKI ACK replay -> 333<=333 RED
        check("replay edilen ACK (333) reddedildi -> WAITING kalir",
              master.getECUState(3) == ECU_State::WAITING_THE_RESPONSE);

        // Daha yuksek counter'li taze ACK -> kabul.
        const auto tag444 = master.calculateSessionKeyTag(3, 444);
        master.markResponseReceived(3, tag444, 444);         // 444>333 -> kabul
        check("daha yuksek counter (444) kabul edildi",
              master.getECUState(3) == ECU_State::RECEIVED_THE_RESPONSE);
    }

    std::printf("\n[14] Callback: TUM ECU'lar onaylaninca BIR kez tetiklenir\n");
    {
        CANKeyDistrb master;
        master.setNonce(0x0A, 1);
        master.calculateSessionKeyKBKDF();

        int callCount = 0;
        master.setOnAllConfirmed([&callCount]() { ++callCount; });

        // Varsayilan 10 ECU; once 9'unu onayla.
        for (std::uint32_t id = 1; id <= 9; ++id) {
            master.markDataSent(id);
            const auto tag = master.calculateSessionKeyTag(id, 100 + id);
            master.markResponseReceived(id, tag, 100 + id);
        }
        check("9/10 onayliyken callback tetiklenmedi", callCount == 0);

        // 10. (son) ECU'yu da onayla -> callback tetiklenmeli.
        master.markDataSent(10);
        const auto tag10 = master.calculateSessionKeyTag(10, 110);
        master.markResponseReceived(10, tag10, 110);
        check("10/10 olunca callback tetiklendi", callCount == 1);

        // Hepsi RECEIVED; baska bir markResponseReceived callback'i TEKRAR tetiklememeli.
        master.markResponseReceived(10, tag10, 111);   // zaten RECEIVED -> yok sayilir
        check("callback yalnizca BIR kez tetiklendi", callCount == 1);
    }

    std::printf("\n=== %s (%d hata) ===\n",
                g_failures == 0 ? "TUM TESTLER GECTI" : "BAZI TESTLER BASARISIZ",
                g_failures);
    return g_failures == 0 ? 0 : 1;
}
