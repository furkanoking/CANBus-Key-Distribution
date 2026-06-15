#ifndef _CANKEYDISTRB_H_
#define _CANKEYDISTRB_H_

#include "Mods.h"

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <thread>
#include <mutex>


class CANKeyDistrb{
public:
    CANKeyDistrb();
    ~CANKeyDistrb();
    
    // just for the Master ECU
    std::array<uint8_t, 16> getMasterKey() const;
    void setTheMode(Mods mode);

    // Nonce'u (ECU_ID + Counter) ham binary olarak Context'e/info'ya yazar.
    // Sayilar metne degil, sabit-genislikli big-endian byte'lara cevrilir.
    void setNonce(std::uint32_t ecuId, std::uint64_t counter);

    std::array<uint8_t, 16> calculateSessionKeyKBKDF();
    std::array<uint8_t, 16> calculateSessionKeyHKDF();
    std::array<uint8_t, 16> getSessionKey() const;
    std::array<uint8_t, 16> calculateHASH() const;

    // --- ECU tablosu: her ECU_ID -> ECUMode (durum + retry sayaci) ---
    // Tezdeki pre-shared registry + tracking bitmap'in karsiligi.
    void addECU(std::uint32_t ecuId);                          // varsayilan ECUMode ile ekler
    void removeECU(std::uint32_t ecuId);                       // tablodan cikarir
    bool hasECU(std::uint32_t ecuId) const;
    std::size_t ecuCount() const;

    void setECUState(std::uint32_t ecuId, ECU_State state);    // bir ECU'nun durumunu degistir
    ECU_State getECUState(std::uint32_t ecuId) const;
    int  getRetryCounter(std::uint32_t ecuId) const;
    void incrementRetry(std::uint32_t ecuId);                  // retry_counter++

    // Master bu ECU'ya parametreleri yollayinca cagrilir:
    // durumu INITIAL_STATE -> WAITING_THE_RESPONSE'a ceker.
    void markDataSent(std::uint32_t ecuId);

    // ECU cevap (ACK) yollayinca cagrilir: tag + nonce paylasir. Once ECU
    // cevap BEKLIYOR mu (WAITING/RESENT) diye bakar, sonra tag'i dogrular
    // (K_S dogru mu) ve ancak ikisi de gecerse RECEIVED_THE_RESPONSE'a ceker.
    void markResponseReceived(std::uint32_t ecuId, std::array<uint8_t, 8> tag,
                              std::uint64_t nonceCounter);

    const std::map<std::uint32_t, ECUMode>& getECUTable() const;

    // After broadcasting, the timer is started
    void SessionKeysInputsAreSent();

    // Bir timeout turu: cevap vermeyen ECU'lara (WAITING/RESENT) tekrar gonderir,
    // retry limitini uygular. Timer thread'i bunu cagirir; ayrica deterministik
    // test icin dogrudan da cagrilabilir (mantik <-> surucu ayrimi).
    void checkECUs();

    // ECU tarafi: kendi K_S'sinin dogrulugunu kanitlayan 64-bit tag'i uretir
    // (ACK icine konur). tag = HMAC(K_S, ECU_ID || K_S_hash || nonce)'in ilk 8 byte'i.
    // nonce = ECU_ID || nonceCounter (ACK ile paylasilir). K_S asla kabloda gitmez.
    std::array<uint8_t, 8> calculateSessionKeyTag(std::uint32_t ecuId,
                                                  std::uint64_t nonceCounter) const;

    // Master tarafi: ACK'ten gelen nonce'u kullanarak tag'i kendi K_S'siyle
    // yeniden hesaplayip karsilastirir. Esitse ECU dogru K_S'yi turetmis demektir.
    bool checkSessionKeyIsCorrect(std::array<uint8_t, 8> receivedTag, std::uint32_t ecuId,
                                  std::uint64_t nonceCounter) const;

    // Tum ECU'lar K_S'yi onaylayinca (RECEIVED) BIR kez cagrilacak callback.
    // Kullanan kisi ne yapacagini buraya koyar (ornegin AES-GCM'i baslatma).
    // Dagitim baslamadan once set edilmeli.
    void setOnAllConfirmed(std::function<void()> callback);

private:
    std::array<uint8_t, 16> masterKey; // this is the K_M key
    std::array<uint8_t, 16> sessionKey; // this is the K_S key
    Mods currentMode;

    //for the KBKDF
    std::string Label;
    std::string Context;
    
    // for the HKDF
    std::array<uint8_t, 16> salt;
    std::string info;

    // Master'in takip ettigi ECU'lar ve durumlari (sirali, ECU_ID'ye gore).
    std::map<std::uint32_t, ECUMode> ecuTable;

    std::function<void()> m_onAllConfirmed;   // tamamlanma callback'i (bos olabilir)
    bool m_committed = false;                 // callback yalnizca bir kez tetiklensin

    void resentTheMessage(std::uint32_t ecuId);

    // registry'deki TUM ECU'lar RECEIVED mi? (cagiran m_mutexECU'yu tutuyor olmali)
    bool allConfirmed() const;

    // Tag'i hesaplayan ortak ic mantik (hem uretim hem dogrulama bunu kullanir):
    // HMAC(K_S, ECU_ID(4B) || K_S_hash(16B) || nonce(ECU_ID||nonceCounter)) -> ilk 8 byte.
    std::array<uint8_t, 8> computeAckTag(std::uint32_t ecuId, std::uint64_t nonceCounter) const;

    // macOS libc++'ta std::jthread yok; tasinabilirlik icin std::thread + elle join.
    std::thread m_timerThread;

    // const okuyucularda da kilitleyebilmek icin mutable.
    mutable std::mutex m_mutexECU;

};


#endif /* _CANKEYDISTRB_H_ */