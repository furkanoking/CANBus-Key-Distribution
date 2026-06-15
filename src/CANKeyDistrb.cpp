#include "CANKeyDistrb.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/sha.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {

// OpenSSL'in C nesnelerini elle free etmeyi unutmamak icin RAII sarmalayici.
// Nesne kapsam disina cikinca EVP_KDF_CTX_free otomatik cagrilir.
struct KdfCtxDeleter {
    void operator()(EVP_KDF_CTX* ctx) const { EVP_KDF_CTX_free(ctx); }
};
using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter>;

// Bir sayiyi (ECU_ID 32-bit, Counter 64-bit) SABIT-GENISLIKLI big-endian ham
// byte'lara cevirip yan yana koyar. Metin ("10") DEGIL, ham deger (0x0A) yazilir;
// boylece alan sinirlari belirsizlesmez ve tum ECU'lar ayni byte'lari uretir.
std::string buildNonceBytes(std::uint32_t ecuId, std::uint64_t counter) {
    std::string bytes;
    bytes.reserve(12);
    for (int shift = 24; shift >= 0; shift -= 8) {           // ECU_ID: 4 byte
        bytes.push_back(static_cast<char>((ecuId >> shift) & 0xFF));
    }
    for (int shift = 56; shift >= 0; shift -= 8) {           // Counter: 8 byte
        bytes.push_back(static_cast<char>((counter >> shift) & 0xFF));
    }
    return bytes;   // toplam 12 ham byte
}

// HMAC-SHA256(key, data) -> 32 byte. Tag uretiminin temeli.
std::array<std::uint8_t, 32> hmacSha256(const std::uint8_t* key, std::size_t keyLen,
                                        const std::uint8_t* data, std::size_t dataLen) {
    std::array<std::uint8_t, 32> out{};
    unsigned int len = 0;
    if (HMAC(EVP_sha256(), key, static_cast<int>(keyLen),
             data, dataLen, out.data(), &len) == nullptr || len != out.size()) {
        throw std::runtime_error("HMAC-SHA256 hesaplama basarisiz");
    }
    return out;
}

// ECU_State'i loglarda okunur metne cevirir.
const char* stateName(ECU_State state) {
    switch (state) {
    case ECU_State::INITIAL_STATE:         return "INITIAL_STATE";
    case ECU_State::WAITING_THE_RESPONSE:  return "WAITING_THE_RESPONSE";
    case ECU_State::RECEIVED_THE_RESPONSE: return "RECEIVED_THE_RESPONSE";
    case ECU_State::RESENT_THE_INPUTS:     return "RESENT_THE_INPUTS";
    }
    return "?";
}

// Verilen algoritma icin (KBKDF / HKDF) bir baglam uretir.
KdfCtxPtr makeKdfContext(const char* algorithm) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, algorithm, nullptr);
    if (kdf == nullptr) {
        throw std::runtime_error(std::string("EVP_KDF_fetch basarisiz: ") + algorithm);
    }
    KdfCtxPtr ctx(EVP_KDF_CTX_new(kdf));
    EVP_KDF_free(kdf);                 // ctx artik kendi kopyasini tutuyor
    if (!ctx) {
        throw std::runtime_error("EVP_KDF_CTX_new basarisiz");
    }
    return ctx;
}

} // namespace

CANKeyDistrb::CANKeyDistrb()
    // Faz 0 (uretim) provizyonlamasinin yerine gecen sabit K_M.
    : masterKey{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
                0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F},
      sessionKey{},                       // henuz turetilmedi, sifir dolu
      currentMode{KDF::KBKDF, 700},       // varsayilan: KBKDF, WCRT=700ms
      Label("CANsec-SKG"),                // tezdeki Label
      Context(),                          // setNonce ile dolacak (asagida)
      // HKDF salt'i SABIT: rastgele olsaydi her nesne farkli anahtar uretir,
      // iki ECU ayni K_S'yi turetemezdi (eski projedeki bug buydu).
      salt{0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
           0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90},
      info() {
    // Baslangic icin gecerli bir nonce kur (ECU_ID=0x0A, Counter=0).
    setNonce(0x0000000A, 0);

    // Varsayilan 10 ECU (constructor tek thread; log uretmemek icin dogrudan
    // ekliyoruz, addECU uzerinden degil).
    for (std::uint32_t id = 1; id <= 10; ++id) {
        ecuTable[id] = ECUMode{};
    }
}

CANKeyDistrb::~CANKeyDistrb() {
    // std::thread (jthread degil): yikilirken hala joinable ise std::terminate()
    // cagrilir. Bu yuzden timer thread'ini elle bekleyip kapatiyoruz.
    if (m_timerThread.joinable()) {
        m_timerThread.join();
    }
}

std::array<uint8_t, 16> CANKeyDistrb::getMasterKey() const {
    return masterKey;
}

void CANKeyDistrb::setTheMode(Mods mode) {
    currentMode = mode;
}

void CANKeyDistrb::setNonce(std::uint32_t ecuId, std::uint64_t counter) {
    const std::string nonceBytes = buildNonceBytes(ecuId, counter);
    Context = nonceBytes;                       // KBKDF: Context = nonce (ham byte)
    info = "CANsec-SKG-hkdf" + nonceBytes;      // HKDF: domain etiketi + nonce (her turda taze)
}

std::array<uint8_t, 16> CANKeyDistrb::calculateSessionKeyKBKDF() {
    auto ctx = makeKdfContext("KBKDF");

    int useL = 1;
    int useSeparator = 1;

    // NIST SP 800-108 Counter modu, CMAC-AES128 (K_M 16 byte oldugu icin AES-128).
    // OpenSSL'de SALT = SP800-108 Label, INFO = Context (kafa karistiran isimlendirme).
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, const_cast<char*>("COUNTER"), 0),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, const_cast<char*>("CMAC"), 0),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, const_cast<char*>("AES-128-CBC"), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, masterKey.data(), masterKey.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          const_cast<char*>(Label.data()), Label.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          const_cast<char*>(Context.data()), Context.size()),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_L, &useL),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, &useSeparator),
        OSSL_PARAM_construct_end(),
    };

    if (EVP_KDF_derive(ctx.get(), sessionKey.data(), sessionKey.size(), params) <= 0) {
        throw std::runtime_error("KBKDF turetme basarisiz");
    }
    return sessionKey;
}

std::array<uint8_t, 16> CANKeyDistrb::calculateSessionKeyHKDF() {
    auto ctx = makeKdfContext("HKDF");

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, masterKey.data(), masterKey.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          const_cast<char*>(info.data()), info.size()),
        OSSL_PARAM_construct_end(),
    };

    if (EVP_KDF_derive(ctx.get(), sessionKey.data(), sessionKey.size(), params) <= 0) {
        throw std::runtime_error("HKDF turetme basarisiz");
    }
    return sessionKey;
}

std::array<uint8_t, 16> CANKeyDistrb::getSessionKey() const {
    return sessionKey;
}

std::array<uint8_t, 16> CANKeyDistrb::calculateHASH() const {
    // SHA-256, 32 byte uretir; tezdeki K_S_hash icin ilk 16 byte'a kisaltiyoruz.
    unsigned char full[SHA256_DIGEST_LENGTH];
    SHA256(sessionKey.data(), sessionKey.size(), full);

    std::array<uint8_t, 16> out{};
    std::copy(full, full + out.size(), out.begin());
    return out;
}

// ---------------------------------------------------------------------------
// ECU tablosu yonetimi
// ---------------------------------------------------------------------------

void CANKeyDistrb::addECU(std::uint32_t ecuId) {
    std::scoped_lock<std::mutex> lock(m_mutexECU);
    // Default ECUMode: retry_counter=0, ecu_state=INITIAL_STATE.
    ecuTable[ecuId] = ECUMode{};
    std::printf("[LOG] addECU: ECU-%u added (INITIAL_STATE)\n", ecuId);
}

void CANKeyDistrb::removeECU(std::uint32_t ecuId) {
    std::scoped_lock<std::mutex> lock(m_mutexECU);
    ecuTable.erase(ecuId);
    std::printf("[LOG] removeECU: ECU-%u removed\n", ecuId);
}

bool CANKeyDistrb::hasECU(std::uint32_t ecuId) const {
    std::scoped_lock<std::mutex> lock(m_mutexECU);
    return ecuTable.find(ecuId) != ecuTable.end();
}

std::size_t CANKeyDistrb::ecuCount() const {
    std::scoped_lock<std::mutex> lock(m_mutexECU);
    return ecuTable.size();
}

void CANKeyDistrb::setECUState(std::uint32_t ecuId, ECU_State state) {
    std::scoped_lock<std::mutex> lock(m_mutexECU);
    auto it = ecuTable.find(ecuId);
    if (it == ecuTable.end()) {
        throw std::out_of_range("ECU not in table: " + std::to_string(ecuId));
    }
    it->second.ecu_state = state;
    std::printf("[LOG] setECUState: ECU-%u -> %s\n", ecuId, stateName(state));
}

ECU_State CANKeyDistrb::getECUState(std::uint32_t ecuId) const {
    std::scoped_lock<std::mutex> lock(m_mutexECU);
    return ecuTable.at(ecuId).ecu_state;   // .at() yoksa exception atar
}

int CANKeyDistrb::getRetryCounter(std::uint32_t ecuId) const {
    std::scoped_lock<std::mutex> lock(m_mutexECU);
    return ecuTable.at(ecuId).retry_counter;
}

void CANKeyDistrb::incrementRetry(std::uint32_t ecuId) {
    std::scoped_lock<std::mutex> lock(m_mutexECU);
    const int n = ++ecuTable.at(ecuId).retry_counter;
    std::printf("[LOG] incrementRetry: ECU-%u retry_counter = %d\n", ecuId, n);
}

void CANKeyDistrb::markDataSent(std::uint32_t ecuId) {
    std::scoped_lock<std::mutex> lock(m_mutexECU);
    auto it = ecuTable.find(ecuId);
    if (it == ecuTable.end()) {
        std::printf("[LOG] markDataSent: ECU-%u not found, skipped\n", ecuId);
        return;
    }
    // Master bu ECU'ya parametreleri yolladi: artik cevabini bekliyoruz.
    it->second.ecu_state = ECU_State::WAITING_THE_RESPONSE;
    std::printf("[LOG] markDataSent: ECU-%u -> WAITING_THE_RESPONSE\n", ecuId);
}

void CANKeyDistrb::markResponseReceived(std::uint32_t ecuId, std::array<uint8_t, 8> tag,
                                        std::uint64_t nonceCounter) {
    bool justCommitted = false;
    {
        std::scoped_lock<std::mutex> lock(m_mutexECU);
        auto it = ecuTable.find(ecuId);
        if (it == ecuTable.end()) {
            std::printf("[LOG] markResponseReceived: ECU-%u not found, response ignored\n", ecuId);
            return;
        }
        // 1) Cevabi yalnizca cevap BEKLEDIGIMIZ ECU'lardan kabul et (WAITING ya da
        //    bir resend sonrasi RESENT). INITIAL/RECEIVED ise dikkate alinmaz.
        const ECU_State st = it->second.ecu_state;
        if (st != ECU_State::WAITING_THE_RESPONSE && st != ECU_State::RESENT_THE_INPUTS) {
            std::printf("[LOG] markResponseReceived: ECU-%u not awaiting a response "
                        "(current: %s), ignored\n", ecuId, stateName(st));
            return;
        }
        // 2) Key confirmation: cevap ancak K_S DOGRUYSA kabul edilir.
        //    (checkSessionKeyIsCorrect ecuTable'a dokunmaz -> kilit altinda guvenli.)
        if (!checkSessionKeyIsCorrect(tag, ecuId, nonceCounter)) {
            std::printf("[LOG] markResponseReceived: ECU-%u key verification FAILED, rejected\n", ecuId);
            return;   // durum degismez -> bir sonraki timeout'ta yine denenir
        }
        // 3) Replay/freshness: counter bu ECU'dan kabul edilen en yuksek counter'dan
        //    BUYUK olmali. Esit/kucukse replay ya da eski mesaj -> reddet.
        if (nonceCounter <= it->second.last_nonce_counter) {
            std::printf("[LOG] markResponseReceived: ECU-%u REPLAY/stale nonce "
                        "(got %llu, last accepted %llu), rejected\n",
                        ecuId, (unsigned long long)nonceCounter,
                        (unsigned long long)it->second.last_nonce_counter);
            return;
        }
        it->second.last_nonce_counter = nonceCounter;
        it->second.ecu_state = ECU_State::RECEIVED_THE_RESPONSE;
        std::printf("[LOG] markResponseReceived: ECU-%u verified -> RECEIVED_THE_RESPONSE\n", ecuId);

        // Karari kilit ALTINDA ver; callback'i kilit DISINDA cagiracagiz.
        if (!m_committed && allConfirmed()) {
            m_committed = true;
            justCommitted = true;
        }
    }   // <-- kilit burada birakilir

    // Callback kullanicinin kodu: deadlock olmamasi icin kilit DISINDA cagrilir.
    if (justCommitted && m_onAllConfirmed) {
        std::printf("[LOG] markResponseReceived: ALL ECUs confirmed -> invoking callback\n");
        m_onAllConfirmed();
    }
}

void CANKeyDistrb::setOnAllConfirmed(std::function<void()> callback) {
    m_onAllConfirmed = std::move(callback);
}

bool CANKeyDistrb::allConfirmed() const {
    // NOT: cagiran m_mutexECU'yu tutuyor olmali (burada kilitlemiyoruz).
    for (const auto& [id, mode] : ecuTable) {
        (void)id;
        if (mode.ecu_state != ECU_State::RECEIVED_THE_RESPONSE) {
            return false;
        }
    }
    return true;
}

const std::map<std::uint32_t, ECUMode>& CANKeyDistrb::getECUTable() const {
    return ecuTable;
}

void CANKeyDistrb::SessionKeysInputsAreSent() {
    // Onceki tur hala calisiyorsa bekle (joinable bir thread'in uzerine
    // atama yapmak yasak).
    if (m_timerThread.joinable()) {
        m_timerThread.join();
    }

    std::printf("[LOG] SessionKeysInputsAreSent: broadcast done, starting timer (WCRT=%d ms)\n",
                currentMode.WCRT);

    m_timerThread = std::thread([this]() {
        // WCRT MILISANIYE cinsinden (seconds degil! seconds(700) = 11.6 dakika).
        std::this_thread::sleep_for(std::chrono::milliseconds(currentMode.WCRT));
        checkECUs();
    });
}

void CANKeyDistrb::checkECUs() {
    // Kilidi yalnizca tabloyu OKURKEN tut, sonra birak. resentTheMessage'i
    // kilit DISINDA cagiriyoruz: cunku o (ileride) incrementRetry/markDataSent
    // gibi yine kilitleyen metotlari cagirabilir -> ayni thread ayni mutex'i
    // tekrar kilitlerse DEADLOCK olur (std::mutex recursive degil).
    std::vector<std::uint32_t> toResend;
    {
        std::scoped_lock<std::mutex> lock(m_mutexECU);
        for (auto& ecu : ecuTable) {
            const ECU_State st = ecu.second.ecu_state;
            // Sadece cevap BEKLEDIGIMIZ ECU'lar: WAITING (ilk gonderim) veya
            // RESENT (onceki retry). INITIAL (hic gonderilmedi) ve RECEIVED
            // (zaten cevapladi) atlanir.
            if (st != ECU_State::WAITING_THE_RESPONSE && st != ECU_State::RESENT_THE_INPUTS) {
                continue;
            }
            // Retry limiti: 3 denemeden sonra bu ECU'dan vazgec (abort).
            if (ecu.second.retry_counter >= MAX_TOTAL_RETRY_COUNTER) {
                std::printf("[LOG] checkECUs: ECU-%u max retries (%d) reached, ABORTED\n",
                            ecu.first, MAX_TOTAL_RETRY_COUNTER);
                continue;
            }
            ecu.second.retry_counter++;
            toResend.push_back(ecu.first);
        }
    }   // <-- kilit burada birakilir

    std::printf("[LOG] checkECUs: timeout fired, %zu ECU(s) will be resent\n",
                toResend.size());
    for (const auto id : toResend) {
        resentTheMessage(id);
    }
}

void CANKeyDistrb::resentTheMessage(std::uint32_t ecuId) {
    std::scoped_lock<std::mutex> lock(m_mutexECU);
    auto it = ecuTable.find(ecuId);
    if (it == ecuTable.end()) {
        return;
    }
    // Retry sayaci checkECUs'ta artirildi; burada sadece "tekrar gonderildi"
    // durumunu isaretliyoruz. (Gercek sistemde parametreler tekrar gonderilir.)
    it->second.ecu_state = ECU_State::RESENT_THE_INPUTS;
    std::printf("[LOG] resentTheMessage: ECU-%u resending (attempt %d/%d)\n",
                ecuId, it->second.retry_counter, MAX_TOTAL_RETRY_COUNTER);
}

std::array<uint8_t, 8> CANKeyDistrb::computeAckTag(std::uint32_t ecuId,
                                                   std::uint64_t nonceCounter) const {
    // "Yan yana" buffer: ECU_ID(4B BE) || K_S_hash(16B) || nonce(ECU_ID||Counter, 12B).
    // nonce ACK ile paylasildigi icin Master ayni nonce'la dogrulayabilir.
    std::vector<std::uint8_t> buffer;

    for (int shift = 24; shift >= 0; shift -= 8) {                    // ECU_ID, 4 byte BE
        buffer.push_back(static_cast<std::uint8_t>((ecuId >> shift) & 0xFF));
    }

    const auto ksHash = calculateHASH();                             // K_S_hash, 16 byte
    buffer.insert(buffer.end(), ksHash.begin(), ksHash.end());

    const std::string nonceBytes = buildNonceBytes(ecuId, nonceCounter);   // nonce, 12 byte
    for (const char c : nonceBytes) {
        buffer.push_back(static_cast<std::uint8_t>(c));
    }

    // tag = HMAC(K_S, buffer), ilk 8 byte (64 bit).
    const auto full = hmacSha256(sessionKey.data(), sessionKey.size(),
                                 buffer.data(), buffer.size());
    std::array<uint8_t, 8> tag{};
    std::copy(full.begin(), full.begin() + tag.size(), tag.begin());
    return tag;
}

std::array<uint8_t, 8> CANKeyDistrb::calculateSessionKeyTag(std::uint32_t ecuId,
                                                            std::uint64_t nonceCounter) const {
    return computeAckTag(ecuId, nonceCounter);   // ECU bu tag'i ACK icine koyar
}

bool CANKeyDistrb::checkSessionKeyIsCorrect(std::array<uint8_t, 8> receivedTag,
                                            std::uint32_t ecuId,
                                            std::uint64_t nonceCounter) const {
    // Master ACK'ten gelen nonce ile beklenen tag'i yeniden hesaplar.
    const auto expected = computeAckTag(ecuId, nonceCounter);

    // Constant-time karsilastirma: '==' ilk farkli byte'ta durur ve zamanlama
    // sizintisi yaratir. CRYPTO_memcmp esit/farkli her durumda ayni surede calisir.
    const bool match =
        CRYPTO_memcmp(expected.data(), receivedTag.data(), expected.size()) == 0;

    std::printf("[LOG] checkSessionKeyIsCorrect: ECU-%u tag %s\n",
                ecuId, match ? "VALID (K_S correct)" : "INVALID (wrong/corrupted K_S)");
    return match;
}