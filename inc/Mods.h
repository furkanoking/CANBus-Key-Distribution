#ifndef _MODS_H_
#define _MODS_H_

#include <cstdint>

enum class KDF {
    KBKDF,
    HKDF,
};


struct Mods {
    KDF kdf;
    int WCRT; // This is the waiting-for-response time in milliseconds
};

enum class ECU_State {
    INITIAL_STATE,
    WAITING_THE_RESPONSE,
    RECEIVED_THE_RESPONSE,
    RESENT_THE_INPUTS
};

struct ECUMode {
    int retry_counter = 0;
    ECU_State ecu_state = ECU_State::INITIAL_STATE;
    // Bu ECU'dan kabul edilen en yuksek nonce counter (replay korumasi).
    // 0 = henuz kabul edilmedi; gecerli counter'lar 1'den baslar.
    std::uint64_t last_nonce_counter = 0;
};

constexpr int MAX_TOTAL_RETRY_COUNTER = 3;


#endif
