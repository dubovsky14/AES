#pragma once

#include "../aes/Byte.h"

#include <vector>

namespace AES   {
    class KeyScheduler128  {
        public:
            KeyScheduler128(const std::vector<Byte> &key);

            KeyScheduler128(uint64_t first_half, uint64_t second_half);

            const Byte*     GetSubKey(unsigned int interation_index)    const;

            static Byte     GetRCKey(unsigned int index);

        private:
            std::vector<Byte>               m_primary_key;
            Byte                            m_subkeys[11][16];

            void InitializeSubkeys();

            static std::vector<Byte>   AddWords(const Byte *target1, const Byte *target2, unsigned int n_bytes);

            static std::vector<Byte>   RotateWordLeft(const Byte *word, unsigned int word_size = 4, unsigned int shift_size = 1);

            static std::vector<Byte>   GFunction(const Byte *word, const Byte &rc_key);
    };
}