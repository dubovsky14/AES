#pragma once

#include "../aes/Byte.h"

#include <vector>

namespace AES   {

    enum class KeySize{AES128bit, AES192bit, AES256bit};
    class KeyScheduler  {
        public:
            KeyScheduler(const std::vector<Byte> &key);

            KeyScheduler(uint64_t first_half, uint64_t second_half);

            KeyScheduler(uint64_t key_part1, uint64_t key_part2, uint64_t key_part3);

            KeyScheduler(uint64_t key_part1, uint64_t key_part2, uint64_t key_part3, uint64_t key_part4);

            const Byte*     GetSubKey(unsigned int interation_index)    const;

            static Byte     GetRCKey(unsigned int index);

            KeySize         GetKeySize()    const {return m_key_size;};

        private:
            std::vector<Byte>               m_primary_key;
            Byte                            m_subkeys[15][16];
            KeySize                         m_key_size;

            void InitializeSubkeys();

            static std::vector<Byte>   AddWords(const Byte *target1, const Byte *target2, unsigned int n_bytes);

            static std::vector<Byte>   RotateWordLeft(const Byte *word, unsigned int word_size = 4, unsigned int shift_size = 1);

            static std::vector<Byte>   GFunction(const Byte *word, const Byte &rc_key);

            static unsigned int get_n_subkeys(KeySize key_size);

            static unsigned int get_n_key_words(KeySize key_size);

            static unsigned int get_n_key_schedule_iterations(KeySize key_size);
    };
}