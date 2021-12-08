

namespace AES   {
    class Byte  {
        public:
            Byte(unsigned char x);

            char GetValue() const {return m_value;};

            Byte operator+(const Byte& b);

            Byte operator-(const Byte& b);

            Byte operator*(const Byte& b);

            static constexpr short unsigned int s_modulo_polynomial = 0b100011011;

        private:
            unsigned char m_value;


    };
}