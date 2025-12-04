#include <iostream>
#include <vector>
#include <cassert>
#include <fstream>

// long long ints and doubles are used due to the algorithms (typically) really big numbers

// Holds public and private keys
// Using long long ints since the numbers used can be extremely big
namespace Key {
    struct Public {
        long long int n{};
        long long int e{};
    };

    struct Private {
        long long int p{};
        long long int q{};
        long long int d{};
    };
}

namespace Utility {
    namespace Math {
        // Checks if a number 'x' is prime or not.
        // If divided with every natural number 'i' between 1 and x, with those extremes not included (1 < i < x), nets a remainder of 0, it is not a prime number
        // Otherwise, it is a prime number.
        constexpr bool isPrime(long long int x) {
            for (int i { 2 }; i < x; ++i)
                if (x % i == 0)
                    return false;
            return true;
        }

        // Creates and returns a list containing all of the dividers of a number 'x'
        // A number is a divider of x if, when x is divided with that number, the remainder is 0
        constexpr std::vector<long long int> dividerList(long long int x) {
            std::vector<long long int> x_dividerList {};
            
            x_dividerList.reserve(x); // Reserves enough capacity to hold the dividers

            for (long long int i { 1 }; i <= x; ++i)
                if (x % i == 0)
                    x_dividerList.push_back(i);
            
            x_dividerList.shrink_to_fit(); // Shrinks the capacity to save on space

            return x_dividerList;
        }

        // Checks if two numbers 'a' and 'b' are coprimes with eachother
        // Two numbers are coprimes if their MCD, Maximum Common Divider/Massimo Comune Divisore is equal to 1
        // This means both numbers highest divder they have in common is 1
        constexpr bool areCoprimes(long long int a, long long int b) {
            // If one of the numbers is 1, their MCD will be only one number, 1
            // Any number is coprime with 1, so we don't need to test it and can already say its true
            if (a == 1 || b == 1)
                return true;

            const std::vector<long long int> a_dividerList { dividerList(a) };
            const std::vector<long long int> b_dividerList { dividerList(b) };

            for (size_t j { 1 }; j < b_dividerList.size(); ++j)
                for (size_t i { 1 }; i < a_dividerList.size(); ++i)
                    if (a_dividerList[i] == b_dividerList[i])
                        return false;

            return true;
        }

        // Faster version of eulero's function. Makes sure 'n' is the product of 'p' and 'q', then uses those last two numbers to get the number of coprimes n has between 1 and 1 (1<fi(n)<n)
        long long int phi(long long int n, long long int p, long long int q) {
            assert(p * q == n && "Error: p * q != n");
            assert(isPrime(p) && isPrime(q));
            return (p - 1) * (q - 1);
        }

        // Basic integer power, multiplies whole number 'x' with itself for a specific number of times, represented with 'exponent'
        // If the exponent is 0, returns 1
        long long int power(long long int x, long long int exponent) {
            if (exponent == 0)
                return 1;
            
            long long int result { x };

            for (long long int i { 1 }; i < exponent; ++i)
                result *= x;

            return result;
        }
    }

    namespace File {
        // Save public and/or private keys to specific files
        // Checks if the file exists. If it doesn't, it will create it. Save to the file the needed informations

        void saveTo(const std::string& filename, const Key::Public& key) {
            std::fstream fs{};

            fs.open(filename);

            if (!fs.is_open()) {
                std::cout << "Couldn't open existing file. Creating " << filename << "...\n";
                fs.clear();
                fs.open(filename, std::ios::out);
                fs.close();
                fs.open(filename);
                std::cout << "File created.\n";
            }

            fs.clear(); // Cleanup the files contents before writing to it. Potentially unsafe and can be used to delete contents in important files

            fs << "n: " << key.n << '\n' << "e: " << key.e; // Write the key to the file
            fs.close();
        }

        void saveTo(const std::string& filename, const Key::Private& key) {
            std::fstream fs{};

            fs.open(filename);

            if (!fs.is_open()) {
                std::cout << "Couldn't open existing file. Creating " << filename << "...\n";
                fs.clear();
                fs.open(filename, std::ios::out);
                fs.close();
                fs.open(filename);
                std::cout << "File created.\n";
            }

            fs.clear(); // Cleanup the files contents before writing to it. Potentially unsafe and can be used to delete contents in important files

            fs << "p: " << key.p << '\n' << "q: " << key.q << '\n' << "d: " << key.d; // Write the key to the file
            fs.close();
        }
    }
}

namespace Generate {
    // Based on two prime numbers 'p' and 'q', calculates a public key, having two numbers 'n' and 'e'
    Key::Public publicKey(const long long int p, const long long int q) {
        assert(Utility::Math::isPrime(p) && Utility::Math::isPrime(q) && "ERROR: p and/or q are not prime numbers."); // Make sure p and q are prime numbers

        const long long int n { p * q };

        const long long int n_eulero { Utility::Math::phi(n, p, q) }; // Calculates phi(n)

        // Chooses the first value that is correct for 'e'
        long long int e {};
        for (long long int i { 2 }; i < n_eulero; ++i)
            if (Utility::Math::areCoprimes(i, n_eulero)) {
                e = i;
                break;
            }

        return Key::Public { n, e };
    }

    Key::Private privateKey(const long long int p, const long long int q, const Key::Public& publicKey) {
        assert(Utility::Math::isPrime(p) && Utility::Math::isPrime(q) && "ERROR: p and/or q are not prime numbers."); // Make sure p and q are prime numbers
        
        const long long int n_eulero { Utility::Math::phi(publicKey.n, p, q) }; // Calculates phi(n) again
        
        long long int k { 1 };
        long long int d {};
        bool isFindingK { true };
        do {
            double temp_d { 0.0f };
            constexpr double epsilon { 0.0001f };

            temp_d = (1.0f / publicKey.e) + k * (static_cast<double>(n_eulero) / publicKey.e);

            if (temp_d <= static_cast<long long int>(temp_d) + epsilon) {
                d = static_cast<long long int>(temp_d);
                isFindingK = false;
            }
            else
                ++k;
        } while (isFindingK);

        return Key::Private { p, q, d };
    }
}

// Encodes a message encoded into a whole number 'm' using a public key. The encoding results into an encoded whole number 'c'
long long int encode(const Key::Public& publicKey, const long long int m) {
    const long long int c { Utility::Math::power(m, publicKey.e) % publicKey.n };

    return c;
}

// Decodes a message that was encoded into a whole number 'c' utilizing both the public and private keys. This decoding will give back the original whole number 'm'.
long long int decode(const Key::Public& publicKey, const Key::Private& privateKey, const long long int c) {
    const long long int m { Utility::Math::power(c, privateKey.d) % publicKey.n };

    return m;
}

int main() {
    long long int p {};
    std::cout << "Insert p: ";
    std::cin >> p;
    
    long long int q {};
    std::cout << "Insert q: ";
    std::cin >> q;

    const std::string publicKey_filename    { "publickey.txt" };
    const std::string privateKey_filename   { "privatekey.txt" };

    const Key::Public publicKey     { Generate::publicKey(p, q)};
    const Key::Private privateKey   { Generate::privateKey(p, q, publicKey) };

    Utility::File::saveTo(publicKey_filename, publicKey);
    Utility::File::saveTo(privateKey_filename, privateKey);

    // Get whole number 'm', to be encoded, from the user
    long long int m {};
    std::cout << "Insert m: ";
    std::cin >> m;

    assert(0 < m && m < publicKey.n && "Error: m isn't bigger than 0 and smaller than n (0<m<n)");

    const long long int c { encode(publicKey, m) };

    std::cout << "Encoded number c: " << c << '\n';

    const long long int m_decoded { decode(publicKey, privateKey, c) };

    std::cout << "Decoded number m: " << m_decoded << '\n';

    if (m == m_decoded)
        std::cout << "Encoding/Decoding successful!\n";
    else
        std::cout << "Encoding/Decoding failed.\n";

    return 0;
}