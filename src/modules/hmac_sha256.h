#ifndef SHA256_H
#define SHA256_H

#include <vector>
#include <cstdint>

class Sha256Context
{
public:
    Sha256Context();
    void Update(const void *buffer, uint32_t bufferSize);
    void Finalise(std::vector<uint8_t> &digest);
    static void Calculate(const void *buffer, uint32_t bufferSize, std::vector<uint8_t> &digest);

private:
    uint64_t length;
    uint32_t state[8], curlen;
    uint8_t buf[64];

    static const uint32_t K[64];
    static void TransformFunction(Sha256Context *context, const uint8_t *buffer);
};

#endif // SHA256_H
