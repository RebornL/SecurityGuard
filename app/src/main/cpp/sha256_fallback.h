/**
 * SHA-256 Fallback实现
 *
 * 当OpenSSL不可用时使用此实现
 * 注意：这是一个纯C++实现的SHA-256，性能可能不如OpenSSL
 */

#ifndef SHA256_FALLBACK_H
#define SHA256_FALLBACK_H

#ifdef USE_FALLBACK_HASH

#include <cstdint>
#include <vector>
#include <string>
#include <cstring>

namespace security {

class Sha256Fallback {
public:
    static std::string hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> digest(DIGEST_SIZE);
        compute(data.data(), data.size(), digest.data());
        return bytesToHex(digest);
    }

    static std::string hash(const uint8_t* data, size_t length) {
        std::vector<uint8_t> digest(DIGEST_SIZE);
        compute(data, length, digest.data());
        return bytesToHex(digest);
    }

private:
    static constexpr size_t DIGEST_SIZE = 32;  // 256 bits = 32 bytes
    static constexpr size_t BLOCK_SIZE = 64;   // 512 bits = 64 bytes

    // SHA-256初始哈希值
    static constexpr uint32_t INITIAL_H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // SHA-256常量K
    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static void compute(const uint8_t* message, size_t length, uint8_t* digest) {
        uint32_t h[8];
        for (int i = 0; i < 8; i++) {
            h[i] = INITIAL_H[i];
        }

        // 预处理：添加填充位和长度
        size_t paddedLength = length + 1 + 8;  // 数据 + 0x80 + 8字节长度
        while (paddedLength % BLOCK_SIZE != 0) {
            paddedLength++;
        }

        std::vector<uint8_t> paddedMessage(paddedLength, 0);
        memcpy(paddedMessage.data(), message, length);
        paddedMessage[length] = 0x80;  // 添加1位和后续的0位

        // 添加原始消息长度（以位为单位）
        uint64_t bitLength = length * 8;
        for (int i = 0; i < 8; i++) {
            paddedMessage[paddedLength - 8 + i] = static_cast<uint8_t>(bitLength >> (56 - 8 * i));
        }

        // 处理每个512位块
        for (size_t offset = 0; offset < paddedLength; offset += BLOCK_SIZE) {
            processBlock(paddedMessage.data() + offset, h);
        }

        // 生成最终哈希值
        for (int i = 0; i < 8; i++) {
            digest[4 * i] = static_cast<uint8_t>(h[i] >> 24);
            digest[4 * i + 1] = static_cast<uint8_t>(h[i] >> 16);
            digest[4 * i + 2] = static_cast<uint8_t>(h[i] >> 8);
            digest[4 * i + 3] = static_cast<uint8_t>(h[i]);
        }
    }

    static void processBlock(const uint8_t* block, uint32_t* h) {
        uint32_t w[64];

        // 准备消息调度数组
        for (int i = 0; i < 16; i++) {
            w[i] = (static_cast<uint32_t>(block[4 * i]) << 24) |
                   (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
                   (static_cast<uint32_t>(block[4 * i + 2]) << 8) |
                   static_cast<uint32_t>(block[4 * i + 3]);
        }

        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        // 初始化工作变量
        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t h_var = h[7];

        // 主循环
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h_var + S1 + ch + K[i] + w[i];
            uint32_t S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h_var = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // 更新哈希值
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_var;
    }

    static uint32_t rightRotate(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

    static std::string bytesToHex(const std::vector<uint8_t>& bytes) {
        static const char hexChars[] = "0123456789abcdef";
        std::string result;
        result.reserve(bytes.size() * 2);
        for (uint8_t byte : bytes) {
            result.push_back(hexChars[(byte >> 4) & 0x0F]);
            result.push_back(hexChars[byte & 0x0F]);
        }
        return result;
    }
};

} // namespace security

#endif // USE_FALLBACK_HASH

#endif // SHA256_FALLBACK_H