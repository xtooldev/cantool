// ============================================================================
//  Seed -> Key   安全访问（UDS 0x27）算法接口（刷写）
// ----------------------------------------------------------------------------
//  系统     : FAWJieFang_J7_VCU_FAW_VCU2
//  菜单     : FAW VCU（二代）
//  算法库   : FAWJieFang_J7_VCU_FAW_VCU2_Alg_Flash.dll
//  导出函数 : GenerateKeyEx
//  定位方式 : ECU 程序指定
//  ABI      : ASAM MCD-1 SeedKey 标准（cdecl，7 参）
// ============================================================================
//
//  这个算法库已经静态反出来了 —— 下面这份实现不链接任何 dll，
//  也不需要 32 位宿主，拷进你自己的工程即可。
//
//      明文算法 : key = AES-128-ECB(seed 用 0x00 补齐到 16 的整数倍)，固定密钥
//      来源 dll : FAWJieFang_J7_VCU_FAW_VCU2_Alg_Flash.dll    （刷写）
//
//  下面这段与 dll 的输出逐字节一致（已用随机种子对拍验证）。
//
#include <cstddef>
#include <cstring>
#include <vector>

namespace faw {

static const unsigned char kAesKey[16] = {
    0xE5, 0xD6, 0xE8, 0x46, 0x56, 0xC1, 0x66, 0x4C,
    0xB4, 0x23, 0xEC, 0xB7, 0x4C, 0xB8, 0x41, 0xCD,
};

static const unsigned char kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};
// AES-128 密钥扩展，rk 至少 176 字节。
static void ExpandKey(const unsigned char key[16], unsigned char* rk)
{
    static const unsigned char rcon[10] = {1,2,4,8,16,32,64,128,0x1b,0x36};
    std::memcpy(rk, key, 16);
    for (int i = 4; i < 44; ++i) {
        unsigned char t[4];
        std::memcpy(t, rk + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            unsigned char a = t[0];
            t[0] = (unsigned char)(kSbox[t[1]] ^ rcon[i / 4 - 1]);
            t[1] = kSbox[t[2]];
            t[2] = kSbox[t[3]];
            t[3] = kSbox[a];
        }
        for (int j = 0; j < 4; ++j)
            rk[i * 4 + j] = (unsigned char)(rk[(i - 4) * 4 + j] ^ t[j]);
    }
}

static unsigned char Xt(unsigned char x)
{
    return (unsigned char)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

// AES-128 单块加密。状态按 in[r + 4*c] 铺开，和标准 AES 一致。
static void EncryptBlock(const unsigned char* rk, const unsigned char in[16],
                         unsigned char out[16])
{
    unsigned char s[16];
    for (int i = 0; i < 16; ++i) s[i] = (unsigned char)(in[i] ^ rk[i]);
    for (int round = 1; round <= 10; ++round) {
        for (int i = 0; i < 16; ++i) s[i] = kSbox[s[i]];        // SubBytes
        unsigned char t;                                        // ShiftRows
        t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
        t = s[2];  s[2]  = s[10]; s[10] = t;
        t = s[6];  s[6]  = s[14]; s[14] = t;
        t = s[3];  s[3]  = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = t;
        if (round != 10) {                                      // MixColumns
            for (int c = 0; c < 4; ++c) {
                unsigned char* a = s + c * 4;
                unsigned char d0 = Xt(a[0]), d1 = Xt(a[1]),
                              d2 = Xt(a[2]), d3 = Xt(a[3]);
                unsigned char b0 = (unsigned char)(d0 ^ d1 ^ a[1] ^ a[2] ^ a[3]);
                unsigned char b1 = (unsigned char)(a[0] ^ d1 ^ d2 ^ a[2] ^ a[3]);
                unsigned char b2 = (unsigned char)(a[0] ^ a[1] ^ d2 ^ d3 ^ a[3]);
                unsigned char b3 = (unsigned char)(d0 ^ a[0] ^ a[1] ^ a[2] ^ d3);
                a[0] = b0; a[1] = b1; a[2] = b2; a[3] = b3;
            }
        }
        for (int i = 0; i < 16; ++i)
            s[i] = (unsigned char)(s[i] ^ rk[round * 16 + i]);  // AddRoundKey
    }
    std::memcpy(out, s, 16);
}

// 对外接口：输入 seed，输出 key。
static bool CalcKey(const std::vector<unsigned char>& seed,
                    std::vector<unsigned char>&       key)
{
    key.clear();
    if (seed.empty()) return true;                     // 空种子得空密钥
    std::vector<unsigned char> data(seed);
    data.resize((data.size() + 15) / 16 * 16, 0x00);   // 0x00 补齐
    unsigned char rk[176];
    ExpandKey(kAesKey, rk);
    key.resize(data.size());
    for (std::size_t i = 0; i < data.size(); i += 16)
        EncryptBlock(rk, &data[i], &key[i]);
    return true;
}

} // namespace faw

// ----------------------------------------------------------------------------
//  用法：
//      std::vector<unsigned char> seed = {0xFA, 0x31, 0x56, 0x71};
//      std::vector<unsigned char> key;
//      faw::CalcKey(seed, key);      // key 即 0x27 要回发的密钥
