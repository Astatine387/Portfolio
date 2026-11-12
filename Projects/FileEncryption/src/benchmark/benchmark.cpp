/**
 * @file    benchmark.cpp
 * @brief   AES-256-GCM pipeline and Argon2id key derivation benchmark
 * @author  Astatine387
 */

#include <benchmark/benchmark.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/constants.h"
#include "core/aes_gcm.h"
#include "core/file_header.h"
#include "core/secure_key.h"
#include "utils/byte_order.h"
#include "utils/platform.h"

namespace {

constexpr int64_t kBenchSize = 256LL * 1024 * 1024;
constexpr int64_t kSpeedChunk = 16LL * 1024;
constexpr int64_t kPipeChunk = static_cast<int64_t>(kChunkSize);

constexpr std::string_view kBenchPw = "benchmark-password";
constexpr std::array<uint8_t, kSaltSize> kBenchSalt{};

constexpr std::string_view kPlainName = "plain.tmp";
constexpr std::string_view kCipherName = "cipher.tmp";
constexpr std::string_view kOutName = "out.tmp";

/**
 * @brief   Build a scratch file path under FE_BENCH_DIR
 * @param   name  File name
 * @return  Full path to the scratch file
 */
std::string BenchPath(std::string_view name) {
  const char* dir = std::getenv("FE_BENCH_DIR");

  std::string path = (dir != nullptr && *dir != '\0') ? dir : ".";

  path += '/';
  path += name;

  return path;
}

/**
 * @brief   Derive the shared session key
 * @return  Pointer to the key on success, nullptr on failure
 */
const SecureKey* SharedKey() {
  static const std::optional<SecureKey> key = DeriveKey(
      std::span<const char>(kBenchPw.data(), kBenchPw.size()), kBenchSalt);

  return key.has_value() ? &key.value() : nullptr;
}

/**
 * @brief   Fill a file with cryptographically secure random bytes
 * @param   path  Destination path
 * @param   size  File size in bytes
 * @return  kSuccess on success, kFailure on failure
 */
Result WriteRandomFile(const std::string& path, int64_t size) {
  std::vector<uint8_t> data(static_cast<size_t>(size));

  if (Random(data.data(), data.size()) == Result::kFailure) {
    return Result::kFailure;
  }

  FILE* file = nullptr;

  OpenFile(&file, path, "wb");

  if (file == nullptr) {
    return Result::kFailure;
  }

  const bool res =
      fwrite(data.data(), sizeof(uint8_t), data.size(), file) == data.size();

  fclose(file);

  if (!res) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

/**
 * @brief   Encrypt the plaintext scratch file
 * @param   key   Session key
 * @return  kSuccess on success, kFailure on failure
 */
Result BuildCipherFile(const SecureKey& key) {
  auto aes = std::make_unique<AesGcm>();

  FILE* src = nullptr;
  FILE* dst = nullptr;

  OpenFile(&src, BenchPath(kPlainName), "rb");
  OpenFile(&dst, BenchPath(kCipherName), "wb+");

  Result res = Result::kFailure;

  if (src != nullptr && dst != nullptr) {
    res = aes->Encrypt(src, dst, key);
  }

  if (src != nullptr) {
    fclose(src);
  }

  if (dst != nullptr) {
    fclose(dst);
  }

  return res;
}

/**
 * @brief   Removes the scratch files when the process exits
 */
class ScratchCleaner {
 public:
  ScratchCleaner()
      : plain_(BenchPath(kPlainName)),
        cipher_(BenchPath(kCipherName)),
        out_(BenchPath(kOutName)) {}

  // NOLINTNEXTLINE(bugprone-exception-escape)
  ~ScratchCleaner() {
    RemoveFile(plain_);
    RemoveFile(cipher_);
    RemoveFile(out_);
  }

  ScratchCleaner(const ScratchCleaner&) = delete;
  ScratchCleaner& operator=(const ScratchCleaner&) = delete;
  ScratchCleaner(ScratchCleaner&&) = delete;
  ScratchCleaner& operator=(ScratchCleaner&&) = delete;

 private:
  std::string plain_;   // Plaintext scratch file
  std::string cipher_;  // Ciphertext scratch file
  std::string out_;     // Decryption output scratch file
};

/**
 * @brief   Create the scratch files
 * @return  kSuccess when the scratch files are ready, kFailure otherwise
 */
Result CreateScratch() {
  static const Result ready = []() {
    static const ScratchCleaner cleaner;

    const SecureKey* key = SharedKey();

    if (key == nullptr) {
      return Result::kFailure;
    }

    if (WriteRandomFile(BenchPath(kPlainName), kBenchSize) ==
        Result::kFailure) {
      return Result::kFailure;
    }

    return BuildCipherFile(*key);
  }();

  return ready;
}

/**
 * @brief   Raw OpenSSL AES-256-GCM throughput without file I/O
 * @param   state   Benchmark state, range(0) is the chunk size in bytes
 */
void BenchRawEvpEncrypt(benchmark::State& state) {
  const SecureKey* key = SharedKey();

  if (key == nullptr) {
    state.SkipWithError("Key derivation failed");
    return;
  }

  const size_t chunk = static_cast<size_t>(state.range(0));
  const int64_t rounds = kBenchSize / state.range(0);

  std::vector<uint8_t> src(chunk);
  std::vector<uint8_t> dst(chunk);

  if (Random(src.data(), src.size()) == Result::kFailure) {
    state.SkipWithError("Random failed");
    return;
  }

  std::array<uint8_t, kNonceSize> nonce{};

  if (Random(nonce.data(), nonce.size()) == Result::kFailure) {
    state.SkipWithError("Random failed");
    return;
  }

  for (auto _ : state) {
    (void)_;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (ctx == nullptr) {
      state.SkipWithError("Cannot create OpenSSL context");
      break;
    }

    bool res =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ==
            1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(kNonceSize), nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key->Bytes().data(),
                           nonce.data()) == 1;

    for (int64_t i = 0; res && i < rounds; i++) {
      int dstlen = 0;

      res = EVP_EncryptUpdate(ctx, dst.data(), &dstlen, src.data(),
                              static_cast<int>(chunk)) == 1;
    }

    std::array<uint8_t, kBlockSize> final_block{};
    int final_len = 0;

    res = res && EVP_EncryptFinal_ex(ctx, final_block.data(), &final_len) == 1;

    EVP_CIPHER_CTX_free(ctx);

    benchmark::DoNotOptimize(dst.data());
    benchmark::ClobberMemory();

    if (!res) {
      state.SkipWithError("OpenSSL AES-256-GCM failed");
      break;
    }
  }

  state.SetBytesProcessed(state.iterations() * rounds * state.range(0));
  state.SetLabel(std::to_string(state.range(0) / 1024) + " KiB chunks");
}

/**
 * @brief   Raw OpenSSL AES-256-GCM throughput
 * @param   state   Benchmark state
 */
void BenchRawEvpChunked(benchmark::State& state) {
  const SecureKey* key = SharedKey();

  if (key == nullptr) {
    state.SkipWithError("Key derivation failed");
    return;
  }

  const int64_t rounds = kBenchSize / static_cast<int64_t>(kChunkSize);

  std::vector<uint8_t> src(kChunkSize);
  std::vector<uint8_t> dst(kChunkSize + kTagSize);

  if (Random(src.data(), src.size()) == Result::kFailure) {
    state.SkipWithError("Random failed");
    return;
  }

  FileHeader header;

  header.salt = kBenchSalt;

  std::array<uint8_t, kHeaderSize> aad{};

  SerializeHeader(aad, header);

  for (auto _ : state) {
    (void)_;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (ctx == nullptr) {
      state.SkipWithError("Cannot create OpenSSL context");
      break;
    }

    bool res =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ==
            1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(kNonceSize), nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key->Bytes().data(),
                           nullptr) == 1;

    for (int64_t i = 0; res && i < rounds; i++) {
      std::array<uint8_t, kNonceSize> nonce{};
      std::array<uint8_t, kBlockSize> final_block{};

      StoreBE64(nonce.data() + kNonceSize - 1 - sizeof(uint64_t),
                static_cast<uint64_t>(i));

      nonce[kNonceSize - 1] = i + 1 == rounds ? 1 : 0;

      int dstlen = 0;

      res = EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, nonce.data()) ==
                1 &&
            EVP_EncryptUpdate(ctx, nullptr, &dstlen, aad.data(),
                              static_cast<int>(aad.size())) == 1 &&
            EVP_EncryptUpdate(ctx, dst.data(), &dstlen, src.data(),
                              static_cast<int>(kChunkSize)) == 1 &&
            EVP_EncryptFinal_ex(ctx, final_block.data(), &dstlen) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                static_cast<int>(kTagSize),
                                dst.data() + kChunkSize) == 1;
    }

    EVP_CIPHER_CTX_free(ctx);

    benchmark::DoNotOptimize(dst.data());
    benchmark::ClobberMemory();

    if (!res) {
      state.SkipWithError("OpenSSL AES-256-GCM failed");
      break;
    }
  }

  state.SetBytesProcessed(state.iterations() * rounds *
                          static_cast<int64_t>(kChunkSize));
  state.SetLabel(std::to_string(kChunkSize / 1024) +
                 " KiB chunks, per-chunk nonce, AAD and tag");
}

/**
 * @brief   End-to-end encryption throughput using AesGcm pipeline
 * @param   state   Benchmark state
 */
void BenchPipelineEncrypt(benchmark::State& state) {
  if (CreateScratch() == Result::kFailure) {
    state.SkipWithError("Cannot prepare scratch files");
    return;
  }

  const SecureKey* key = SharedKey();

  if (key == nullptr) {
    state.SkipWithError("Key derivation failed");
    return;
  }

  const std::string src_path = BenchPath(kPlainName);
  const std::string dst_path = BenchPath(kCipherName);

  for (auto _ : state) {
    (void)_;

    auto aes = std::make_unique<AesGcm>();

    FILE* src = nullptr;
    FILE* dst = nullptr;

    OpenFile(&src, src_path, "rb");
    OpenFile(&dst, dst_path, "wb+");

    bool res = src != nullptr && dst != nullptr;

    if (res) {
      res = aes->Encrypt(src, dst, *key) == Result::kSuccess;
    }

    if (src != nullptr) {
      fclose(src);
    }

    if (dst != nullptr) {
      fclose(dst);
    }

    if (!res) {
      state.SkipWithError("Encryption failed");
      break;
    }
  }

  state.SetBytesProcessed(state.iterations() * kBenchSize);
}

/**
 * @brief   End-to-end decryption throughput using AesGcm pipeline
 * @param   state   Benchmark state
 */
void BenchPipelineDecrypt(benchmark::State& state) {
  if (CreateScratch() == Result::kFailure) {
    state.SkipWithError("Cannot prepare scratch files");
    return;
  }

  const SecureKey* key = SharedKey();

  if (key == nullptr) {
    state.SkipWithError("Key derivation failed");
    return;
  }

  const std::string src_path = BenchPath(kCipherName);
  const std::string dst_path = BenchPath(kOutName);

  for (auto _ : state) {
    (void)_;

    auto aes = std::make_unique<AesGcm>();

    FILE* src = nullptr;
    FILE* dst = nullptr;

    OpenFile(&src, src_path, "rb");
    OpenFile(&dst, dst_path, "wb+");

    FileHeader header;

    bool res = src != nullptr && dst != nullptr &&
               ReadHeader(src, header) == HeaderStatus::kOk;

    if (res) {
      res = aes->Decrypt(src, dst, *key, header) == Result::kSuccess;
    }

    if (src != nullptr) {
      fclose(src);
    }

    if (dst != nullptr) {
      fclose(dst);
    }

    if (!res) {
      state.SkipWithError("Decryption failed");
      break;
    }
  }

  state.SetBytesProcessed(state.iterations() * kBenchSize);
}

/**
 * @brief   File I/O floor
 * @param   state   Benchmark state
 */
void BenchFileCopy(benchmark::State& state) {
  if (CreateScratch() == Result::kFailure) {
    state.SkipWithError("Cannot prepare scratch files");
    return;
  }

  const std::string src_path = BenchPath(kPlainName);
  const std::string dst_path = BenchPath(kOutName);
  const int64_t rounds = kBenchSize / static_cast<int64_t>(kChunkSize);

  std::vector<uint8_t> buff(kChunkSize);

  for (auto _ : state) {
    (void)_;

    FILE* src = nullptr;
    FILE* dst = nullptr;

    OpenFile(&src, src_path, "rb");
    OpenFile(&dst, dst_path, "wb+");

    bool res = src != nullptr && dst != nullptr;

    for (int64_t i = 0; res && i < rounds; i++) {
      res =
          fread(buff.data(), sizeof(uint8_t), kChunkSize, src) == kChunkSize &&
          fwrite(buff.data(), sizeof(uint8_t), kChunkSize, dst) == kChunkSize;
    }

    if (src != nullptr) {
      fclose(src);
    }

    if (dst != nullptr) {
      fclose(dst);
    }

    if (!res) {
      state.SkipWithError("File copy failed");
      break;
    }
  }

  state.SetBytesProcessed(state.iterations() * kBenchSize);
  state.SetLabel(std::to_string(kChunkSize / 1024) +
                 " KiB reads and writes, no crypto");
}

/**
 * @brief   Raw OpenSSL AES-256-GCM over a working set too large for the cache
 * @param   state   Benchmark state
 */
void BenchRawEvpStreaming(benchmark::State& state) {
  const SecureKey* key = SharedKey();

  if (key == nullptr) {
    state.SkipWithError("Key derivation failed");
    return;
  }

  const int64_t rounds = kBenchSize / static_cast<int64_t>(kChunkSize);

  std::vector<uint8_t> buff(static_cast<size_t>(kBenchSize));

  FileHeader header;

  header.salt = kBenchSalt;

  std::array<uint8_t, kHeaderSize> aad{};

  SerializeHeader(aad, header);

  std::array<uint8_t, kTagSize> tag{};

  for (auto _ : state) {
    (void)_;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (ctx == nullptr) {
      state.SkipWithError("Cannot create OpenSSL context");
      break;
    }

    bool res =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ==
            1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(kNonceSize), nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key->Bytes().data(),
                           nullptr) == 1;

    for (int64_t i = 0; res && i < rounds; i++) {
      std::array<uint8_t, kNonceSize> nonce{};
      std::array<uint8_t, kBlockSize> final_block{};

      StoreBE64(nonce.data() + kNonceSize - 1 - sizeof(uint64_t),
                static_cast<uint64_t>(i));

      nonce[kNonceSize - 1] = i + 1 == rounds ? 1 : 0;

      uint8_t* chunk = buff.data() + (static_cast<size_t>(i) * kChunkSize);
      int dstlen = 0;

      res = EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, nonce.data()) ==
                1 &&
            EVP_EncryptUpdate(ctx, nullptr, &dstlen, aad.data(),
                              static_cast<int>(aad.size())) == 1 &&
            EVP_EncryptUpdate(ctx, chunk, &dstlen, chunk,
                              static_cast<int>(kChunkSize)) == 1 &&
            EVP_EncryptFinal_ex(ctx, final_block.data(), &dstlen) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                static_cast<int>(kTagSize), tag.data()) == 1;
    }

    EVP_CIPHER_CTX_free(ctx);

    benchmark::DoNotOptimize(buff.data());
    benchmark::ClobberMemory();

    if (!res) {
      state.SkipWithError("OpenSSL AES-256-GCM failed");
      break;
    }
  }

  state.SetBytesProcessed(state.iterations() * kBenchSize);
  state.SetLabel(std::to_string(kChunkSize / 1024) +
                 " KiB chunks, 256 MiB working set");
}

/**
 * @brief   Encrypt a file the way the pipeline does
 * @param   src   Source file
 * @param   dst   Destination file
 * @param   key   Session key
 * @return  kSuccess on success, kFailure on failure
 */
Result EncryptSync(FILE* src, FILE* dst, const SecureKey& key) {
  FileHeader header;

  header.params = key.Params();
  std::ranges::copy(key.Salt(), header.salt.begin());
  std::ranges::copy(key.Commitment(), header.commitment.begin());

  std::array<uint8_t, kHeaderSize> aad{};

  SerializeHeader(aad, header);

  if (fwrite(aad.data(), sizeof(uint8_t), aad.size(), dst) != aad.size()) {
    return Result::kFailure;
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  if (ctx == nullptr) {
    return Result::kFailure;
  }

  bool res = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                                nullptr) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 static_cast<int>(kNonceSize), nullptr) == 1 &&
             EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.Bytes().data(),
                                nullptr) == 1;

  const int64_t rounds = kBenchSize / static_cast<int64_t>(kChunkSize);

  std::vector<uint8_t> buff(kChunkSize + kTagSize);

  for (int64_t i = 0; res && i < rounds; i++) {
    std::array<uint8_t, kNonceSize> nonce{};
    std::array<uint8_t, kBlockSize> final_block{};

    StoreBE64(nonce.data() + kNonceSize - 1 - sizeof(uint64_t),
              static_cast<uint64_t>(i));

    nonce[kNonceSize - 1] = i + 1 == rounds ? 1 : 0;

    int dstlen = 0;

    res = fread(buff.data(), sizeof(uint8_t), kChunkSize, src) == kChunkSize;

    if (res) {
      res = EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, nonce.data()) ==
                1 &&
            EVP_EncryptUpdate(ctx, nullptr, &dstlen, aad.data(),
                              static_cast<int>(aad.size())) == 1 &&
            EVP_EncryptUpdate(ctx, buff.data(), &dstlen, buff.data(),
                              static_cast<int>(kChunkSize)) == 1 &&
            EVP_EncryptFinal_ex(ctx, final_block.data(), &dstlen) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                static_cast<int>(kTagSize),
                                buff.data() + kChunkSize) == 1;
    }

    if (res) {
      res =
          fwrite(buff.data(), sizeof(uint8_t), buff.size(), dst) == buff.size();
    }
  }

  EVP_CIPHER_CTX_free(ctx);

  if (!res) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

/**
 * @brief   End-to-end encryption throughput with synchronous write
 * @param   state   Benchmark state
 */
void BenchPipelineEncryptSync(benchmark::State& state) {
  if (CreateScratch() == Result::kFailure) {
    state.SkipWithError("Cannot prepare scratch files");
    return;
  }

  const SecureKey* key = SharedKey();

  if (key == nullptr) {
    state.SkipWithError("Key derivation failed");
    return;
  }

  const std::string src_path = BenchPath(kPlainName);
  const std::string dst_path = BenchPath(kOutName);

  for (auto _ : state) {
    (void)_;

    FILE* src = nullptr;
    FILE* dst = nullptr;

    OpenFile(&src, src_path, "rb");
    OpenFile(&dst, dst_path, "wb+");

    bool res = src != nullptr && dst != nullptr;

    if (res) {
      res = EncryptSync(src, dst, *key) == Result::kSuccess;
    }

    if (src != nullptr) {
      fclose(src);
    }

    if (dst != nullptr) {
      fclose(dst);
    }

    if (!res) {
      state.SkipWithError("Encryption failed");
      break;
    }
  }

  state.SetBytesProcessed(state.iterations() * kBenchSize);
  state.SetLabel("256 MiB, tmpfs, synchronous write");
}

/**
 * @brief   Argon2id key derivation at the parameters this build ships with
 * @param   state   Benchmark state
 */
void BenchArgon2id(benchmark::State& state) {
  std::array<uint8_t, kSaltSize> salt{};

  for (size_t i = 0; i < kSaltSize; i++) {
    salt[i] = static_cast<uint8_t>(i);
  }

  for (auto _ : state) {
    (void)_;

    auto key = DeriveKey(
        std::span<const char>(kBenchPw.data(), kBenchPw.size()), salt);

    benchmark::DoNotOptimize(key);

    if (!key.has_value()) {
      state.SkipWithError("Key derivation failed");
      break;
    }
  }
}

}  // namespace

BENCHMARK(BenchRawEvpEncrypt)
    ->Arg(kSpeedChunk)
    ->Arg(kPipeChunk)
    ->Unit(benchmark::kMillisecond);
BENCHMARK(BenchRawEvpChunked)->Unit(benchmark::kMillisecond);
BENCHMARK(BenchRawEvpStreaming)->Unit(benchmark::kMillisecond);
BENCHMARK(BenchFileCopy)->Unit(benchmark::kMillisecond);
BENCHMARK(BenchPipelineEncrypt)->Unit(benchmark::kMillisecond);
BENCHMARK(BenchPipelineEncryptSync)->Unit(benchmark::kMillisecond);
BENCHMARK(BenchPipelineDecrypt)->Unit(benchmark::kMillisecond);

BENCHMARK(BenchArgon2id)->Unit(benchmark::kMillisecond)->Iterations(3);

BENCHMARK_MAIN();
