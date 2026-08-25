/**
 * @file    benchmark.cpp
 * @brief   AES-256-GCM pipeline throughput, raw OpenSSL baseline, and Argon2id key derivation
 * @author  Astatine387
 */

#include <benchmark/benchmark.h>
#include <openssl/evp.h>

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
#include "core/secure_key.h"
#include "utils/platform.h"

namespace {

constexpr int64_t kBenchSize = 256LL * 1024 * 1024;
constexpr int64_t kSpeedChunk = 16LL * 1024;

constexpr int64_t kPipeChunk = static_cast<int64_t>(kBuffSize * kBlockSize);

constexpr std::string_view kBenchPw = "benchmark-password";
constexpr std::array<uint8_t, kSaltSize> kBenchSalt{};

constexpr std::string_view kPlainName = "plain.tmp";
constexpr std::string_view kCipherName = "cipher.tmp";
constexpr std::string_view kOutName = "out.tmp";

/**
 * @brief   Build a scratch file path under FE_BENCH_DIR
 * @param   name    File name
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
 * @brief   Derive the shared session key and hand out a view of it
 * @return  Pointer to the shared key on success, nullptr on failure
 */
const SecureKey* SharedKey() {
  static const std::optional<SecureKey> key =
      DeriveKey(std::span<const char>(kBenchPw.data(), kBenchPw.size()), kBenchSalt);

  return key.has_value() ? &key.value() : nullptr;
}

/**
 * @brief   Fill a file with cryptographically secure random bytes
 * @param   path    Destination path
 * @param   size    File size in bytes
 * @return  true on success
 */
bool WriteRandomFile(const std::string& path, int64_t size) {
  std::vector<uint8_t> data(static_cast<size_t>(size));

  if (Random(data.data(), data.size()) == Result::kFailure) {
    return false;
  }

  FILE* file = nullptr;

  OpenFile(&file, path, "wb");

  if (file == nullptr) {
    return false;
  }

  const bool res = fwrite(data.data(), sizeof(uint8_t), data.size(), file) == data.size();

  fclose(file);

  return res;
}

/**
 * @brief   Encrypt the plaintext scratch file
 * @param   key     Session key
 * @return  true on success
 */
bool BuildCipherFile(const SecureKey& key) {
  auto aes = std::make_unique<AesGcm>();

  FILE* src = nullptr;
  FILE* dst = nullptr;

  OpenFile(&src, BenchPath(kPlainName), "rb");
  OpenFile(&dst, BenchPath(kCipherName), "wb+");

  bool res = src != nullptr && dst != nullptr;

  if (res) {
    res = aes->Encrypt(src, dst, key, kBenchSalt) == Result::kSuccess;
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
 * @class   ScratchCleaner
 * @brief   Removes the scratch files when the process exits
 */
class ScratchCleaner {
 public:
  ScratchCleaner() : plain_(BenchPath(kPlainName)), cipher_(BenchPath(kCipherName)), out_(BenchPath(kOutName)) {}

  // NOLINTNEXTLINE(bugprone-exception-escape) paths are built in the constructor; nothing here allocates
  ~ScratchCleaner() {
    RemoveFile(plain_);
    RemoveFile(cipher_);
    RemoveFile(out_);
  }

  ScratchCleaner(const ScratchCleaner&) = delete;             // Delete copy constructor
  ScratchCleaner& operator=(const ScratchCleaner&) = delete;  // Delete copy assignment operator
  ScratchCleaner(ScratchCleaner&&) = delete;                  // Delete move constructor
  ScratchCleaner& operator=(ScratchCleaner&&) = delete;       // Delete move assignment operator

 private:
  std::string plain_;   // Plaintext scratch file
  std::string cipher_;  // Ciphertext scratch file
  std::string out_;     // Decryption output scratch file
};

/**
 * @brief   Create the scratch files
 * @return  true when the scratch files are ready
 */
bool CreateScratch() {
  static const bool ready = []() {
    static const ScratchCleaner cleaner;

    const SecureKey* key = SharedKey();

    if (key == nullptr) {
      return false;
    }

    if (!WriteRandomFile(BenchPath(kPlainName), kBenchSize)) {
      return false;
    }

    return BuildCipherFile(*key);
  }();

  return ready;
}

/**
 * @brief   Raw OpenSSL AES-256-GCM throughput, no file I/O
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

  std::array<uint8_t, kIVSize> iv{};

  if (Random(iv.data(), iv.size()) == Result::kFailure) {
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

    bool res = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIVSize), nullptr) == 1 &&
               EVP_EncryptInit_ex(ctx, nullptr, nullptr, key->Bytes().data(), iv.data()) == 1;

    for (int64_t i = 0; res && i < rounds; i++) {
      int dstlen = 0;

      res = EVP_EncryptUpdate(ctx, dst.data(), &dstlen, src.data(), static_cast<int>(chunk)) == 1;
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
 * @brief   End-to-end encryption throughput through the real AesGcm pipeline
 * @param   state   Benchmark state
 */
void BenchPipelineEncrypt(benchmark::State& state) {
  if (!CreateScratch()) {
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
      res = aes->Encrypt(src, dst, *key, kBenchSalt) == Result::kSuccess;
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
 * @brief   End-to-end decryption throughput through the real AesGcm pipeline
 * @param   state   Benchmark state
 */
void BenchPipelineDecrypt(benchmark::State& state) {
  if (!CreateScratch()) {
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

    bool res = src != nullptr && dst != nullptr;

    if (res) {
      res = aes->Decrypt(src, dst, *key) == Result::kSuccess;
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

    auto key = DeriveKey(std::span<const char>(kBenchPw.data(), kBenchPw.size()), salt);

    benchmark::DoNotOptimize(key);

    if (!key.has_value()) {
      state.SkipWithError("Key derivation failed");
      break;
    }
  }
}

}  // namespace

BENCHMARK(BenchRawEvpEncrypt)->Arg(kSpeedChunk)->Arg(kPipeChunk)->Unit(benchmark::kMillisecond);
BENCHMARK(BenchPipelineEncrypt)->Unit(benchmark::kMillisecond);
BENCHMARK(BenchPipelineDecrypt)->Unit(benchmark::kMillisecond);
/* Few iterations per repetition: at 512 MiB of memory cost a single derivation already dominates, and the
 * spread is better captured by --benchmark_repetitions than by averaging inside one repetition. */

BENCHMARK(BenchArgon2id)->Unit(benchmark::kMillisecond)->Iterations(3);

BENCHMARK_MAIN();
