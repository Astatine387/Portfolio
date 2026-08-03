/**
 * @file    benchmark.cpp
 * @brief   AES-GCM and Argon2id peformance test
 * @author  Astatine387
 */

#include <benchmark/benchmark.h>

#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <string>

#include "core/aes_gcm.h"
#include "core/secure_key.h"
#include "utils/platform.h"

inline constexpr int64_t kFileSize = 4LL * 1024 * 1024 * 1024;

/**
 * @class   Benchmark
 * @brief   Fixture for AES-GCM and Argon2id performance test
 */
class Benchmark : public benchmark::Fixture {
 protected:
  std::string src_path_ = "bench_src.tmp";
  std::string enc_path_ = "bench_enc.tmp";
  std::string dec_path_ = "bench_dec.tmp";
  const char* pw_ = "password";
  size_t psize_ = strlen(pw_);

  void Create(size_t size) {
    FILE* file = nullptr;

    OpenFile(&file, src_path_, "wb");

    if (file) {
      std::vector<uint8_t> data(size, uint8_t{ 'a' });
      fwrite(data.data(), 1, size, file);
      fclose(file);
    }
  }

  void Clean() {
    RemoveFile(src_path_);
    RemoveFile(enc_path_);
    RemoveFile(dec_path_);
  }
};

/**
 * @brief   Encryption benchmark
 */
BENCHMARK_DEFINE_F(Benchmark, Encrypt)(benchmark::State& state) {
  const size_t size = static_cast<size_t>(state.range(0));

  Create(size);

  /* Derive the key once so the benchmark measures AES throughput, not Argon2 */

  std::array<uint8_t, kSaltSize> salt{};
  auto key = DeriveKey(std::span<const char>(pw_, psize_), salt);

  if (!key) {
    state.SkipWithError("Key derivation failed");
    return;
  }

  for (auto _ : state) {
    (void)_;

    AesGcm aes;
    FILE *src = nullptr, *dst = nullptr;

    OpenFile(&src, src_path_, "rb");
    OpenFile(&dst, enc_path_, "wb+");

    aes.Encrypt(src, dst, *key, salt);

    if (src) {
      fclose(src);
    }

    if (dst) {
      fclose(dst);
    }
  }

  state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(size));
  state.SetLabel(std::to_string(size / (size_t{ 1024 } * 1024)) + " MB");

  Clean();
}

/**
 * @brief   Decryption benchmark
 */
BENCHMARK_DEFINE_F(Benchmark, Decrypt)(benchmark::State& state) {
  const size_t size = static_cast<size_t>(state.range(0));
  Create(size);

  /* Derive the key once so the benchmark measures AES throughput, not Argon2 */

  std::array<uint8_t, kSaltSize> salt{};
  auto key = DeriveKey(std::span<const char>(pw_, psize_), salt);

  if (!key) {
    state.SkipWithError("Key derivation failed");
    return;
  }

  /* Encrypt */
  {
    AesGcm aes;
    FILE *src = nullptr, *dst = nullptr;

    OpenFile(&src, src_path_, "rb");
    OpenFile(&dst, enc_path_, "wb+");

    aes.Encrypt(src, dst, *key, salt);

    if (src) {
      fclose(src);
    }

    if (dst) {
      fclose(dst);
    }
  }

  /* Decrypt and test performance */

  for (auto _ : state) {
    (void)_;

    AesGcm aes;
    FILE *src = nullptr, *dst = nullptr;

    OpenFile(&src, enc_path_, "rb");
    OpenFile(&dst, dec_path_, "wb+");

    aes.Decrypt(src, dst, *key);

    if (src) {
      fclose(src);
    }

    if (dst) {
      fclose(dst);
    }
  }

  state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(size));

  Clean();
}

/**
 * @brief   Argon2id benchmark
 */
static void BenchArgon2id(benchmark::State& state) {
  std::array<uint8_t, kSaltSize> salt{};

  const char* pw = "password";
  size_t psize = strlen(pw);

  for (size_t i = 0; i < kSaltSize; i++) {
    salt[i] = static_cast<uint8_t>(i);
  }

  for (auto _ : state) {
    (void)_;

    /* Measure the production key-derivation path */

    auto key = DeriveKey(std::span<const char>(pw, psize), salt);
    benchmark::DoNotOptimize(key);
  }
}

BENCHMARK_REGISTER_F(Benchmark, Encrypt)
    ->Arg(kFileSize)  // 4 GiB
    ->Unit(benchmark::kMillisecond);

BENCHMARK_REGISTER_F(Benchmark, Decrypt)
    ->Arg(kFileSize)  // 4 GiB
    ->Unit(benchmark::kMillisecond);

BENCHMARK(BenchArgon2id)->Unit(benchmark::kMillisecond)->Iterations(10);

BENCHMARK_MAIN();