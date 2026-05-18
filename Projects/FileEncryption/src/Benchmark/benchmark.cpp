/**
 * @file    Benchmark.cpp
 * @brief   AES-GCM and Argon2id peformance test
 * @author  Astatine387
 */

#include <benchmark/benchmark.h>

#include <cstring>
#include <string>

#include "Core/aes_gcm.h"
#include "Utils/platform.h"

#define FILE_SIZE 4LL * 1024 * 1024 * 1024

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
      std::vector<uint8_t> data(size, 'a');
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
  size_t size = state.range(0);

  Create(size);

  for ([[maybe_unused]] auto _ :
       state) {  // NOLINT(clang-analyzer-deadcode.DeadStores)
    AesGcm aes;
    FILE *src = nullptr, *dst = nullptr;

    OpenFile(&src, src_path_, "rb");
    OpenFile(&dst, enc_path_, "wb+");

    aes.Encrypt(src, dst, pw_, psize_);

    if (src) {
      fclose(src);
    }

    if (dst) {
      fclose(dst);
    }
  }

  state.SetBytesProcessed(int64_t(state.iterations()) * size);
  state.SetLabel(std::to_string(size / (1024 * 1024)) + " MB");

  Clean();
}

/**
 * @brief   Decryption benchmark
 */
BENCHMARK_DEFINE_F(Benchmark, Decrypt)(benchmark::State& state) {
  size_t size = state.range(0);
  Create(size);

  /* Encrypt */

  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, pw_, psize_);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Decrypt and test performance */

  for (auto _ : state) {
    AesGcm aes;
    FILE *src = nullptr, *dst = nullptr;

    OpenFile(&src, enc_path_, "rb");
    OpenFile(&dst, dec_path_, "wb+");

    aes.Decrypt(src, dst, pw_, psize_);

    if (src) {
      fclose(src);
    }

    if (dst) {
      fclose(dst);
    }
  }

  state.SetBytesProcessed(int64_t(state.iterations()) * size);

  Clean();
}

/**
 * @brief   Argon2id benchmark
 */
static void BenchArgon2id(benchmark::State& state) {
  uint8_t salt[kSaltSize], key[kKeySize];
  const char* pw = "password";
  int psize = strlen(pw);

  for (int i = 0; i < kSaltSize; i++) {
    salt[i] = i;
  }

  for (auto _ : state) {
    Argon2id(salt, pw, psize, key);
  }
}

BENCHMARK_REGISTER_F(Benchmark, Encrypt)
    ->Arg(FILE_SIZE)  // 4 GiB
    ->Unit(benchmark::kMillisecond);

BENCHMARK_REGISTER_F(Benchmark, Decrypt)
    ->Arg(FILE_SIZE)  // 4 GiB
    ->Unit(benchmark::kMillisecond);

BENCHMARK(BenchArgon2id)->Unit(benchmark::kMillisecond)->Iterations(10);

BENCHMARK_MAIN();