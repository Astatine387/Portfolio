/**
 * @file    Benchmark.cpp
 * @brief   AES-GCM and Argon2id peformance test
 * @author  Astatine387
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"
#include <QString>
#include <benchmark/benchmark.h>

#define FILE_SIZE 4LL * 1024 * 1024 * 1024

/**
 * @class   Benchmark
 * @brief   Fixture for AES-GCM and Argon2id performance test
 */
class Benchmark : public benchmark::Fixture {
protected:
    QString srcPath = "bench_src.tmp";
    QString encPath = "bench_enc.tmp";
    QString decPath = "bench_dec.tmp";
    const char *pw = "password";
    size_t psize = strlen(pw);

    void create(size_t size) {
        FILE *file = nullptr;

        OpenFile(&file, srcPath, "wb");

        if (file) {
            std::vector<uint8_t> data(size, 'a');
            fwrite(data.data(), 1, size, file);
            fclose(file);
        }
    }

    void clean() {
        RemoveFile(srcPath);
        RemoveFile(encPath);
        RemoveFile(decPath);
    }
};

/**
 * @brief   Encryption benchmark
 */
BENCHMARK_DEFINE_F(Benchmark, Encrypt)(benchmark::State &state) {
    size_t size = state.range(0);

    create(size);

    for (auto _ : state) {
        AES_GCM aes;
        FILE *src = nullptr, *dst = nullptr;

        OpenFile(&src, srcPath, "rb");
        OpenFile(&dst, encPath, "wb+");

        aes.encrypt(src, dst, pw, psize);

        if (src) fclose(src);
        if (dst) fclose(dst);
    }

    state.SetBytesProcessed(int64_t(state.iterations()) * size);
    state.SetLabel(std::to_string(size / (1024 * 1024)) + " MB");

    clean();
}

/**
 * @brief   Decryption benchmark
 */
BENCHMARK_DEFINE_F(Benchmark, Decrypt)(benchmark::State &state) {
    size_t size = state.range(0);
    create(size);


    /* Encrypt */

    AES_GCM aes;
    FILE *src = nullptr, *dst = nullptr;

    OpenFile(&src, srcPath, "rb");
    OpenFile(&dst, encPath, "wb+");

    aes.encrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);


    /* Decrypt and test performance */

    for (auto _ : state) {
        AES_GCM aes;
        FILE *src = nullptr, *dst = nullptr;

        OpenFile(&src, encPath, "rb");
        OpenFile(&dst, decPath, "wb+");

        aes.decrypt(src, dst, pw, psize);

        if (src) fclose(src);
        if (dst) fclose(dst);
    }

    state.SetBytesProcessed(int64_t(state.iterations()) * size);

    clean();
}

/**
 * @brief   Argon2id benchmark
 */
static void BM_Argon2id(benchmark::State &state) {
    uint8_t salt[kSaltSize], key[kKeySize];
    const char *pw = "password";
    int psize = strlen(pw);

    for (int i = 0; i < kSaltSize; i++) salt[i] = i;

    for (auto _ : state) Argon2id(salt, pw, psize, key);
}

BENCHMARK_REGISTER_F(Benchmark, Encrypt)
->Arg(FILE_SIZE) // 4 GiB
->Unit(benchmark::kMillisecond);

BENCHMARK_REGISTER_F(Benchmark, Decrypt)
->Arg(FILE_SIZE) // 4 GiB
->Unit(benchmark::kMillisecond);

BENCHMARK(BM_Argon2id)
->Unit(benchmark::kMillisecond)
->Iterations(10);

BENCHMARK_MAIN();