/**
 * @file    crypto_worker_test.cpp
 * @brief   Unit tests for CryptoWorker class
 * @author  Astatine387
 */

#include "core/crypto_worker.h"

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "common/constants.h"
#include "core/aes_gcm.h"
#include "core/file_header.h"
#include "core/secure_key.h"
#include "utils/byte_order.h"
#include "utils/password.h"
#include "utils/platform.h"

/**
 * @class   CryptoWorkerTest
 * @brief   Test fixture for CryptoWorker encryption/decryption tests
 */
class CryptoWorkerTest : public ::testing::Test {
 protected:
  std::string src_path_ = "worker_src.tmp";
  std::string enc_path_ = "worker_enc.tmp";
  std::string dec_path_ = "worker_dec.tmp";

  /**
   * @brief   Clean up temporary files after each test
   */
  void TearDown() override {
    RemoveFile(src_path_);
    RemoveFile(enc_path_);
    RemoveFile(dec_path_);
  }

  /**
   * @brief   Create a password from a C string
   * @param   str   Source password
   * @return  Password holding a copy of the C string
   */
  static Password MakePw(const char* str) {
    Password pw;

    EXPECT_EQ(pw.SetData(str, strlen(str)), Result::kSuccess);

    return pw;
  }

  /**
   * @brief   Get the cheapest Argon2id parameters this build accepts
   * @return  The cheapest Argon2id parameters
   */
  static KdfParams MinParams() {
    return KdfParams{ .time_cost = kMinTimeCost, .mem_cost = kMinMemCost, .parallelism = kMinParallelism };
  }

  /**
   * @brief   Configuration applied to a worker before it runs
   */
  using WorkerSetup = std::function<void(CryptoWorker&)>;

  /**
   * @brief   Run one worker job to complete and hand back what it reported
   * @param   src     Source file path
   * @param   dst     Destination file path
   * @param   pw      Password
   * @param   mode    Encryption or decryption
   * @param   setup   Applied to the worker before Work, for callbacks or an up-front cancel
   * @return  Message passed to the finished callback
   */
  std::string RunWorker(const std::string& src, const std::string& dst, const char* pw, CryptoMode mode,
                        const WorkerSetup& setup = nullptr) {
    std::string msg;

    CryptoWorker worker(src, dst, MakePw(pw), mode);

    worker.SetFinishedCallback([&](const std::string& m) { msg = m; });

    if (setup) {
      setup(worker);
    }

    worker.Work();

    return msg;
  }

  /**
   * @brief   Convert a C string to a byte vector
   */
  static std::vector<uint8_t> ToBytes(const char* str) {
    const auto* bytes = reinterpret_cast<const uint8_t*>(str);

    return { bytes, bytes + strlen(str) };
  }

  /**
   * @brief   Create test file
   * @param   path    File path
   * @param   data    File content
   */
  void Create(const std::string& path, const std::vector<uint8_t>& data) {
    FILE* file = nullptr;

    OpenFile(&file, path, "wb");

    if (file) {
      if (!data.empty()) {
        fwrite(data.data(), sizeof(uint8_t), data.size(), file);
      }

      fclose(file);
    }
  }

  /**
   * @brief   Read file into buffer
   * @param   path    Source file path
   * @param   vec     Destination buffer
   */
  void Read(const std::string& path, std::vector<uint8_t>& vec) {
    FILE* file = nullptr;

    OpenFile(&file, path, "rb");

    if (!file) {
      return;
    }

    const int64_t fsize = GetFileSize(file);

    if (fsize < 0) {
      fclose(file);
      return;
    }

    vec.resize(static_cast<size_t>(fsize));

    size_t res = fread(vec.data(), sizeof(uint8_t), vec.size(), file);

    fclose(file);

    EXPECT_EQ(res, vec.size());
  }

  /**
   * @brief   Replace the Argon2id parameters in a file header, leaving the body untouched
   * @param   path    Encrypted file path
   * @param   params  Parameters to store
   */
  void PatchHeaderParams(const std::string& path, const KdfParams& params) {
    std::vector<uint8_t> buff;

    Read(path, buff);

    ASSERT_GE(buff.size(), kHeaderSize);

    StoreLE32(buff.data() + kMagicSize + 1, params.time_cost);
    StoreLE32(buff.data() + kMagicSize + 1 + sizeof(uint32_t), params.mem_cost);
    StoreLE32(buff.data() + kMagicSize + 1 + sizeof(uint32_t) * 2, params.parallelism);

    Create(path, buff);
  }

  /**
   * @brief   Write an encrypted file whose header records the given parameters
   * @param   params  Argon2id parameters to derive with and record
   * @param   data    Plaintext to encrypt
   */
  void MakeFileWith(const KdfParams& params, const std::vector<uint8_t>& data) {
    std::array<uint8_t, kSaltSize> salt{};
    FILE *src = nullptr, *dst = nullptr;

    salt.fill(0x33);

    Create(src_path_, data);

    auto tmp = DeriveKey(std::span<const char>("password", 8), salt, params);

    ASSERT_TRUE(tmp.has_value());

    SecureKey key = std::move(tmp.value());  // NOLINT(bugprone-unchecked-optional-access)
    AesGcm aes;

    OpenFile(&src, src_path_, "rb");
    OpenFile(&dst, enc_path_, "wb+");

    if (src && dst) {
      EXPECT_EQ(aes.Encrypt(src, dst, key, salt, params), Result::kSuccess);
    }

    if (src) {
      fclose(src);
    }

    if (dst) {
      fclose(dst);
    }
  }
};

/* ==================================================
 * Encryption/Decryption Tests
 * ================================================== */

/**
 * @brief   Verify a worker round-trip reports completion and preserves data
 */
TEST_F(CryptoWorkerTest, EncryptDecryptRoundTrip) {
  const std::vector<uint8_t> orig = ToBytes("Hello, world!");
  std::vector<uint8_t> copy;

  Create(src_path_, orig);

  EXPECT_NE(RunWorker(src_path_, enc_path_, "password", CryptoMode::kEncrypt).find("complete"), std::string::npos);
  EXPECT_TRUE(FileExists(enc_path_));
  EXPECT_NE(RunWorker(enc_path_, dec_path_, "password", CryptoMode::kDecrypt).find("complete"), std::string::npos);

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/* ==================================================
 * Callback Tests
 * ================================================== */

/**
 * @brief   Verify progress callback is invoked with an encrypting status carrying the percentage
 */
TEST_F(CryptoWorkerTest, ProgressCallbackReportsEncrypting) {
  std::string status;
  int last = -1;

  Create(src_path_, std::vector<uint8_t>(kChunkSize * 10, 'a'));

  RunWorker(src_path_, enc_path_, "password", CryptoMode::kEncrypt, [&](CryptoWorker& worker) {
    worker.SetProgressCallback([&](int perc, const std::string& msg) {
      last = perc;
      status = msg;
    });
  });

  EXPECT_GE(last, 0);
  EXPECT_NE(status.find("Encrypting"), std::string::npos);
  EXPECT_NE(status.find(std::to_string(last) + "%"), std::string::npos);
}

/**
 * @brief   Verify progress callback is invoked with a decrypting status carrying the percentage
 */
TEST_F(CryptoWorkerTest, ProgressCallbackReportsDecrypting) {
  std::string status;
  int last = -1;

  MakeFileWith(MinParams(), std::vector<uint8_t>(kChunkSize * 10, 'a'));

  RunWorker(enc_path_, dec_path_, "password", CryptoMode::kDecrypt, [&](CryptoWorker& worker) {
    worker.SetProgressCallback([&](int perc, const std::string& msg) {
      last = perc;
      status = msg;
    });
  });

  EXPECT_GE(last, 0);
  EXPECT_NE(status.find("Decrypting"), std::string::npos);
  EXPECT_NE(status.find(std::to_string(last) + "%"), std::string::npos);
}

/* ==================================================
 * Cancellation Tests
 * ================================================== */

/**
 * @brief   Verify a cancelled encryption reports cancellation and removes output
 */
TEST_F(CryptoWorkerTest, CancelEncryptionRemovesOutput) {
  Create(src_path_, std::vector<uint8_t>(kChunkSize * 10, 'a'));

  const std::string msg = RunWorker(src_path_, dec_path_, "password", CryptoMode::kEncrypt,
                                    [](CryptoWorker& worker) { worker.RequestCancel(); });

  EXPECT_NE(msg.find("cancelled"), std::string::npos);
  EXPECT_FALSE(FileExists(dec_path_));
}

/**
 * @brief   Verify a cancelled decryption reports cancellation and removes output
 */
TEST_F(CryptoWorkerTest, CancelDecryptionRemovesOutput) {
  MakeFileWith(MinParams(), std::vector<uint8_t>(kChunkSize * 10, 'a'));

  const std::string msg = RunWorker(enc_path_, dec_path_, "password", CryptoMode::kDecrypt,
                                    [](CryptoWorker& worker) { worker.RequestCancel(); });

  EXPECT_NE(msg.find("cancelled"), std::string::npos);
  EXPECT_FALSE(FileExists(dec_path_));
}

/* ==================================================
 * Failure Tests
 * ================================================== */

/**
 * @brief   Verify a wrong password fails decryption and removes its output
 */
TEST_F(CryptoWorkerTest, WrongPasswordRemovesOutput) {
  MakeFileWith(MinParams(), ToBytes("Hello, world!"));

  const std::string msg = RunWorker(enc_path_, dec_path_, "asdf1234", CryptoMode::kDecrypt);

  EXPECT_NE(msg.find("failed"), std::string::npos);
  EXPECT_FALSE(FileExists(dec_path_));
}

/**
 * @brief   Verify a corrupted chunk mid-file leaves no partial plaintext at the destination
 */
TEST_F(CryptoWorkerTest, CorruptChunkLeavesNoDestinationFile) {
  constexpr size_t kChunks = 5;
  constexpr size_t kBad = 3;
  std::vector<uint8_t> cipher;

  MakeFileWith(MinParams(), std::vector<uint8_t>(kChunks * kChunkSize, 'a'));

  Read(enc_path_, cipher);

  ASSERT_EQ(cipher.size(), kHeaderSize + kChunks * (kChunkSize + kTagSize));

  /* Damage a byte inside the fourth chunk, leaving the three before it valid */

  cipher[kHeaderSize + kBad * (kChunkSize + kTagSize) + 10] ^= 0x01;

  Create(enc_path_, cipher);

  const std::string msg = RunWorker(enc_path_, dec_path_, "password", CryptoMode::kDecrypt);

  EXPECT_NE(msg.find("failed"), std::string::npos);
  EXPECT_FALSE(FileExists(dec_path_));
}

/**
 * @brief   Verify a source too short to hold a header is rejected before key derivation
 */
TEST_F(CryptoWorkerTest, TooShortSourceIsRejected) {
  Create(src_path_, std::vector<uint8_t>(kHeaderSize - 1, 'a'));

  const std::string msg = RunWorker(src_path_, dec_path_, "password", CryptoMode::kDecrypt);

  EXPECT_NE(msg.find("Cannot read the file header"), std::string::npos);
  EXPECT_FALSE(FileExists(dec_path_));
}

/**
 * @brief   Verify a file written by another tool is rejected on the magic number
 */
TEST_F(CryptoWorkerTest, ForeignSourceIsRejected) {
  Create(src_path_, std::vector<uint8_t>(kMinSize, 'a'));

  const std::string msg = RunWorker(src_path_, dec_path_, "password", CryptoMode::kDecrypt);

  EXPECT_NE(msg.find("Not a FileEncryption file"), std::string::npos);
  EXPECT_FALSE(FileExists(dec_path_));
}

/**
 * @brief   Verify parameters outside the accepted range are rejected before Argon2id runs
 */
TEST_F(CryptoWorkerTest, OutOfRangeHeaderParamsAreRejected) {
  const std::array<KdfParams, 6> cases{
    KdfParams{ .time_cost = kMinTimeCost - 1, .mem_cost = kMemCost, .parallelism = kParallelism },
    KdfParams{ .time_cost = kMaxTimeCost + 1, .mem_cost = kMemCost, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMinMemCost - 1, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMaxMemCost + 1, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMemCost, .parallelism = kMinParallelism - 1 },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMemCost, .parallelism = kMaxParallelism + 1 },
  };

  MakeFileWith(MinParams(), ToBytes("Hello, world!"));

  for (const KdfParams& params : cases) {
    SCOPED_TRACE(testing::Message() << "t=" << params.time_cost << " m=" << params.mem_cost
                                    << " p=" << params.parallelism);

    PatchHeaderParams(enc_path_, params);

    const std::string msg = RunWorker(enc_path_, dec_path_, "password", CryptoMode::kDecrypt);

    EXPECT_NE(msg.find("Unsupported key derivation parameters"), std::string::npos);
    EXPECT_FALSE(FileExists(dec_path_));
  }
}

/**
 * @brief   Verify a file is decrypted with the parameters its header records
 */
TEST_F(CryptoWorkerTest, DecryptUsesHeaderKdfParams) {
  const std::vector<uint8_t> orig = ToBytes("Hello, world!");
  std::vector<uint8_t> copy;

  MakeFileWith(MinParams(), orig);

  const std::string msg = RunWorker(enc_path_, dec_path_, "password", CryptoMode::kDecrypt);

  EXPECT_NE(msg.find("complete"), std::string::npos);

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify a missing source file reports an open failure
 */
TEST_F(CryptoWorkerTest, MissingSourceReportsError) {
  const std::string msg = RunWorker("fake.tmp", enc_path_, "password", CryptoMode::kEncrypt);

  EXPECT_NE(msg.find("Open failed"), std::string::npos);
  EXPECT_FALSE(FileExists(enc_path_));
}

/**
 * @brief   Verify an uncreatable destination reports an open failure
 */
TEST_F(CryptoWorkerTest, UncreatableDestinationReportsError) {
  Create(src_path_, ToBytes("Hello, world!"));

  const std::string msg = RunWorker(src_path_, "fake/out.tmp", "password", CryptoMode::kEncrypt);

  EXPECT_NE(msg.find("Open failed"), std::string::npos);
}

/* ==================================================
 * Concurrency Tests
 * ================================================== */

/**
 * @brief   Verify cancelling from another thread while the worker runs is race-free
 */
TEST_F(CryptoWorkerTest, ConcurrentCancelDuringWork) {
  std::atomic<bool> in_progress{ false };
  std::string msg;

  Create(src_path_, std::vector<uint8_t>(kChunkSize * 64, 'a'));

  CryptoWorker worker(src_path_, enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  worker.SetProgressCallback([&](int, const std::string&) { in_progress.store(true, std::memory_order_release); });

  worker.SetFinishedCallback([&](const std::string& m) { msg = m; });

  std::thread runner([&] { worker.Work(); });

  while (!in_progress.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }

  worker.RequestCancel();

  runner.join();

  EXPECT_TRUE(msg.find("complete") != std::string::npos || msg.find("cancelled") != std::string::npos);

  if (msg.find("cancelled") != std::string::npos) {
    EXPECT_FALSE(FileExists(enc_path_));
  }
}
