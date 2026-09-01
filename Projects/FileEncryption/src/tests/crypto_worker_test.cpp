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
   * @brief   Build a locked Password from a C-style string
   * @param   str   Source password
   * @return  Password holding a copy of str
   */
  static Password MakePw(const char* str) {
    Password pw;

    EXPECT_EQ(pw.SetData(str, strlen(str)), Result::kSuccess);

    return pw;
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
    StoreLE32(buff.data() + kMagicSize + 1 + 2 * sizeof(uint32_t), params.parallelism);

    Create(path, buff);
  }

  /**
   * @brief   Write an encrypted file whose header records the given parameters
   * @param   params  Argon2id parameters to derive with and record
   * @param   data    Plaintext to encrypt
   */
  void MakeFileWith(const KdfParams& params, const std::vector<uint8_t>& data) {
    FILE *src = nullptr, *dst = nullptr;
    std::array<uint8_t, kSaltSize> salt{};

    salt.fill(0x33);

    Create(src_path_, data);

    auto derived = DeriveKey(std::span<const char>("password", 8), salt, params);

    ASSERT_TRUE(derived.has_value());

    SecureKey key = std::move(derived.value());  // NOLINT(bugprone-unchecked-optional-access)
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
  const char* data = "Hello, world!";
  std::vector<uint8_t> orig = ToBytes(data), copy;
  std::string enc_msg, dec_msg;

  Create(src_path_, orig);

  /* Encrypt */

  CryptoWorker enc(src_path_, enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  enc.SetFinishedCallback([&](const std::string& msg) { enc_msg = msg; });

  enc.Work();

  EXPECT_NE(enc_msg.find("complete"), std::string::npos);
  EXPECT_TRUE(FileExists(enc_path_));

  /* Decrypt */

  CryptoWorker dec(enc_path_, dec_path_, MakePw("password"), CryptoMode::kDecrypt);

  dec.SetFinishedCallback([&](const std::string& msg) { dec_msg = msg; });

  dec.Work();

  EXPECT_NE(dec_msg.find("complete"), std::string::npos);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/* ==================================================
 * Callback Tests
 * ================================================== */

/**
 * @brief   Verify progress callback is invoked with an encrypting status
 */
TEST_F(CryptoWorkerTest, ProgressCallbackReportsStatus) {
  std::vector<uint8_t> orig(kChunkSize * 10, 'a');
  int cnt = 0;
  std::string status;

  Create(src_path_, orig);

  CryptoWorker worker(src_path_, enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  worker.SetProgressCallback([&](int, const std::string& msg) {
    cnt++;

    status = msg;
  });

  worker.Work();

  EXPECT_GT(cnt, 0);
  EXPECT_NE(status.find("Encrypting"), std::string::npos);
}

/**
 * @brief   Verify progress callback is invoked with a decrypting status
 */
TEST_F(CryptoWorkerTest, ProgressCallbackReportsDecrypting) {
  std::vector<uint8_t> orig(kChunkSize * 10, 'a');
  std::string status;

  Create(src_path_, orig);

  /* Encrypt first to produce a valid ciphertext */

  CryptoWorker enc(src_path_, enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  enc.Work();

  /* Decrypt with a progress callback */

  CryptoWorker dec(enc_path_, dec_path_, MakePw("password"), CryptoMode::kDecrypt);

  dec.SetProgressCallback([&](int, const std::string& msg) { status = msg; });

  dec.Work();

  EXPECT_NE(status.find("Decrypting"), std::string::npos);  // line 69
}

/**
 * @brief   Verify a cancelled decryption reports cancellation and removes output
 */
TEST_F(CryptoWorkerTest, CancelDecryptionRemovesOutput) {
  std::vector<uint8_t> orig(kChunkSize * 10, 'a');
  std::string msg;

  Create(src_path_, orig);

  /* Encrypt first to produce a valid ciphertext */

  CryptoWorker enc(src_path_, enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  enc.Work();

  /* Decrypt, but cancel up front */

  CryptoWorker dec(enc_path_, dec_path_, MakePw("password"), CryptoMode::kDecrypt);

  dec.SetFinishedCallback([&](const std::string& m) { msg = m; });

  dec.RequestCancel();

  dec.Work();

  EXPECT_NE(msg.find("canceled"), std::string::npos);  // lines 99-100
  EXPECT_FALSE(FileExists(dec_path_));
}

/* ==================================================
 * Cancellation Tests
 * ================================================== */

/**
 * @brief   Verify a cancelled job reports cancellation and removes its output
 */
TEST_F(CryptoWorkerTest, CancelRemovesOutput) {
  std::vector<uint8_t> orig(kChunkSize * 10, 'a');
  std::string msg;

  Create(src_path_, orig);

  CryptoWorker worker(src_path_, enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  worker.SetFinishedCallback([&](const std::string& m) { msg = m; });

  /* Request cancellation up front so the first progress check aborts */

  worker.RequestCancel();

  worker.Work();

  EXPECT_NE(msg.find("canceled"), std::string::npos);
  EXPECT_FALSE(FileExists(enc_path_));
}

/* ==================================================
 * Failure Tests
 * ================================================== */

/**
 * @brief   Verify a wrong password fails decryption and removes its output
 */
TEST_F(CryptoWorkerTest, WrongPasswordRemovesOutput) {
  const char* data = "Hello, world!";
  std::vector<uint8_t> orig = ToBytes(data);
  std::string enc_msg, dec_msg;

  Create(src_path_, orig);

  /* Encrypt with the correct password */

  CryptoWorker enc(src_path_, enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  enc.SetFinishedCallback([&](const std::string& msg) { enc_msg = msg; });

  enc.Work();

  EXPECT_NE(enc_msg.find("complete"), std::string::npos);

  /* Decrypt with a wrong password */

  CryptoWorker dec(enc_path_, dec_path_, MakePw("asdf1234"), CryptoMode::kDecrypt);

  dec.SetFinishedCallback([&](const std::string& msg) { dec_msg = msg; });

  dec.Work();

  EXPECT_NE(dec_msg.find("failed"), std::string::npos);
  EXPECT_FALSE(FileExists(dec_path_));
}

/**
 * @brief   Verify a source too short to hold a header is rejected before key derivation
 */
TEST_F(CryptoWorkerTest, TooShortSourceIsRejected) {
  std::vector<uint8_t> buff(kHeaderSize - 1, 'a');
  std::string msg;

  Create(src_path_, buff);

  CryptoWorker dec(src_path_, dec_path_, MakePw("password"), CryptoMode::kDecrypt);

  dec.SetFinishedCallback([&](const std::string& m) { msg = m; });

  dec.Work();

  EXPECT_NE(msg.find("Cannot read the file header"), std::string::npos);
  EXPECT_FALSE(FileExists(dec_path_));
}

/**
 * @brief   Verify a file written by another tool is rejected on the magic number
 */
TEST_F(CryptoWorkerTest, ForeignSourceIsRejected) {
  std::vector<uint8_t> buff(kMinSize, 'a');
  std::string msg;

  Create(src_path_, buff);

  CryptoWorker dec(src_path_, dec_path_, MakePw("password"), CryptoMode::kDecrypt);

  dec.SetFinishedCallback([&](const std::string& m) { msg = m; });

  dec.Work();

  EXPECT_NE(msg.find("Not a FileEncryption file"), std::string::npos);
  EXPECT_FALSE(FileExists(dec_path_));
}

/**
 * @brief   Verify parameters outside the accepted range are rejected before Argon2id runs
 */
TEST_F(CryptoWorkerTest, OutOfRangeHeaderParamsAreRejected) {
  const char* data = "Hello, world!";
  std::string enc_msg;

  Create(src_path_, ToBytes(data));

  /* One real encryption supplies a valid file for every case below */

  CryptoWorker enc(src_path_, enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  enc.SetFinishedCallback([&](const std::string& m) { enc_msg = m; });

  enc.Work();

  ASSERT_NE(enc_msg.find("complete"), std::string::npos);

  const std::array<KdfParams, 6> cases{
    KdfParams{ .time_cost = kMinTimeCost - 1, .mem_cost = kMemCost, .parallelism = kParallelism },
    KdfParams{ .time_cost = kMaxTimeCost + 1, .mem_cost = kMemCost, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMinMemCost - 1, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMaxMemCost + 1, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMemCost, .parallelism = kMinParallelism - 1 },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMemCost, .parallelism = kMaxParallelism + 1 },
  };

  for (const KdfParams& params : cases) {
    SCOPED_TRACE(testing::Message() << "t=" << params.time_cost << " m=" << params.mem_cost
                                    << " p=" << params.parallelism);

    std::string dec_msg;

    PatchHeaderParams(enc_path_, params);

    CryptoWorker dec(enc_path_, dec_path_, MakePw("password"), CryptoMode::kDecrypt);

    dec.SetFinishedCallback([&](const std::string& m) { dec_msg = m; });

    dec.Work();

    EXPECT_NE(dec_msg.find("Unsupported key derivation parameters"), std::string::npos);
    EXPECT_FALSE(FileExists(dec_path_));
  }
}

/**
 * @brief   Verify a file is decrypted with the parameters its header records
 */
TEST_F(CryptoWorkerTest, DecryptUsesHeaderKdfParams) {
  const char* data = "Hello, world!";
  const KdfParams params{ .time_cost = kMinTimeCost, .mem_cost = kMinMemCost, .parallelism = kMinParallelism };
  std::vector<uint8_t> orig = ToBytes(data), copy;
  std::string msg;

  /* Build a file under the cheapest accepted parameters rather than the build defaults */

  MakeFileWith(params, orig);

  CryptoWorker dec(enc_path_, dec_path_, MakePw("password"), CryptoMode::kDecrypt);

  dec.SetFinishedCallback([&](const std::string& m) { msg = m; });

  dec.Work();

  EXPECT_NE(msg.find("complete"), std::string::npos);

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify a missing source file reports an open failure
 */
TEST_F(CryptoWorkerTest, MissingSourceReportsError) {
  std::string msg;

  CryptoWorker worker("fake.tmp", enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  worker.SetFinishedCallback([&](const std::string& m) { msg = m; });

  worker.Work();

  EXPECT_NE(msg.find("Open failed"), std::string::npos);
  EXPECT_FALSE(FileExists(enc_path_));
}

/**
 * @brief   Verify an uncreatable destination reports an open failure
 */
TEST_F(CryptoWorkerTest, UncreatableDestinationReportsError) {
  const char* data = "Hello, world!";
  std::vector<uint8_t> orig = ToBytes(data);
  std::string msg;

  Create(src_path_, orig);

  CryptoWorker worker(src_path_, "no_such_dir/out.tmp", MakePw("password"), CryptoMode::kEncrypt);

  worker.SetFinishedCallback([&](const std::string& m) { msg = m; });

  worker.Work();

  EXPECT_NE(msg.find("Open failed"), std::string::npos);
}

/* ==================================================
 * Concurrency Tests
 * ================================================== */

/**
 * @brief   Verify cancelling from another thread while the worker runs is race-free
 */
TEST_F(CryptoWorkerTest, ConcurrentCancelDuringWork) {
  /* Large enough that encryption spans many progress checkpoints */

  std::vector<uint8_t> orig(kChunkSize * 64, 'a');
  std::atomic<bool> in_progress{ false };
  std::string msg;

  Create(src_path_, orig);

  CryptoWorker worker(src_path_, enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  /* Signal once the worker is actively processing */

  worker.SetProgressCallback([&](int, const std::string&) { in_progress.store(true, std::memory_order_release); });

  worker.SetFinishedCallback([&](const std::string& m) { msg = m; });

  std::thread runner([&] { worker.Work(); });

  /* Wait for the processing loop, then cancel concurrently with it */

  while (!in_progress.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }

  worker.RequestCancel();

  runner.join();

  /* The race is benign: completion and cancellation are both valid outcomes */

  EXPECT_TRUE(msg.find("complete") != std::string::npos || msg.find("canceled") != std::string::npos);

  if (msg.find("canceled") != std::string::npos) {
    EXPECT_FALSE(FileExists(enc_path_));
  }
}
