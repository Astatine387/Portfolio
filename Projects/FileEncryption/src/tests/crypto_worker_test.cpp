/**
 * @file    crypto_worker_test.cpp
 * @brief   Unit tests for CryptoWorker class
 * @author  Astatine387
 */

#include "core/crypto_worker.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "common/constants.h"
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

    int64_t size = GetFileSize(file);

    vec.resize(static_cast<size_t>(size));

    fread(vec.data(), sizeof(uint8_t), vec.size(), file);

    fclose(file);
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
  int dsize = static_cast<int>(strlen(data));
  std::vector<uint8_t> orig(data, data + dsize), copy;
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
  std::vector<uint8_t> orig(static_cast<size_t>(kBlockSize) * kBuffSize * 10, 'a');
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
  std::vector<uint8_t> orig(static_cast<size_t>(kBlockSize) * kBuffSize * 10, 'a');
  std::string status;

  Create(src_path_, orig);

  /* Encrypt first to produce a valid ciphertext */

  CryptoWorker enc(src_path_, enc_path_, MakePw("password"), CryptoMode::kEncrypt);

  enc.Work();

  /* Decrypt with a progress callback */

  CryptoWorker dec(enc_path_, dec_path_, MakePw("password"), CryptoMode::kDecrypt);

  dec.SetProgressCallback([&](int perc, const std::string& msg) { status = msg; });

  dec.Work();

  EXPECT_NE(status.find("Decrypting"), std::string::npos);  // line 69
}

/**
 * @brief   Verify a cancelled decryption reports cancellation and removes output
 */
TEST_F(CryptoWorkerTest, CancelDecryptionRemovesOutput) {
  std::vector<uint8_t> orig(static_cast<size_t>(kBlockSize) * kBuffSize * 10, 'a');
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
  std::vector<uint8_t> orig(static_cast<size_t>(kBlockSize) * kBuffSize * 10, 'a');
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
  int dsize = static_cast<int>(strlen(data));
  std::vector<uint8_t> orig(data, data + dsize);
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
 * @brief   Verify a source too short to hold a salt fails key derivation
 */
TEST_F(CryptoWorkerTest, TooShortSourceFailsKeyDerivation) {
  std::vector<uint8_t> buff(kSaltSize - 1, 'a');
  std::string msg;

  Create(src_path_, buff);

  CryptoWorker dec(src_path_, dec_path_, MakePw("password"), CryptoMode::kDecrypt);

  dec.SetFinishedCallback([&](const std::string& m) { msg = m; });

  dec.Work();

  EXPECT_NE(msg.find("Key derivation failed"), std::string::npos);
  EXPECT_FALSE(FileExists(dec_path_));
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
  int dsize = static_cast<int>(strlen(data));
  std::vector<uint8_t> orig(data, data + dsize);
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

  std::vector<uint8_t> orig(static_cast<size_t>(kBlockSize) * kBuffSize * 64, 'a');
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