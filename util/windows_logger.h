//  Copyright (c) 2013, Facebook, Inc.  All rights reserved.
//  This source code is licensed under the BSD-style license found in the
//  LICENSE file in the root directory of this source tree. An additional grant
//  of patent rights can be found in the PATENTS file in the same directory.
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//
// Logger implementation that can be shared by all environments
// where enough posix functionality is available.

#pragma once

#include "rocksdb/env.h"
#include "Windows.h"

namespace rocksdb {

class WindowsLogger : public Logger {
 private:
  HANDLE file_;
  std::atomic_size_t log_size_;
  const static uint64_t flush_every_seconds_ = 5;
  std::atomic_uint_fast64_t last_flush_micros_;
  Env* env_;
  bool flush_pending_;

 public:
  WindowsLogger(HANDLE f, Env* env,
              const InfoLogLevel log_level = InfoLogLevel::ERROR_LEVEL)
      : file_(f),
      env_(env),
      Logger(log_level)
  {}

  virtual ~WindowsLogger() {
    CloseHandle(file_);
  }

  virtual void Flush() {
    if (flush_pending_) {
      flush_pending_ = false;
      FlushFileBuffers(file_);
    }
    last_flush_micros_ = env_->NowMicros();
  }

  using Logger::Logv;
  virtual void Logv(const char* format, va_list ap) {
    const uint64_t thread_id = GetCurrentThreadId();

    // We try twice: the first time with a fixed-size stack allocated buffer,
    // and the second time with a much larger dynamically allocated buffer.
    char buffer[500];
    for (int iter = 0; iter < 2; iter++) {
      char* base;
      int bufsize;
      if (iter == 0) {
        bufsize = sizeof(buffer);
        base = buffer;
      } else {
        bufsize = 30000;
        base = new char[bufsize];
      }
      char* p = base;
      char* limit = base + bufsize;

      struct timeval now_tv;
      gettimeofday(&now_tv, nullptr);
      const time_t seconds = now_tv.tv_sec;
      struct tm t;
      localtime_r(&seconds, &t);
      p += snprintf(p, limit - p,
                    "%04d/%02d/%02d-%02d:%02d:%02d.%06d %llx ",
                    t.tm_year + 1900,
                    t.tm_mon + 1,
                    t.tm_mday,
                    t.tm_hour,
                    t.tm_min,
                    t.tm_sec,
                    static_cast<int>(now_tv.tv_usec),
                    static_cast<long long unsigned int>(thread_id));

      // Print the message
      if (p < limit) {
        va_list backup_ap;
        va_copy(backup_ap, ap);
        auto n = vsnprintf_s(p, limit - p, _TRUNCATE, format, backup_ap);
        assert(errno != ERANGE);
        if (n < 0) {
          // Truncate happened
          n = limit - p - 1; // TODO(stash): check this!!!!!!!!!!
        }
        p += n;
        va_end(backup_ap);
      }

      // Truncate to available space if necessary
      if (p >= limit) {
        if (iter == 0) {
          continue;       // Try again with larger buffer
        } else {
          p = limit - 1;
        }
      }

      // Add newline if necessary
      if (p == base || p[-1] != '\n') {
        *p++ = '\n';
      }

      assert(p <= limit);
      const size_t write_size = p - base;

      DWORD numBytesWritten;
      WriteFile(file_, base, write_size, &numBytesWritten, NULL);
      flush_pending_ = true;
      assert(numBytesWritten == write_size);
      if (numBytesWritten > 0) {
        log_size_ += write_size;
      }
      uint64_t now_micros = static_cast<uint64_t>(now_tv.tv_sec) * 1000000 +
        now_tv.tv_usec;
      if (now_micros - last_flush_micros_ >= flush_every_seconds_ * 1000000) {
        Flush();
      }
      if (base != buffer) {
        delete[] base;
      }
      break;
    }
  }

  size_t GetLogFileSize() const {
    return log_size_;
  }
};

}  // namespace rocksdb
