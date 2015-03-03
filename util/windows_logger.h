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

namespace rocksdb {

const int kDebugLogChunkSize = 128 * 1024;

class WindowsLogger : public Logger {

 public:
  WindowsLogger(FILE* f, uint64_t (*gettid)(), Env* env,
              const InfoLogLevel log_level = InfoLogLevel::ERROR_LEVEL)
      : Logger(log_level)
  {}

  virtual ~WindowsLogger() {
    throw std::logic_error("Not implemented yet!");
  }

  virtual void Flush() {
    throw std::logic_error("Not implemented yet!");
  }

  size_t GetLogFileSize() const {
    throw std::logic_error("Not implemented yet!");
  }
};

}  // namespace rocksdb
