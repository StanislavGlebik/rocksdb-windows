//  Copyright (c) 2013, Facebook, Inc.  All rights reserved.
//  This source code is licensed under the BSD-style license found in the
//  LICENSE file in the root directory of this source tree. An additional grant
//  of patent rights can be found in the PATENTS file in the same directory.
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "port/port_win.h"

#include <algorithm>
#include <cstdlib>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include "util/logging.h"
#include <Windows.h>

#include <chrono>

int snprintf(char *str, size_t size, const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  int res = vsnprintf_s(str, size, _TRUNCATE, format, ap);
  if (res == -1)
  {
    // Output was truncated
    res = size - 1;
    str[size - 1] = 0;
  }
  va_end(ap);
  return res;
}

int gettimeofday(struct timeval *tv, struct timezone *tz) {
  if (tv != nullptr) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli = { ft.dwLowDateTime, ft.dwHighDateTime };
    uli.QuadPart -= 116444736000000000ull;
    tv->tv_sec = uli.QuadPart / 10000000;
    tv->tv_usec = (uli.QuadPart % 10000000 + 5) / 10;
  }
  return 0;
}

struct tm *localtime_r(const time_t *timep, struct tm *result) {
  return localtime_s(result, timep) == 0 ? result : nullptr;
}

int pthread_key_create(pthread_key_t *key, void(*destructor)(void*)) {
  // TODO: Register destructor to be called from DllMain
  *key = TlsAlloc();
  if (*key == TLS_OUT_OF_INDEXES)
  {
    return GetLastError();
  }
  return 0;
}

void *pthread_getspecific(pthread_key_t key) {
  return TlsGetValue(key);
}

int pthread_setspecific(pthread_key_t key, const void *value) {
  return !TlsSetValue(key, const_cast<void *>(value));
}

namespace rocksdb {
namespace port {

Mutex::Mutex(bool adaptive) {
  // ignore adaptive for non-linux platform
}

Mutex::~Mutex() {
}

void Mutex::Lock() {
  m_.lock();
#ifndef NDEBUG
  locked_ = true;
#endif
}

void Mutex::Unlock() {
#ifndef NDEBUG
  locked_ = false;
#endif
  m_.unlock();
}

void Mutex::AssertHeld() {
#ifndef NDEBUG
  assert(locked_);
#endif
}

CondVar::CondVar(Mutex* mu)
    : mu_(mu) {
}

CondVar::~CondVar() {
}

void CondVar::Wait() {
#ifndef NDEBUG
  mu_->locked_ = false;
#endif
  std::unique_lock<std::mutex> lock(mu_->m_, std::adopt_lock);
  cv_.wait(lock);
  lock.release();
#ifndef NDEBUG
  mu_->locked_ = true;
#endif
}

bool CondVar::TimedWait(uint64_t abs_time_us) {
#ifndef NDEBUG
  mu_->locked_ = false;
#endif
  std::unique_lock<std::mutex> lock(mu_->m_, std::adopt_lock);
  std::chrono::steady_clock::duration duration = std::chrono::microseconds(abs_time_us);
  std::chrono::steady_clock::time_point timepoint(duration);
  std::cv_status result = cv_.wait_until(lock, timepoint);
  lock.release();
#ifndef NDEBUG
  mu_->locked_ = true;
#endif
  return result == std::cv_status::timeout;
}

void CondVar::Signal() {
  cv_.notify_one();
}

void CondVar::SignalAll() {
  cv_.notify_all();
}

RWMutex::RWMutex() {
  InitializeSRWLock(&rw_);
}

RWMutex::~RWMutex() {
}

void RWMutex::ReadLock() {
  AcquireSRWLockShared(&rw_);
}

void RWMutex::WriteLock() {
  AcquireSRWLockExclusive(&rw_);
}

void RWMutex::ReadUnlock() { 
  ReleaseSRWLockShared(&rw_);
}

void RWMutex::WriteUnlock() {
  ReleaseSRWLockExclusive(&rw_);
}

BOOL CALLBACK RunInitializer(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *lpContext) {
  INIT_PROC initializer = static_cast<INIT_PROC>(Parameter);
  initializer();
  return TRUE;
}

void InitOnce(port::OnceType * once, void(*initializer)()) {
  InitOnceExecuteOnce(once, RunInitializer, initializer, NULL);
}


}  // namespace port
}  // namespace rocksdb
