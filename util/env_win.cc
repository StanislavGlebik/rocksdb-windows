//  Copyright (c) 2013, Facebook, Inc.  All rights reserved.
//  This source code is licensed under the BSD-style license found in the
//  LICENSE file in the root directory of this source tree. An additional grant
//  of patent rights can be found in the PATENTS file in the same directory.
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "rocksdb/env.h"
#include "rocksdb/slice.h"
#include "port/port.h"
#include "util/coding.h"
#include "util/logging.h"
#include "util/random.h"
#include <intsafe.h>
#include <set>
#include <signal.h>
#include <time.h>
#include <Windows.h>

#include <atomic>

#define WORKING
#ifdef WORKING

// This is only set from db_stress.cc and for testing only.
// If non-zero, kill at various points in source code with probability 1/this
int rocksdb_kill_odds = 0;

namespace rocksdb {

namespace {

class HandleGuard
{
public:
  explicit HandleGuard(HANDLE h) :
    h_(h)
  {
  }

  operator HANDLE()
  {
    h_;
  }

  ~HandleGuard()
  {
    ::CloseHandle(h_);
  }

private:
  HANDLE h_;
};

// list of pathnames that are locked
static std::set<std::string> lockedFiles;
static port::Mutex mutex_lockedFiles;

static Status IOError(const std::string& context, int err_number) {
  return Status::IOError(context, strerror(err_number));
}

#ifdef NDEBUG
// empty in release build
#define TEST_KILL_RANDOM(rocksdb_kill_odds)
#else

// Kill the process with probablity 1/odds for testing.
static void TestKillRandom(int odds, const std::string& srcfile,
                           int srcline) {
  time_t curtime = time(nullptr);
  Random r((uint32_t)curtime);

  assert(odds > 0);
  bool crash = r.OneIn(odds);
  if (crash) {
    fprintf(stdout, "Crashing at %s:%d\n", srcfile.c_str(), srcline);
    fflush(stdout);
    TerminateProcess(GetCurrentProcess(), 1);
  }
}

// To avoid crashing always at some frequently executed codepaths (during
// kill random test), use this factor to reduce odds
#define REDUCE_ODDS 2
#define REDUCE_ODDS2 4

#define TEST_KILL_RANDOM(rocksdb_kill_odds) {   \
  if (rocksdb_kill_odds > 0) { \
    TestKillRandom(rocksdb_kill_odds, __FILE__, __LINE__);     \
  } \
}

#endif

namespace {
  static size_t GetUniqueIdFromFile(HANDLE file, char* id, size_t max_size) {
    if (max_size < kMaxVarint32Length * 2) {
      return 0;
    }

    _BY_HANDLE_FILE_INFORMATION info = { 0 };
    if (GetFileInformationByHandle(file, &info) == FALSE) {
      return 0;
    }

    char* rid = id;
    rid = EncodeVarint64(rid, info.nFileIndexHigh);
    rid = EncodeVarint64(rid, info.nFileIndexLow);
    assert(rid >= id);
    return static_cast<size_t>(rid-id);
  }
}

class WindowsSequentialFile: public SequentialFile {
 private:
  std::string filename_;
  HANDLE file_;
  bool use_os_buffer_;

 public:
   WindowsSequentialFile(const std::string& fname, HANDLE f,
      const EnvOptions& options)
      : filename_(fname), file_(f),
        use_os_buffer_(options.use_os_buffer) {
  }
   virtual ~WindowsSequentialFile() { CloseHandle(file_); }

  virtual Status Read(size_t n, Slice* result, char* scratch) {
    Status s;
    DWORD dwBytesToRead = n > DWORD_MAX ? DWORD_MAX : static_cast<DWORD>(n);
    DWORD dwBytesRead = 0;
    if (ReadFile(file_, scratch, dwBytesToRead, &dwBytesRead, nullptr) != FALSE) {
	  // TODO(stash): check if works fine with EOF
      *result = Slice(scratch, dwBytesRead);
    } else {
      s = IOError(filename_, GetLastError());
    }
    return s;
  }

  virtual Status Skip(uint64_t n) {
    LARGE_INTEGER li; li.QuadPart = n;
    if (SetFilePointerEx(file_, li, nullptr, FILE_CURRENT) == FALSE) {
      return IOError(filename_, GetLastError());
    }
    return Status::OK();
  }
};

class WindowsRandomAccessFile : public RandomAccessFile {
private:
  std::string filename_;
  HANDLE file_;
  bool use_os_buffer_;

public:
  WindowsRandomAccessFile(const std::string& fname, HANDLE f,
    const EnvOptions& options)
    : filename_(fname), file_(f), use_os_buffer_(options.use_os_buffer) {
    assert(!options.use_mmap_reads);
  }
  virtual ~WindowsRandomAccessFile() { CloseHandle(file_); }

  virtual Status Read(uint64_t offset, size_t n, Slice* result,
    char* scratch) const {
    Status s;
    DWORD dwBytesToRead = n > DWORD_MAX ? DWORD_MAX : static_cast<DWORD>(n);
    DWORD dwBytesRead = 0;
    OVERLAPPED overlapped = { 0 };
    overlapped.Offset = static_cast<DWORD>(offset);
    overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32);
    if (ReadFile(file_, scratch, dwBytesToRead, &dwBytesRead, &overlapped) != FALSE) {
      *result = Slice(scratch, dwBytesRead);
    } else {
      s = IOError(filename_, GetLastError());
    }
    return s;
  }

  virtual size_t GetUniqueId(char* id, size_t max_size) const {
    return GetUniqueIdFromFile(file_, id, max_size);
  }
};

// mmap() based random-access
class WindowsMmapReadableFile: public RandomAccessFile {
 private:
  HANDLE file_;
  HANDLE mapping_;
  std::string filename_;
  void* mmapped_region_;
  size_t length_;

 public:
  // base[0,length-1] contains the mmapped contents of the file.
   WindowsMmapReadableFile(HANDLE f, HANDLE m, const std::string& fname,
                          void* base, size_t length,
                          const EnvOptions& options)
      : file_(f), mapping_(m), filename_(fname), mmapped_region_(base), length_(length) {
    assert(options.use_mmap_reads);
    assert(options.use_os_buffer);
  }
   virtual ~WindowsMmapReadableFile() {
     UnmapViewOfFile(mmapped_region_);
     CloseHandle(mapping_);
     CloseHandle(file_);
  }

  virtual Status Read(uint64_t offset, size_t n, Slice* result,
                      char* scratch) const {
    Status s;
    if (offset + n > length_) {
      *result = Slice();
      s = IOError(filename_, EINVAL);
    } else {
      *result = Slice(reinterpret_cast<char*>(mmapped_region_) + offset, n);
    }
    return s;
  }

  virtual size_t GetUniqueId(char* id, size_t max_size) const {
    return GetUniqueIdFromFile(file_, id, max_size);
  }
};

class WindowsMmapFile : public WritableFile {
private:
  std::string filename_;
  HANDLE file_;
};

#if TODO_MMAP_WRITABLE_FILE
// We preallocate up to an extra megabyte and use memcpy to append new
// data to the file.  This is safe since we either properly close the
// file before reading from it, or for log files, the reading code
// knows enough to skip zero suffixes.
class PosixMmapFile : public WritableFile {
 private:
  std::string filename_;
  int fd_;
  size_t page_size_;
  size_t map_size_;       // How much extra memory to map at a time
  char* base_;            // The mapped region
  char* limit_;           // Limit of the mapped region
  char* dst_;             // Where to write next  (in range [base_,limit_])
  char* last_sync_;       // Where have we synced up to
  uint64_t file_offset_;  // Offset of base_ in file
  // Have we done an munmap of unsynced data?
  bool pending_sync_;
#ifdef ROCKSDB_FALLOCATE_PRESENT
  bool fallocate_with_keep_size_;
#endif

  // Roundup x to a multiple of y
  static size_t Roundup(size_t x, size_t y) {
    return ((x + y - 1) / y) * y;
  }

  size_t TruncateToPageBoundary(size_t s) {
    s -= (s & (page_size_ - 1));
    assert((s % page_size_) == 0);
    return s;
  }

  bool UnmapCurrentRegion() {
    bool result = true;
    TEST_KILL_RANDOM(rocksdb_kill_odds);
    if (base_ != nullptr) {
      if (last_sync_ < limit_) {
        // Defer syncing this data until next Sync() call, if any
        pending_sync_ = true;
      }
      if (munmap(base_, limit_ - base_) != 0) {
        result = false;
      }
      file_offset_ += limit_ - base_;
      base_ = nullptr;
      limit_ = nullptr;
      last_sync_ = nullptr;
      dst_ = nullptr;

      // Increase the amount we map the next time, but capped at 1MB
      if (map_size_ < (1<<20)) {
        map_size_ *= 2;
      }
    }
    return result;
  }

  Status MapNewRegion() {
#ifdef ROCKSDB_FALLOCATE_PRESENT
    assert(base_ == nullptr);

    TEST_KILL_RANDOM(rocksdb_kill_odds);
    // we can't fallocate with FALLOC_FL_KEEP_SIZE here
    int alloc_status = fallocate(fd_, 0, file_offset_, map_size_);
    if (alloc_status != 0) {
      // fallback to posix_fallocate
      alloc_status = posix_fallocate(fd_, file_offset_, map_size_);
    }
    if (alloc_status != 0) {
      return Status::IOError("Error allocating space to file : " + filename_ +
        "Error : " + strerror(alloc_status));
    }

    TEST_KILL_RANDOM(rocksdb_kill_odds);
    void* ptr = mmap(nullptr, map_size_, PROT_READ | PROT_WRITE, MAP_SHARED,
                     fd_, file_offset_);
    if (ptr == MAP_FAILED) {
      return Status::IOError("MMap failed on " + filename_);
    }

    TEST_KILL_RANDOM(rocksdb_kill_odds);

    base_ = reinterpret_cast<char*>(ptr);
    limit_ = base_ + map_size_;
    dst_ = base_;
    last_sync_ = base_;
    return Status::OK();
#else
    return Status::NotSupported("This platform doesn't support fallocate()");
#endif
  }

 public:
  PosixMmapFile(const std::string& fname, int fd, size_t page_size,
                const EnvOptions& options)
      : filename_(fname),
        fd_(fd),
        page_size_(page_size),
        map_size_(Roundup(65536, page_size)),
        base_(nullptr),
        limit_(nullptr),
        dst_(nullptr),
        last_sync_(nullptr),
        file_offset_(0),
        pending_sync_(false) {
#ifdef ROCKSDB_FALLOCATE_PRESENT
    fallocate_with_keep_size_ = options.fallocate_with_keep_size;
#endif
    assert((page_size & (page_size - 1)) == 0);
    assert(options.use_mmap_writes);
  }


  ~PosixMmapFile() {
    if (fd_ >= 0) {
      PosixMmapFile::Close();
    }
  }

  virtual Status Append(const Slice& data) {
    const char* src = data.data();
    size_t left = data.size();
    TEST_KILL_RANDOM(rocksdb_kill_odds * REDUCE_ODDS);
    PrepareWrite(GetFileSize(), left);
    while (left > 0) {
      assert(base_ <= dst_);
      assert(dst_ <= limit_);
      size_t avail = limit_ - dst_;
      if (avail == 0) {
        if (UnmapCurrentRegion()) {
          Status s = MapNewRegion();
          if (!s.ok()) {
            return s;
          }
          TEST_KILL_RANDOM(rocksdb_kill_odds);
        }
      }

      size_t n = (left <= avail) ? left : avail;
      memcpy(dst_, src, n);
      dst_ += n;
      src += n;
      left -= n;
    }
    TEST_KILL_RANDOM(rocksdb_kill_odds);
    return Status::OK();
  }

  virtual Status Close() {
    Status s;
    size_t unused = limit_ - dst_;

    TEST_KILL_RANDOM(rocksdb_kill_odds);

    if (!UnmapCurrentRegion()) {
      s = IOError(filename_, errno);
    } else if (unused > 0) {
      // Trim the extra space at the end of the file
      if (ftruncate(fd_, file_offset_ - unused) < 0) {
        s = IOError(filename_, errno);
      }
    }

    TEST_KILL_RANDOM(rocksdb_kill_odds);

    if (close(fd_) < 0) {
      if (s.ok()) {
        s = IOError(filename_, errno);
      }
    }

    fd_ = -1;
    base_ = nullptr;
    limit_ = nullptr;
    return s;
  }

  virtual Status Flush() {
    TEST_KILL_RANDOM(rocksdb_kill_odds);
    return Status::OK();
  }

  virtual Status Sync() {
    Status s;

    if (pending_sync_) {
      // Some unmapped data was not synced
      TEST_KILL_RANDOM(rocksdb_kill_odds);
      pending_sync_ = false;
      if (fdatasync(fd_) < 0) {
        s = IOError(filename_, errno);
      }
      TEST_KILL_RANDOM(rocksdb_kill_odds * REDUCE_ODDS);
    }

    if (dst_ > last_sync_) {
      // Find the beginnings of the pages that contain the first and last
      // bytes to be synced.
      size_t p1 = TruncateToPageBoundary(last_sync_ - base_);
      size_t p2 = TruncateToPageBoundary(dst_ - base_ - 1);
      last_sync_ = dst_;
      TEST_KILL_RANDOM(rocksdb_kill_odds);
      if (msync(base_ + p1, p2 - p1 + page_size_, MS_SYNC) < 0) {
        s = IOError(filename_, errno);
      }
      TEST_KILL_RANDOM(rocksdb_kill_odds);
    }

    return s;
  }

  /**
   * Flush data as well as metadata to stable storage.
   */
  virtual Status Fsync() {
    if (pending_sync_) {
      // Some unmapped data was not synced
      TEST_KILL_RANDOM(rocksdb_kill_odds);
      pending_sync_ = false;
      if (fsync(fd_) < 0) {
        return IOError(filename_, errno);
      }
      TEST_KILL_RANDOM(rocksdb_kill_odds);
    }
    // This invocation to Sync will not issue the call to
    // fdatasync because pending_sync_ has already been cleared.
    return Sync();
  }

  /**
   * Get the size of valid data in the file. This will not match the
   * size that is returned from the filesystem because we use mmap
   * to extend file by map_size every time.
   */
  virtual uint64_t GetFileSize() {
    size_t used = dst_ - base_;
    return file_offset_ + used;
  }

  virtual Status InvalidateCache(size_t offset, size_t length) {
#ifndef OS_LINUX
    return Status::OK();
#else
    // free OS pages
    int ret = Fadvise(fd_, offset, length, POSIX_FADV_DONTNEED);
    if (ret == 0) {
      return Status::OK();
    }
    return IOError(filename_, errno);
#endif
  }

#ifdef ROCKSDB_FALLOCATE_PRESENT
  virtual Status Allocate(off_t offset, off_t len) {
    TEST_KILL_RANDOM(rocksdb_kill_odds);
    int alloc_status = fallocate(
        fd_, fallocate_with_keep_size_ ? FALLOC_FL_KEEP_SIZE : 0, offset, len);
    if (alloc_status == 0) {
      return Status::OK();
    } else {
      return IOError(filename_, errno);
    }
  }
#endif
};
#endif

class WindowsWritableFile : public WritableFile {
 private:
  const std::string filename_;
  HANDLE file_;
  size_t cursize_;      // current size of cached data in buf_
  size_t capacity_;     // max size of buf_
  unique_ptr<char[]> buf_;           // a buffer to cache writes
  uint64_t filesize_;
  bool pending_sync_;
  bool pending_fsync_;
  uint64_t last_sync_size_;
  uint64_t bytes_per_sync_;

 public:
   WindowsWritableFile(const std::string& fname, HANDLE f, size_t capacity,
                      const EnvOptions& options)
      : filename_(fname),
        file_(f),
        cursize_(0),
        capacity_(capacity),
        buf_(new char[capacity]),
        filesize_(0),
        pending_sync_(false),
        pending_fsync_(false),
        last_sync_size_(0),
        bytes_per_sync_(options.bytes_per_sync) {
    assert(!options.use_mmap_writes);
  }

   ~WindowsWritableFile() {
    if (file_ != INVALID_HANDLE_VALUE) {
      WindowsWritableFile::Close();
    }
  }

  virtual Status Append(const Slice& data) {
    const char* src = data.data();
    size_t left = data.size();
    Status s;
    pending_sync_ = true;
    pending_fsync_ = true;

    TEST_KILL_RANDOM(rocksdb_kill_odds * REDUCE_ODDS2);

    PrepareWrite(GetFileSize(), left);
    // if there is no space in the cache, then flush
    if (cursize_ + left > capacity_) {
      s = Flush();
      if (!s.ok()) {
        return s;
      }
      // Increase the buffer size, but capped at 1MB
      if (capacity_ < (1<<20)) {
        capacity_ *= 2;
        buf_.reset(new char[capacity_]);
      }
      assert(cursize_ == 0);
    }

    // if the write fits into the cache, then write to cache
    // otherwise do a write() syscall to write to OS buffers.
    if (cursize_ + left <= capacity_) {
      memcpy(buf_.get()+cursize_, src, left);
      cursize_ += left;
    } else {
      while (left != 0) {
        DWORD dwBytesToWrite = left > DWORD_MAX ? DWORD_MAX : static_cast<DWORD>(left);
        DWORD dwBytesWritten = 0;
        if (WriteFile(file_, src, dwBytesToWrite, &dwBytesWritten, nullptr) == FALSE) {
          return IOError(filename_, GetLastError());
        }
        TEST_KILL_RANDOM(rocksdb_kill_odds);

        left -= dwBytesWritten;
        src += dwBytesWritten;
      }
    }
    filesize_ += data.size();
    return Status::OK();
  }

  virtual Status Close() {
    Status s;
    s = Flush(); // flush cache to OS
    if (!s.ok()) {
      return s;
    }

    TEST_KILL_RANDOM(rocksdb_kill_odds);

    /*size_t block_size;
    size_t last_allocated_block;
    GetPreallocationStatus(&block_size, &last_allocated_block);
    if (last_allocated_block > 0) {
      // trim the extra space preallocated at the end of the file
      int dummy __attribute__((unused));
      dummy = ftruncate(fd_, filesize_);  // ignore errors
    }*/

    if (CloseHandle(file_) == FALSE) {
      if (s.ok()) {
        s = IOError(filename_, errno);
      }
    }
    file_ = INVALID_HANDLE_VALUE;
    return s;
  }

  // write out the cached data to the OS cache
  virtual Status Flush() {
    TEST_KILL_RANDOM(rocksdb_kill_odds * REDUCE_ODDS2);
    size_t left = cursize_;
    char* src = buf_.get();
    while (left != 0) {
      DWORD dwBytesToWrite = left > DWORD_MAX ? DWORD_MAX : static_cast<DWORD>(left);
      DWORD dwBytesWritten = 0;
      if (WriteFile(file_, src, dwBytesToWrite, &dwBytesWritten, nullptr) == FALSE) {
        return IOError(filename_, errno);
      }
      TEST_KILL_RANDOM(rocksdb_kill_odds * REDUCE_ODDS2);
      left -= dwBytesWritten;
      src += dwBytesWritten;
    }
    cursize_ = 0;

    // sync OS cache to disk for every bytes_per_sync_
    // TODO: give log file and sst file different options (log
    // files could be potentially cached in OS for their whole
    // life time, thus we might not want to flush at all).
    if (bytes_per_sync_ &&
        filesize_ - last_sync_size_ >= bytes_per_sync_) {
      RangeSync(last_sync_size_, filesize_ - last_sync_size_);
      last_sync_size_ = filesize_;
    }

    return Status::OK();
  }

  virtual Status Sync() {
    Status s = Flush();
    if (!s.ok()) {
      return s;
    }
    TEST_KILL_RANDOM(rocksdb_kill_odds);
    if (pending_sync_ && FlushFileBuffers(file_) == FALSE) {
      return IOError(filename_, errno);
    }
    TEST_KILL_RANDOM(rocksdb_kill_odds);
    pending_sync_ = false;
    return Status::OK();
  }

  virtual Status Fsync() {
    Status s = Flush();
    if (!s.ok()) {
      return s;
    }
    TEST_KILL_RANDOM(rocksdb_kill_odds);
    if (pending_fsync_ && FlushFileBuffers(file_) < 0) {
      return IOError(filename_, errno);
    }
    TEST_KILL_RANDOM(rocksdb_kill_odds);
    pending_fsync_ = false;
    pending_sync_ = false;
    return Status::OK();
  }

  virtual uint64_t GetFileSize() {
    return filesize_;
  }
};


class WindowsEnv : public Env {
 public:
  WindowsEnv();

  virtual ~WindowsEnv() {
  }

  virtual Status NewSequentialFile(const std::string& fname,
                                   unique_ptr<SequentialFile>* result,
                                   const EnvOptions& options) {
	Status s;
    result->reset();
	HANDLE fileHandle = CreateFile(fname.c_str(), GENERIC_READ,
								   FILE_SHARE_READ, NULL, OPEN_EXISTING,
								   FILE_ATTRIBUTE_NORMAL, NULL);
	// TODO(stash): use mmap
	if (INVALID_HANDLE_VALUE == fileHandle)
	{
		*result = nullptr;
		s = IOError(fname, errno);
	} else {
		result->reset(new WindowsSequentialFile(fname, fileHandle, options));
		s = Status::OK();
	}
	return s;
  }

  virtual Status NewRandomAccessFile(const std::string& fname,
                                     unique_ptr<RandomAccessFile>* result,
                                     const EnvOptions& options) {
	  Status s;
	  result->reset();
	  HANDLE fileHandle = CreateFile(fname.c_str(), GENERIC_READ,
		  FILE_SHARE_READ, NULL, OPEN_EXISTING,
		  FILE_ATTRIBUTE_NORMAL, NULL);
	  // TODO(stash): use mmap
	  if (INVALID_HANDLE_VALUE == fileHandle)	{
		  *result = nullptr;
		  s = IOError(fname, errno);
	  } else if (options.use_mmap_reads) {
		  // TODO(stash): check condition
		  DWORD fileSizeHighPart;
		  DWORD fileSizeLowPart = ::GetFileSize(fileHandle, &fileSizeHighPart);
		  LARGE_INTEGER fileSize;
		  fileSize.LowPart = fileSizeLowPart;
		  fileSize.HighPart = fileSizeHighPart;
		  HANDLE fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
		  if (NULL == fileMapping) {
			  s = IOError(fname, errno);
		  } else {
			  void* base = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
			  // TODO(stash): check
			  result->reset(
				  new WindowsMmapReadableFile(fileHandle, fileMapping,
											  fname, base, fileSize.QuadPart, options));
		  }
      s = Status::OK();
	  } else {
		  result->reset(new WindowsRandomAccessFile(fname, fileHandle, options));
		  s = Status::OK();
	  }
    return s;
  }

  virtual Status NewWritableFile(const std::string& fname,
                                 unique_ptr<WritableFile>* result,
                                 const EnvOptions& options) {
    return Status::NotSupported("Not supported yet");
  }

  virtual Status NewRandomRWFile(const std::string& fname,
                                 unique_ptr<RandomRWFile>* result,
                                 const EnvOptions& options) {
    result->reset();
    // no support for mmap yet
    if (options.use_mmap_writes || options.use_mmap_reads) {
      return Status::NotSupported("No support for mmap read/write yet");
    }
    Status s;
    return Status::NotSupported("Not supported yet");
  }

  virtual Status NewDirectory(const std::string& name,
                              unique_ptr<Directory>* result) {
    result->reset();
    return Status::OK();
  }

  virtual bool FileExists(const std::string& fname) {
    return false;
  }

  virtual Status GetChildren(const std::string& dir,
                             std::vector<std::string>* result) {
    result->clear();
    return Status::OK();
  }


  virtual Status DeleteFile(const std::string& fname) {
	  return Status::NotSupported("Not supported yet");
  }

  virtual Status RenameFile(const std::string& src,
	  const std::string& target)
  {
	  return Status::NotSupported("Not supported yet");
  }

  virtual Status CreateDir(const std::string& name) {
    Status result;
    auto res = ::CreateDirectory(TEXT(name.c_str()), NULL);
    if (0 == res)
    {
      auto error = GetLastError();
      result = IOError(name, error);
    }
    return result;
  };

  virtual Status CreateDirIfMissing(const std::string& name) {
    Status result;
    auto res = ::CreateDirectory(TEXT(name.c_str()), NULL);
    if (0 == res)
    {
      auto error = GetLastError();
      if (ERROR_ALREADY_EXISTS != error)
      {
        result = IOError(name, error);
      }
    }
    return result;
  };

  virtual Status DeleteDir(const std::string& name) {
    Status result;
    auto res = ::RemoveDirectory(TEXT(name.c_str()));
    if (0 == res)
    {
      auto error = GetLastError();
      result = IOError(name, error);
    }
    return result;
  };

  virtual Status GetFileSize(const std::string& fname, uint64_t* size) {
    WIN32_FILE_ATTRIBUTE_DATA fad;

    ::GetFileAttributesEx(TEXT(fname.c_str()), ::GetFileExInfoStandard, &fad);

    if ((fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
      return Status::NotSupported(fname + " is a directory");
    }

    *size = static_cast<uint64_t>(fad.nFileSizeHigh) <<
      (sizeof(fad.nFileSizeLow) * 8) + fad.nFileSizeLow;
    return Status::OK();
  }

  virtual Status GetFileModificationTime(const std::string& fname,
                                         uint64_t* file_mtime) {
    // GetFileTime
    auto h = HandleGuard(CreateFile(fname.c_str(), 0,
      FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0));

    if (h == INVALID_HANDLE_VALUE)
    {
      return IOError(fname, GetLastError());
    }

    FILETIME lwt;
    ::GetFileTime(h, 0, 0, &lwt);

    LARGE_INTEGER ans;
    ans.HighPart = lwt.dwHighDateTime;
    ans.LowPart = lwt.dwLowDateTime;
    *file_mtime = ans.QuadPart;
  }

  virtual Status LockFile(const std::string& fname, FileLock** lock) {
    return Status::NotSupported("Not supported yet");
  }

  virtual Status UnlockFile(FileLock* lock) {
    return Status::NotSupported("Not supported yet");
  }

  virtual void Schedule(void (*function)(void*), void* arg, Priority pri = LOW);

  virtual void StartThread(void (*function)(void* arg), void* arg);

  virtual void WaitForJoin();

  virtual unsigned int GetThreadPoolQueueLen(Priority pri = LOW) const override;

  virtual Status GetTestDirectory(std::string* result) {
    return Status::NotSupported("Not supported yet");
  }

  virtual Status NewLogger(const std::string& fname,
                           shared_ptr<Logger>* result) {
    return Status::NotSupported("Not supported yet");
  }

  virtual uint64_t NowMicros() {
    return 0;
  }

  virtual uint64_t NowNanos() {
    return 0;
  }

  virtual void SleepForMicroseconds(int micros) {
    // Not implemented yet
  }

  virtual Status GetHostName(char* name, uint64_t len) {
    return Status::NotSupported("Not supported yet");
  }

  virtual Status GetCurrentTime(int64_t* unix_time) {
    return Status::NotSupported("Not supported yet");
  }

  virtual Status GetAbsolutePath(const std::string& db_path,
      std::string* output_path) {
    return Status::NotSupported("Not supported yet");
  }

  // Allow increasing the number of worker threads.
  virtual void SetBackgroundThreads(int num, Priority pri) {
  }

  virtual std::string TimeToString(uint64_t secondsSince1970) {
    // Not implemented yet
    return "NOTSUPPORTEDYET";
  }

  EnvOptions OptimizeForLogWrite(const EnvOptions& env_options) const {
    // TODO
    return env_options;
  }

  EnvOptions OptimizeForManifestWrite(const EnvOptions& env_options) const {
    // TODO
    return env_options;
  }

  virtual void IncBackgroundThreadsIfNeeded(int number, Priority pri)
  {
    // Not implemented yet
  }


 private:
  bool checkedDiskForMmap_;
  bool forceMmapOff; // do we override Env options?


  // Returns true iff the named directory exists and is a directory.
  virtual bool DirExists(const std::string& dname) {
    return false;
  }

  size_t page_size_;


  class ThreadPool {
   public:
    ThreadPool() {
    }

    ~ThreadPool() {
    }

    // Return true if there is at least one thread needs to terminate.
    bool HasExcessiveThread() {
    }

    // Return true iff the current thread is the excessive thread to terminate.
    // Always terminate the running thread that is added last, even if there are
    // more than one thread to terminate.
    bool IsLastExcessiveThread(size_t thread_id) {
    }

    // Is one of the threads to terminate.
    bool IsExcessiveThread(size_t thread_id) {
    }

    void BGThread(size_t thread_id) {
    }

    // Helper struct for passing arguments when creating threads.
    struct BGThreadMetadata {
      ThreadPool* thread_pool_;
      size_t thread_id_;  // Thread count in the thread.
      explicit BGThreadMetadata(ThreadPool* thread_pool, size_t thread_id)
          : thread_pool_(thread_pool), thread_id_(thread_id) {}
    };

    static void* BGThreadWrapper(void* arg) {
      BGThreadMetadata* meta = reinterpret_cast<BGThreadMetadata*>(arg);
      size_t thread_id = meta->thread_id_;
      ThreadPool* tp = meta->thread_pool_;
      delete meta;
      tp->BGThread(thread_id);
      return nullptr;
    }

    void WakeUpAllThreads() {
    }

    void SetBackgroundThreads(int num) {
    }

    void StartBGThreads() {
    }

    void Schedule(void (*function)(void*), void* arg) {
    }

    unsigned int GetQueueLen() const {
    }

   private:
    // Entry per Schedule() call
    struct BGItem { void* arg; void (*function)(void*); };

    int total_threads_limit_;
    std::atomic_uint queue_len_;  // Queue length. Used for stats reporting
    bool exit_all_threads_;
  };
};

WindowsEnv::WindowsEnv()
  : checkedDiskForMmap_(false),
    forceMmapOff(false) {
}

void WindowsEnv::Schedule(void(*function)(void*), void* arg, Priority pri) {
  // Not implemented yet
}

unsigned int WindowsEnv::GetThreadPoolQueueLen(Priority pri) const {
  // Not implemented yet
  return 0;
}

namespace {
struct StartThreadState {
  void (*user_function)(void*);
  void* arg;
};
}
static void* StartThreadWrapper(void* arg) {
  StartThreadState* state = reinterpret_cast<StartThreadState*>(arg);
  state->user_function(state->arg);
  delete state;
  return nullptr;
}

void WindowsEnv::StartThread(void(*function)(void* arg), void* arg) {
}

void WindowsEnv::WaitForJoin() {
}

}  // namespace

std::string Env::GenerateUniqueId() {
  return "NOTSUPPORTEDYET";
}

Env* Env::Default() {
  static WindowsEnv default_env;
  return &default_env;
}

}  // namespace rocksdb

#endif
