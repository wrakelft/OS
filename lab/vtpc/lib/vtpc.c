#define _GNU_SOURCE

#include "vtpc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BLOCK_SIZE 4096
#define CACHE_CAPACITY 1024
#define MAX_FILES 128

struct cache_page_s {
  void* data;
  int fd;
  off_t page_index;
  size_t data_len;
  bool is_valid;
  bool is_dirty;
  struct cache_page_s* prev;
  struct cache_page_s* next;
};

typedef struct cache_page_s cache_page_t;

typedef struct {
  int os_fd_direct;
  int os_fd;
  bool use_direct;
  off_t cursor;
  off_t size;
  bool in_use;
} file_handle_t;

static cache_page_t cache[CACHE_CAPACITY];
static file_handle_t files[MAX_FILES];
static cache_page_t* list_head = NULL;
static cache_page_t* list_tail = NULL;

static bool page_in_list(cache_page_t* p) {
  return p == list_head || p == list_tail || p->prev != NULL || p->next != NULL;
}

static void list_remove(cache_page_t* page) {
  if (!page) {
    return;
  }
  if (page != list_head && page != list_tail && page->prev == NULL &&
      page->next == NULL) {
    return;
  }
  if (page->prev) {
    page->prev->next = page->next;
  } else {
    list_head = page->next;
  }
  if (page->next) {
    page->next->prev = page->prev;
  } else {
    list_tail = page->prev;
  }
  page->prev = page->next = NULL;
}

static void list_push_back(cache_page_t* page) {
  page->prev = list_tail;
  page->next = NULL;
  if (list_tail) {
    list_tail->next = page;
  } else {
    list_head = page;
  }
  list_tail = page;
}

static void make_recent(cache_page_t* page) {
  list_remove(page);
  list_push_back(page);
}

static int find_page_in_cache(int fd, off_t page_index) {
  for (int i = 0; i < CACHE_CAPACITY; i++) {
    if (cache[i].is_valid && cache[i].fd == fd &&
        cache[i].page_index == page_index) {
      make_recent(&cache[i]);
      return i;
    }
  }
  return -1;
}

static int find_victim_idx(off_t avoid_page_idx, int avoid_fd) {
  for (int i = 0; i < CACHE_CAPACITY; i++) {
    if (!cache[i].is_valid) {
      list_remove(&cache[i]);
      cache[i].prev = cache[i].next = NULL;
      cache[i].is_dirty = false;
      cache[i].data_len = 0;
      return i;
    }
  }

  cache_page_t* victim_ptr = list_tail;
  if (victim_ptr->fd == avoid_fd && victim_ptr->page_index == avoid_page_idx) {
    victim_ptr = victim_ptr->prev;
  }

  if (!victim_ptr) {
    victim_ptr = list_head;
  }

  if (victim_ptr->is_dirty) {
    file_handle_t* fil = &files[victim_ptr->fd];
    if (fil->use_direct) {
      if (pwrite(
              fil->os_fd_direct,
              victim_ptr->data,
              BLOCK_SIZE,
              victim_ptr->page_index * (off_t)BLOCK_SIZE
          ) < 0) {
        return -1;
      }
      off_t page_end = (victim_ptr->page_index + 1) * (off_t)BLOCK_SIZE;
      if (page_end > fil->size) {
        ftruncate(fil->os_fd, fil->size);
      }
    } else {
      size_t len = victim_ptr->data_len;
      if (len > 0) {
        if (pwrite(
                fil->os_fd,
                victim_ptr->data,
                len,
                victim_ptr->page_index * (off_t)BLOCK_SIZE
            ) < 0) {
          return -1;
        }
      }
    }
    victim_ptr->is_dirty = false;
  }
  victim_ptr->is_valid = false;
  list_remove(victim_ptr);
  return (int)(victim_ptr - cache);
}

int vtpc_open(const char* path, int mode, int access) {
  unsigned int mode_u = (unsigned int)mode;
  unsigned int fd_buf_flags_u = mode_u & ~(unsigned int)O_DIRECT;
  int fd_buf = open(path, (int)fd_buf_flags_u, access);
  if (fd_buf < 0) {
    return -1;
  }

  unsigned int flags_direct = (unsigned int)mode | (unsigned int)O_DIRECT;
  int fd_direct = open(path, (int)flags_direct, access);
  bool use_direct = true;
  if (fd_direct < 0) {
    use_direct = false;
    fd_direct = fd_buf;
  }

  off_t sz = lseek(fd_buf, 0, SEEK_END);
  lseek(fd_buf, 0, SEEK_SET);

  for (int i = 0; i < MAX_FILES; i++) {
    if (!files[i].in_use) {
      files[i].os_fd_direct = fd_direct;
      files[i].os_fd = fd_buf;
      files[i].use_direct = use_direct;
      files[i].cursor = 0;
      files[i].size = (sz < 0) ? 0 : sz;
      files[i].in_use = true;
      return i;
    }
  }
  if (use_direct && fd_direct != fd_buf) {
    close(fd_direct);
  }
  close(fd_buf);
  errno = EMFILE;
  return -1;
}

int vtpc_close(int fd) {
  if (fd < 0 || fd >= MAX_FILES || !files[fd].in_use) {
    errno = EBADF;
    return -1;
  }

  vtpc_fsync(fd);
  if (files[fd].use_direct && files[fd].os_fd_direct != files[fd].os_fd) {
    close(files[fd].os_fd_direct);
  }
  close(files[fd].os_fd);
  files[fd].in_use = false;

  for (int i = 0; i < CACHE_CAPACITY; i++) {
    if (cache[i].is_valid && cache[i].fd == fd) {
      if (page_in_list(&cache[i])) {
        list_remove(&cache[i]);
      }
      cache[i].prev = cache[i].next = NULL;
      cache[i].is_valid = false;
      cache[i].is_dirty = false;
      cache[i].data_len = 0;
    }
  }
  return 0;
}

static int get_cached_page(int fd, off_t p_idx) {
  int c_idx = find_page_in_cache(fd, p_idx);
  if (c_idx != -1) {
    return c_idx;
  }
  c_idx = find_victim_idx(p_idx, fd);
  cache_page_t* page = &cache[c_idx];
  if (!page->data) {
    if (posix_memalign(&page->data, BLOCK_SIZE, BLOCK_SIZE)) {
      errno = ENOMEM;
      return -2;
    }
  }

  memset(page->data, 0, BLOCK_SIZE);

  struct stat st;
  if (fstat(files[fd].os_fd, &st) < 0) {
    return -2;
  }
  off_t disk_sz = st.st_size;

  off_t start = p_idx * (off_t)BLOCK_SIZE;
  ssize_t rdt = 0;

  if (start < disk_sz) {
    off_t remain = disk_sz - start;

    if (files[fd].use_direct && remain >= (off_t)BLOCK_SIZE) {
      rdt = pread(files[fd].os_fd_direct, page->data, BLOCK_SIZE, start);
      if (rdt < 0) {
        return -2;
      }
    } else {
      size_t want =
          (remain < (off_t)BLOCK_SIZE) ? (size_t)remain : (size_t)BLOCK_SIZE;
      rdt = pread(files[fd].os_fd, page->data, want, start);
      if (rdt < 0) {
        return -2;
      }
    }
  }
  page->fd = fd;
  page->page_index = p_idx;
  page->data_len = (size_t)rdt;
  page->is_valid = true;
  page->is_dirty = false;
  list_push_back(page);

  return c_idx;
}

ssize_t vtpc_read(int fd, void* buf, size_t count) {
  if (fd < 0 || fd >= MAX_FILES || !files[fd].in_use) {
    errno = EBADF;
    return -1;
  }
  file_handle_t* fil = &files[fd];
  char* user_ptr = (char*)buf;
  size_t bytes_done = 0;

  while (bytes_done < count && fil->cursor < fil->size) {
    off_t p_idx = fil->cursor / BLOCK_SIZE;
    size_t p_off = (size_t)(fil->cursor % BLOCK_SIZE);

    int c_idx = get_cached_page(fd, p_idx);
    if (c_idx < 0) {
      return (bytes_done > 0) ? (ssize_t)bytes_done : -1;
    }

    cache_page_t* page = &cache[c_idx];

    size_t available = BLOCK_SIZE - p_off;
    size_t left = fil->size - fil->cursor;
    size_t to_copy = available;
    if (to_copy > left) {
      to_copy = left;
    }
    if (to_copy > count - bytes_done) {
      to_copy = count - bytes_done;
    }

    memcpy((char*)buf + bytes_done, (char*)page->data + p_off, to_copy);
    bytes_done += to_copy;
    fil->cursor += (off_t)to_copy;
  }
  return (ssize_t)bytes_done;
}

ssize_t vtpc_write(int fd, const void* buf, size_t count) {
  if (fd < 0 || fd >= MAX_FILES || !files[fd].in_use) {
    errno = EBADF;
    return -1;
  }
  file_handle_t* fil = &files[fd];
  size_t bytes_done = 0;

  while (bytes_done < count) {
    off_t p_idx = fil->cursor / BLOCK_SIZE;
    size_t p_off = (size_t)(fil->cursor % BLOCK_SIZE);

    int c_idx = get_cached_page(fd, p_idx);
    if (c_idx < 0) {
      return (bytes_done > 0) ? (ssize_t)bytes_done : -1;
    }

    cache_page_t* page = &cache[c_idx];
    size_t to_write = (count - bytes_done < BLOCK_SIZE - p_off)
                          ? (count - bytes_done)
                          : (BLOCK_SIZE - p_off);

    memcpy((char*)cache[c_idx].data + p_off, (char*)buf + bytes_done, to_write);
    cache[c_idx].is_dirty = true;

    if (p_off + to_write > page->data_len) {
      page->data_len = p_off + to_write;
    }

    bytes_done += to_write;
    fil->cursor += (off_t)to_write;
    if (fil->cursor > fil->size) {
      fil->size = fil->cursor;

      if (ftruncate(fil->os_fd, fil->size) < 0) {
        return (bytes_done > 0) ? (ssize_t)bytes_done : -1;
      }
    }
    make_recent(&cache[c_idx]);
  }
  return (ssize_t)bytes_done;
}

off_t vtpc_lseek(int fd, off_t offset, int whence) {
  if (fd < 0 || fd >= MAX_FILES || !files[fd].in_use) {
    errno = EBADF;
    return -1;
  }
  off_t new_pos = 0;
  if (whence == SEEK_SET) {
    new_pos = offset;
  } else if (whence == SEEK_CUR) {
    new_pos = files[fd].cursor + offset;
  } else if (whence == SEEK_END) {
    new_pos = files[fd].size + offset;
  } else {
    errno = EINVAL;
    return -1;
  }

  if (new_pos < 0) {
    errno = EINVAL;
    return -1;
  }

  files[fd].cursor = new_pos;
  return new_pos;
}

int vtpc_fsync(int fd) {
  if (fd < 0 || fd >= MAX_FILES || !files[fd].in_use) {
    errno = EBADF;
    return -1;
  }

  file_handle_t* fil = &files[fd];

  for (int i = 0; i < CACHE_CAPACITY; i++) {
    if (cache[i].is_valid && cache[i].fd == fd && cache[i].is_dirty) {
      off_t off = cache[i].page_index * (off_t)BLOCK_SIZE;
      if (fil->use_direct) {
        if (pwrite(fil->os_fd_direct, cache[i].data, BLOCK_SIZE, off) < 0) {
          return -1;
        }
      } else {
        size_t len = cache[i].data_len;
        if (len > 0) {
          if (pwrite(fil->os_fd, cache[i].data, len, off) < 0) {
            return -1;
          }
        }
      }
      cache[i].is_dirty = false;
    }
  }
  if (ftruncate(fil->os_fd, fil->size) < 0) {
    return -1;
  }
  return fsync(fil->os_fd);
}
