#define _POSIX_C_SOURCE 200809L

#include "vtsh.h"

#include <dirent.h>
#include <fnmatch.h>
#include <glob.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_LINE 1024
#define MAX_ARGS 64
#define EXT 127
#define EXIT_SIGNAL_BASE 128
#define NANOSECONDS_IN_SECOND 1e9

const char* vtsh_prompt(void) {
  return "vtsh> ";
}

static int vtsh_builtin_cd(char* const* argv) {
  const char* path = argv[1];

  if (path == NULL) {
    path = getenv("HOME"); /* NOLINT(concurrency-mt-unsafe) */
    if (path == NULL) {
      (void)fprintf(stderr, "cd: HOME not set\n");
      return 1;
    }
  }

  if (chdir(path) != 0) {
    perror("cd");
    return 1;
  }

  return 0;
}

static int vtsh_run_with_wildcards(char** argv) {
  struct dirent** entries = NULL;
  int i_val = 0;
  int match_count = 0;

  int n_val = scandir(".", &entries, NULL, alphasort);
  if (n_val < 0) {
    perror("scandir");
    return 1;
  }

  char* matching_files[MAX_ARGS];

  for (int i = 0; i < n_val; i++) {
    if (fnmatch(argv[1], entries[i]->d_name, FNM_PATHNAME) == 0) {
      matching_files[match_count++] = entries[i]->d_name;
    }
    free(entries[i]);
  }

  free(entries);

  if (match_count == 0) {
    (void)fprintf(stderr, "No files match the pattern\n");
    return 1;
  }

  char* new_argv[MAX_ARGS];
  new_argv[0] = argv[0];

  for (i_val = 0; i_val < match_count; i_val++) {
    new_argv[i_val + 1] = matching_files[i_val];
  }
  new_argv[match_count + 1] = NULL;

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return 1;
  }

  if (pid == 0) {
    execvp(new_argv[0], new_argv);
    perror("execvp");
    _exit(EXT);
  } else {
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
      perror("waitpid");
      return 1;
    }
    if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
      return EXIT_SIGNAL_BASE;
    }
  }

  return 0;
}

static int vtsh_run_with_globbing(char** argv) {
  char* new_argv[MAX_ARGS];
  int new_argc = 0;
  glob_t g_val;

  for (int i = 0; argv[i] != NULL && new_argc < MAX_ARGS - 1; ++i) {
    const char* a_val = argv[i];
    if (strchr(a_val, '*') != NULL || strchr(a_val, '?') != NULL ||
        strchr(a_val, '[') != NULL) {
      int flags = GLOB_NOCHECK;
      if (glob(a_val, flags, NULL, &g_val) != 0) {  // NOLINT(concurrency-mt-unsafe)
        new_argv[new_argc++] = strdup(a_val);
        continue;
      }

      for (size_t j = 0; j < g_val.gl_pathc && new_argc < MAX_ARGS - 1; ++j) {
        new_argv[new_argc++] = strdup(g_val.gl_pathv[j]);
      }
      globfree(&g_val);
    } else {
      new_argv[new_argc++] = strdup(a_val);
    }
  }

  new_argv[new_argc] = NULL;

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    for (int i = 0; i < new_argc; ++i) {
      free(new_argv[i]);
    }
    return 1;
  }

  if (pid == 0) {
    execvp(new_argv[0], new_argv);
    perror("execvp");
    _exit(EXT);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid");
    for (int i = 0; i < new_argc; ++i) {
      free(new_argv[i]);
    }
    return 1;
  }

  for (int i = 0; i < new_argc; ++i) {
    free(new_argv[i]);
  }

  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return EXIT_SIGNAL_BASE;
  }

  return 1;
}

static int vtsh_run(char** argv) {
  if (argv[0] == NULL) {
    return 0;
  }

  if (strcmp(argv[0], "cd") == 0) {
    return vtsh_builtin_cd(argv);
  }

  bool has_wildcard = false;
  for (int i = 0; argv[i] != NULL; ++i) {
    if (strchr(argv[i], '*') != NULL || strchr(argv[i], '?') != NULL ||
        strchr(argv[i], '[') != NULL) {
      has_wildcard = true;
      break;
    }
  }
  if (has_wildcard) {
    return vtsh_run_with_globbing(argv);
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return 1;
  }

  if (pid == 0) {
    execvp(argv[0], argv);
    perror("execvp");
    _exit(EXT);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid");
    return -1;
  }

  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return EXIT_SIGNAL_BASE;
  }

  return 1;
}

static int vtsh_exec_simple(char* line) {
  char* argv[MAX_ARGS];
  int argc = 0;

  char* saveptr = NULL;

  char* token = strtok_r(line, " \t", &saveptr);
  while (token && argc < MAX_ARGS - 1) {
    argv[argc++] = token;
    token = strtok_r(NULL, " \t", &saveptr);
  }
  argv[argc] = NULL;

  if (argc == 0) {
    return 0;
  }

  return vtsh_run(argv);
}

static void vtsh_eval(char* line) {
  int last_exit = 0;
  char* pos = line;

  while (1) {
    char* op_pos = strstr(pos, "&&");

    char* segment_end = op_pos ? op_pos : pos + strlen(pos);

    char saved = *segment_end;
    *segment_end = '\0';

    while (*pos == ' ' || *pos == '\t') {
      pos++;
    }
    size_t len = strlen(pos);
    while (len > 0 && (pos[len - 1] == ' ' || pos[len - 1] == '\t')) {
      len--;
      pos[len] = '\0';
    }

    if (*pos != '\0') {
      char command_buf[MAX_LINE];
      strncpy(command_buf, pos, MAX_LINE);
      command_buf[MAX_LINE - 1] = '\0';

      last_exit = vtsh_exec_simple(command_buf);
    }

    *segment_end = saved;

    if (last_exit != 0) {
      return;
    }

    if (!op_pos) {
      return;
    }

    pos = op_pos + 2;
  }
}

void vtsh_loop(void) {
  char line[MAX_LINE];

  for (;;) {
    printf("%s", vtsh_prompt());
    if (fflush(stdout) != 0) {
      perror("fflush");
    }

    if (!fgets(line, sizeof(line), stdin)) {
      break;
    }

    line[strcspn(line, "\n")] = '\0';

    if (strcmp(line, "exit") == 0) {
      break;
    }

    if (line[0] == '\0') {
      continue;
    }

    vtsh_eval(line);
  }
}

int main(void) {
  vtsh_loop();
  return 0;
}
