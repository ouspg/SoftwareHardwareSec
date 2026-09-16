#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char __executable_start;

/* Buffer size is randomized per student when attempting remote task.
 * Build-time buffer size, >= 48 so the 25-byte execve shellcode, for example,
 * cannot overwrite itself (it pushes down to buffer + BUFSIZE - 4). */
#ifndef BUFSIZE
#define BUFSIZE 64
#endif

#if BUFSIZE < 48
#error "BUFSIZE must be at least 48"
#endif

/* Build-time task id (1-3) selects the leak the task is meant to use. */
#ifndef TASK
#define TASK 1
#endif

#if TASK < 1 || TASK > 3
#error "TASK must be 1, 2 or 3"
#endif

/* Only compiled for task 1. */
#ifndef FLAGPATH
#define FLAGPATH "/home/player/flag.txt"
#endif

#if TASK == 1
void secret() {
  char flag[128];
  FILE *fp = fopen(FLAGPATH, "r");

  if (fp == NULL)
    return;

  while (fgets(flag, sizeof(flag), fp) != NULL)
    fputs(flag, stdout);

  fclose(fp);
}
#endif

void stackoverflow(char *string) {
  char buffer[BUFSIZE];
  strcpy(buffer, string);
  printf("%s\n", buffer);
}

int main() {
  char input[256];

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);

  printf("Starting very vulnerable program...\n");
#if TASK == 1
  printf("[*] base @ %p\n", (void *)&__executable_start);
#elif TASK == 2
  printf("[*] stack @ %p\n", (void *)input);
#else
  printf("[*] system @ %p\n", dlsym(RTLD_DEFAULT, "system"));
#endif
#if TASK == 3 && defined(SHOWFLAGPATH)
  printf("[*] flag @ %p (%s)\n", (void *)FLAGPATH, FLAGPATH);
#endif
  printf("Printing arguments of the program: \n");

  if (fgets(input, sizeof(input), stdin) == NULL)
    return 1;

  input[strcspn(input, "\n")] = '\0';
  stackoverflow(input);

  return 0;
}
