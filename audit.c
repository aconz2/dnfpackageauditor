#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <ev.h>
#include <libaudit.h>
#include <linux/audit.h>

int fd;
int raw = 0;
int tree = 0;
int cmdline = 0;
const int rootpid = 1;                /* 1 is systemd */

#define CMDLINEBUFSIZ 1024

static char cmdlinebuf[CMDLINEBUFSIZ];

/* message looks like  */
const char *example_message = "audit(1586360348.516:58178): argc=2 a0=\"/usr/bin/esmtp\" a1=\"-t\" items=2 ppid=2478 pid=2500 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=2 comm=\"dotlockfile\" exe=\"/usr/bin/dotlockfile\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)";

/* this is craziness, why doesn't the message have something more structured than a formatted string, when I just want to unformat it */
/* the message has a max length and if there are lots of args, the ppid, pid, and exe can get cut off */
static void get_important_bits(char *message, char **args, char **ppid, char **pid, char **exe) {
  /* TODO: was trying to parse the args but I think there is some weird quoting */
  /* char *cur = message + 36;     /\* skip timestamp *\/ */
  /* char *args_begin = strstr(message, "a0=\""); */
  /* char *args_end = strstr(args_begin, " items="); */
  /*  *args_end = '\0'; */
  /* (void)args; */

  *ppid = NULL;
  *pid = NULL;
  *exe = NULL;

  /* char *ppid_begin = strstr(args_end + 7, "ppid=") + 5; */
  char *ppid_begin = strstr(message, "ppid=");
  if (ppid_begin == NULL) {return;}
  ppid_begin += 5;
  char *ppid_end = strchr(ppid_begin, ' ');
  *ppid_end = '\0';

  char *pid_begin = strstr(ppid_end + 1, "pid=");
  if (pid_begin == NULL) {return;}
  pid_begin += 4;
  char *pid_end = strchr(pid_begin, ' ');
  *pid_end = '\0';

  char *exe_begin = strstr(pid_end + 1, "exe=\"");
  if (exe_begin == NULL) {return;}
  exe_begin += 5;
  char *exe_end = strchr(exe_begin, '"');
  if (exe_end) {
    *exe_end = '\0';
  } else {
    exe_begin = NULL;
  }

  /* *args = args_begin; */
  (void)args;
  *ppid = ppid_begin;
  *pid = pid_begin;
  *exe = exe_begin;
}

/* following three functions modified https://gist.github.com/fclairamb/a16a4237c46440bdb172 */
static void get_process_name(const pid_t pid, char *name) {
	char procfile[BUFSIZ];
	sprintf(procfile, "/proc/%d/cmdline", pid);
	FILE* fp = fopen(procfile, "r");
  if (!fp) {
    name[0] = '\0';
    return;
  }
  size_t size = fread(name, sizeof(char), BUFSIZ, fp);
  if (size > 0) {
    if ('\n' == name[size - 1])
      name[size - 1] = '\0';
  } else {
    name[0] = '\0';
  }
  fclose(fp);
}

static pid_t get_process_parent_id(const pid_t pid) {
	char buffer[BUFSIZ];
	sprintf(buffer, "/proc/%d/stat", pid);
	FILE* fp = fopen(buffer, "r");
  if (!fp) {
    return 0;
  }
  size_t size = fread(buffer, sizeof(char), BUFSIZ, fp);
  if (size > 0) {
    // See: http://man7.org/linux/man-pages/man5/proc.5.html section /proc/[pid]/stat
    strtok(buffer, " "); // (1) pid  %d
    strtok(NULL, " "); // (2) comm  %s
    strtok(NULL, " "); // (3) state  %c
    char *s_ppid = strtok(NULL, " "); // (4) ppid  %d
    fclose(fp);
    return atoi(s_ppid);
  } else {
    return 0;
  }
}

/* uses static buffer! */
static char *get_process_cmdline(const pid_t pid, size_t *len) {
	char buffer[BUFSIZ];
	sprintf(buffer, "/proc/%d/cmdline", pid);
	FILE* fp = fopen(buffer, "r");
  if (!fp) {
    cmdlinebuf[0] = '\0';
    *len = 0;
    return cmdlinebuf;
  }
  size_t size = fread(cmdlinebuf, sizeof(char), CMDLINEBUFSIZ, fp);
  fclose(fp);

  cmdlinebuf[size - 1] = '\0';
  char *cur = strchr(cmdlinebuf, '\0'); /* skip past first arg (we already have the exe) */
  if (cur == NULL) {
    *len = 0;
    cmdlinebuf[0] = '\0';
    return cmdlinebuf;
  }
  cur += 1;
  assert(cur >= cmdlinebuf);
  assert(size >= (cur - cmdlinebuf));
  *len = size - (cur - cmdlinebuf);
  if (*len > 0) {
    *len -= 1; /* when we print we don't have to print the last \0 as a space */
  }
  assert(*len < CMDLINEBUFSIZ);
  return cur;
}

static void print_args(char *buf, size_t len, char nullchar) {
  for (size_t i = 0; i < len; i++) {
    char c = buf[i];
    if (c == '\0') c = nullchar;
    fputc(c, stdout);
  }
}

static void print_ancestry(pid_t pid) {
  bool first = true;
	while (pid != rootpid) {
    if (!first) {
      printf(" -- ");
    }
    first = false;

		char buf[BUFSIZ];
		get_process_name(pid, buf);
		printf("%s(%d)", buf, pid);
    if (cmdline) {
      size_t len;
      char *cur = get_process_cmdline(pid, &len);
      fputc('[', stdout);
      print_args(cur, len, ' ');
      fputc(']', stdout);
    }
		pid = get_process_parent_id(pid);
	}
}

void monitoring(struct ev_loop *loop, struct ev_io *io, int revents) {
  struct audit_reply reply;
  audit_get_reply(fd, &reply, GET_REPLY_NONBLOCKING, 0);

  /* printf("Event: Type=%s type=%d\n", audit_msg_type_to_name(reply.type), reply.type); */

  if (reply.type == AUDIT_EXECVE) {
    if (raw) {
      /* hmm it looks like the reply.len truncates some of the message */
      /* printf("Type=%s Message=%.*s\n", audit_msg_type_to_name(reply.type), reply.len, reply.message); */
      /* printf("Type=%s Message=%s\n", audit_msg_type_to_name(reply.type), reply.message); */
      printf("%s\n", reply.message);
    }
    char *args, *ppid, *pid, *exe;
    get_important_bits(reply.message, &args, &ppid, &pid, &exe);
    /* printf("%s\t%s\t%s\t%s\n", args, ppid, pid, exe); */
    if (tree) {
      if (pid) {
        print_ancestry(atoi(pid));
        printf("\n");
      }
    } else {
      printf("%s\t%s\t%s", ppid, pid, exe);
      if (cmdline && pid) {
        size_t len;
        char * cur = get_process_cmdline(atoi(pid), &len);
        print_args(cur, len, '\t');
      }
      printf("\n");
    }
  }
}



int main(int argc, char **argv) {
  /* size_t len; */
  /* char *cur = get_process_cmdline(1, &len); */
  /* printf("len=%ld\n", len); */
  /* print_args(cur, len, ' '); */
  /* return -1; */
  if (argc == 2) {
    if (strchr(argv[1], 'h')) {
      printf("Usage: audit [rtc]\n");
      printf(" r : print full message from kernel\n");
      printf(" t : print in tree format showing full ancestry\n");
      printf(" c : print cmdline arguments\n");
      printf("defaults to print ppid,pid,exe in TSV format\n");
      return 0;
    }
    if (strchr(argv[1], 'r')) {raw = 1;}
    if (strchr(argv[1], 't')) {tree = 1;}
    if (strchr(argv[1], 'c')) {cmdline = 1;}
  }

  int ret;
  fd = audit_open();
  if (fd < 0) {
    perror("audit_open");
    return -1;
  }
  ret = audit_set_enabled(fd, 1);
  if (ret < 0) {
    perror("audit_set_enabled");
    return -1;
  }

  ret = audit_set_backlog_limit(fd, 1024);
  if (ret < 0) {
    perror("audit_set_backlog_limit");
    return -1;
  }

  struct audit_rule_data *rule = malloc(sizeof(struct audit_rule_data));
  audit_rule_init_data(rule);

  ret = audit_rule_syscallbyname_data(rule, "execve");
  if (ret < 0) {
    perror("audit_rule_syscallbyname_data");
    return -1;
  }

  ret = audit_add_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);

  ret = audit_set_pid(fd, getpid(), WAIT_YES);
  if (ret < 0) {
    perror("audit_set_pid");
    return -1;
  }

  struct ev_loop *loop = ev_default_loop(EVFLAG_NOENV);
  struct ev_io monitor;

  ev_io_init(&monitor, monitoring, fd, EV_READ);
  ev_io_start(loop, &monitor);
  ev_loop(loop, 0);
  audit_close(fd);

  return 0;
}
