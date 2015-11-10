/*
  Reading configfile
 
  Invoking ethspray zero or more times dependnig on config.


  /etc/ethsprayd.conf
   rxdir=/etc/ethspray/rx
   txdir=/etc/ethspray/tx
   exec=/usr/bin/ethspray


  For each line in each file ${rxdir}/*.conf
  Runs: ${exec} -F rx|tx ${contentoffile}

 ethsprayd [-f configfile] [-d|--daemonize]


 */
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "jelopt.h"

struct {
	char *configfile;
	int daemonize;
	int verbose;
	char *rxdir, *txdir, *execfn;
} conf;

struct child {
	pid_t pid;
	struct child *next;
};

int splitargs(char **argv, int i, const char *string)
{
	char *p, *eow;

	p = strdup(string);
	while(1) {
		eow = strchr(p, ' ');
		if(!eow) {
			argv[i++] = p;
			break;
		}
		argv[i++] = p;
		*eow = 0;
		p = eow+1;
	}
	argv[i++] = 0;
	return 0;
}

int readandrun(struct child **children, const char *dir, char *mode)
{
	DIR *d;
	struct dirent *ent;
	
	d = opendir(dir);
	if(!d) return -1;
	while((ent = readdir(d))) {
		if(ent->d_name[0] == '.') continue;
		if(strlen(ent->d_name) < 6) continue;
		if(strcmp(ent->d_name+strlen(ent->d_name)-5, ".conf")) continue;
		printf("%s\n", ent->d_name);
		{
			int fd, n;
			pid_t pid;
			char fn[1024], buf[256];
			struct child *child;
			
			snprintf(fn, sizeof(fn), "%s/%s", dir, ent->d_name);
			fd = open(fn, O_RDONLY);
			if(fd == -1) {
				fprintf(stderr, "ERROR: could not open '%s'\n", fn);
				continue;
			}
			n = read(fd, buf, sizeof(buf)-1);
			close(fd);
			if(n <= 0) {
				fprintf(stderr, "ERROR: empty file '%s'\n", fn);
				continue;
			}
			buf[n] = 0;
			
			pid = fork();
			if(pid == 0) {
				char *envp[1], *argv[32];
				envp[0] = (void*)0;
				argv[0] = conf.execfn;
				argv[1] = "-F";
				argv[2] = mode;
				splitargs(argv, 3, buf);
				if(conf.verbose > 1) fprintf(stderr, "execve '%s'\n", conf.execfn);
				execve(conf.execfn, argv, envp);
				fprintf(stderr, "ERROR: execve failed\n");
				exit(2);
			}
			if(pid == -1) {
				fprintf(stderr, "ERROR: fork failed\n");
				continue;
			}
			child = malloc(sizeof(struct child));
			child->pid = pid;
			child->next = *children;
			*children = child;
		}
	}
	closedir(d);
	return 0;
}

int mainconfig()
{
	int fd;
	char *buf;
	struct stat statb;
	ssize_t n;

	fd = open(conf.configfile, O_RDONLY);
	if(fd == -1) return -1;
	if(fstat(fd, &statb)) {
		close(fd);
		return -1;
	}
	buf = malloc(statb.st_size+1);
	if(!buf) {
		close(fd);
		return -1;
	}
	n = read(fd, buf, statb.st_size); /* FIXME: should loop */
	close(fd);
	if(n <= 0) {
		free(buf);
		return -1;
	}
	buf[n] = 0;

	{
		char *p = buf;
		char *eol;

		while(1) {
			eol = strchr(p, '\n');
			if(!strncmp(p, "rxdir=", 6)) {
				if(eol) 
					conf.rxdir = strndup(p+6, eol-p-6);
				else
					conf.rxdir = strdup(p+6);
			}
			if(!strncmp(p, "txdir=", 6)) {
				if(eol) 
					conf.txdir = strndup(p+6, eol-p-6);
				else
					conf.txdir = strdup(p+6);
			}
			if(!strncmp(p, "exec=", 5)) {
				if(eol) 
					conf.execfn = strndup(p+5, eol-p-5);
				else
					conf.execfn = strdup(p+5);
			}

			if(!eol) break;
			p = eol + 1;
		}
	}
	free(buf);
	return 0;
}

int reap(struct child **children, pid_t pid)
{
	struct child *child, *prev = (void*)0;
	for(child = *children;child;child = child->next) {
		if(child->pid == pid) {
			if(prev)
				prev->next = child->next;
			else
				*children = child->next;
			break;
		}
		prev = child;
	}
	return 0;
}

void daemonize(void)
{
	pid_t pid, sid;
	int fd;

	/* already a daemon */
	if ( getppid() == 1 ) return;

	if((pid = fork()) < 0)
		exit(-1);

	if (pid > 0) _exit(0);

	umask(0);

	if((sid = setsid()) < 0)
		exit(-1);

	if ((chdir("/")) < 0)
		exit(-1);

	if((fd = open("/dev/null", O_RDWR, 0)) >= 0) {
		if(fd>2) {
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
		}
		if(fd) close(fd);
	}
}

int main(int argc, char **argv)
{
	int status, err=0;
	struct child *children = (void*)0;

	conf.configfile = "/etc/ethsprayd.conf";
	conf.rxdir = "/etc/ethspray/rx";
	conf.txdir = "/etc/ethspray/tx";
	conf.execfn = "/usr/bin/ethspray";

	if(jelopt(argv, 'h', "help", 0, &err)) {
	usage:
		printf("ethsprayd [-v] [-f configfile] [-d] [-v]\n"
		       " -v --verbose    be verbose\n"
		       " -f --config     location of configfile\n"
		       " -d --daemonize  daemonize\n"
		       "\n"
		       "For each line in each file ${rxdir}/*.conf\n"
		       "Runs: ${exec} -F rx|tx ${contentoffile}\n"
		       "\n"
		       " Configfile format:\n"
		       "rxdir=/etc/ethspray/rx\n"
		       "txdir=/etc/ethspray/tx\n"
		       "exec=/usr/bin/ethspray\n"
			);
		exit(0);
	}


	while(jelopt(argv, 'f', "config", &conf.configfile, &err));
	while(jelopt(argv, 'd', "daemonize", (void*)0, &err))
		conf.daemonize = 1;
	while(jelopt(argv, 'v', "verbose", (void*)0, &err))
		conf.verbose++;
	argc = jelopt_final(argv, &err);
	if(err) {
		fprintf(stderr, "ethsprayd: Syntax error in options.\n");
		exit(2);
	}

	if(mainconfig()) {
		fprintf(stderr, "failed to read main config\n");
		exit(2);
	}
	
	if(conf.daemonize) {
		daemonize();
	}
	
	readandrun(&children, conf.rxdir, "rx");
	readandrun(&children, conf.txdir, "tx");

	/* reap all children */
	{
		pid_t pid;
		while((pid=waitpid(-1, &status, 0))) {
			if(conf.verbose) fprintf(stderr, "ethsprayd: reaped pid %d\n", pid);
			if(pid == -1) exit(2);
			reap(&children, pid);
			if(children == (void*)0) break;
		}
	}
	exit(1);
}
