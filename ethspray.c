/*
 * File: ethspray.c
 * Implements: network connectivity tester.
 *
 * Copyright: Jens Låås, Uppsala University, 2015
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <net/if.h>

#include "jelist.h"
#include "jelopt.h"

#define ETH_P_ETHSPRAY 0x6814

#define DELAYOK 50000000

#define WINDOWSIZE 100
#define SCALINGFACTOR 100

struct mac {
	int fd; /* socket */
	struct sockaddr_ll addr;
	struct timeval ts[WINDOWSIZE]; /* circular buffer */
	int rate;
	int pos; /* position in ts array */
	int last; /* last position */
	int loss; /* last calculated packet loss rate in percent */
	time_t lastlossreport; /* latest time loss report waas sent */
	int lastloss; /* loss rate reported in last report */
	time_t lastreport; /* latest "still failed" sent at this time */
	uint64_t fail; /* nr of failures detected */
	uint64_t count; /* total number of packets processed */
	struct timeval gracets; /* point in time when grace period expired */
	struct timeval recoveryts; /* point in time for recovery event */
	struct timeval gracetime; /* time until grace period has expired*/
	uint8_t data[4]; /* proto, proto, rate-hi, rate-lo */
};

struct {
	char *description;
	int verbose;
	int fd;
	int nr_allow_loss;
	int recoverytime; /* time after reconnect for recovery */
	int foreground;
	int facility;
	char *exec;
	int ifindex;
} conf;

int eth_aton(const char *str, uint8_t *maddr)
{
	int i;
	unsigned int a;
	const char *p;
	p = str;
	for(i=0;i<6;i++) {
		if(!p) return -1;
		sscanf(p, "%x", &a);
		maddr[i] = a;
		p = strchr(p, ':');
		if(p) p++;
	}
	return 0;
}

char *eth_ntoa(uint8_t *maddr)
{
	int i;
	static char str[3*6+1];

	for(i=0;i<6;i++) {
		sprintf(str+i*3, "%02x%s", maddr[i], i==5?"":":");
	}
	str[3*6] = 0;
	return str;
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

int logmsg(struct mac *mac, char *msg, struct timeval *ts, long sleepns)
{
	pid_t pid;
	char ats[64];
	struct tm tm;
	
	gmtime_r(&ts->tv_sec, &tm);
	snprintf(ats, sizeof(ats), "%02d:%02d:%02d.%03ld", tm.tm_hour, tm.tm_min, tm.tm_sec, ts->tv_usec/1000);
	
	if(conf.verbose) fprintf(stderr, "%s[%s]: %s at UTC %s\n", mac?eth_ntoa(mac->addr.sll_addr):"(sender)", conf.description, msg, ats);
	
	pid = fork();
	if(pid == 0) {
		close(conf.fd);
		if(sleepns) {
			struct timespec req;
			req.tv_sec = 0;
			req.tv_nsec = sleepns;
			nanosleep(&req, (void*)0);
		}
		syslog(LOG_ERR, "%s[%s] %s at UTC %s", mac?eth_ntoa(mac->addr.sll_addr):"(sender)", conf.description, msg, ats);
		_exit(0);
	}
	return 0;
}

int event(struct mac *mac, char *msg, struct timeval *ts, long sleepns, char *number)
{
	pid_t pid;
	char ats[64];
	struct tm tm;
	
	gmtime_r(&ts->tv_sec, &tm);
	snprintf(ats, sizeof(ats), "UTC %02d:%02d:%02d.%03ld", tm.tm_hour, tm.tm_min, tm.tm_sec, ts->tv_usec/1000);
	
	pid = fork();
        if(pid == 0) {
		char *argv[7];
                close(conf.fd);
		if(sleepns) {
			struct timespec req;
			req.tv_sec = 0;
			req.tv_nsec = sleepns;
			nanosleep(&req, (void*)0);
		}
		argv[0] = conf.exec;
		argv[1] = eth_ntoa(mac->addr.sll_addr);
		argv[2] = msg;
		argv[3] = ats;
		argv[4] = conf.description;
		argv[5] = (void*)0;
		if(number) argv[5] = number;
		argv[6] = (void*)0;
		execv(conf.exec, argv);
                _exit(0);
	}
        return 0;
}

int mac_status_fail(struct mac *mac, struct timeval *ts)
{
	if(mac->fail == 0) {
		logmsg(mac, "connectivity failed", ts, 0);
		if(conf.exec) event(mac, "FAIL", ts, 0, (void*)0);
	}
	if(mac->fail &&
	   (ts->tv_sec > mac->lastreport) &&
	   ((ts->tv_sec % (conf.recoverytime?conf.recoverytime:60)) == 0)) {
		mac->lastreport = ts->tv_sec;
		logmsg(mac, "connectivity still failed", ts, 0);
	}
	mac->fail++;
	if(conf.verbose) fprintf(stderr, "%s: fail = %llu\n", eth_ntoa(mac->addr.sll_addr), mac->fail);
	return mac->fail;
}

int mac_status_ok(struct mac *mac, struct timeval *ts)
{
	if(mac->fail) {
		memcpy(&mac->recoveryts, ts, sizeof(struct timeval));
		mac->recoveryts.tv_sec += conf.recoverytime;
		logmsg(mac, "reconnected", ts, DELAYOK);
		if(conf.exec) event(mac, "RECONNECT", ts, DELAYOK, (void*)0);
	}
	mac->fail = 0;
	if(mac->recoveryts.tv_sec) {
		if(mac->recoveryts.tv_sec < ts->tv_sec) {
			memset(&mac->recoveryts, 0, sizeof(struct timeval));
			if(conf.verbose) fprintf(stderr, "%s: recovered\n", eth_ntoa(mac->addr.sll_addr));
			logmsg(mac, "connectivity recovered", ts, DELAYOK);
			if(conf.exec) event(mac, "RECOVERED", ts, DELAYOK, (void*)0);
		}
	}
	if(conf.verbose > 1) fprintf(stderr, "%s: fail = %llu recover=%lu\n",
				 eth_ntoa(mac->addr.sll_addr), mac->fail, mac->recoveryts.tv_sec);
	return mac->fail;
}

int mac_loss(struct mac *mac, struct timeval *ts)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "current packet loss %2d%%", mac->loss);
	logmsg(mac, buf, ts, 0);
	if(conf.exec) {
		snprintf(buf, sizeof(buf), "%d", mac->loss);
		event(mac, "LOSS", ts, DELAYOK, buf);
	}
	mac->lastlossreport = ts->tv_sec;
	mac->lastloss = mac->loss;
	return mac->loss;
}

void receiver(struct jlhead *macs)
{
	struct pollfd *fds;
	struct sockaddr_ll from_addr;
	struct mac *mac;
	struct jliter iter;
	unsigned int fromlen;
	struct timeval ts;
	int got, rc, i;
	int polltimeout = 500;		
	uint8_t buf[14+4];

	fds = malloc(sizeof(struct pollfd)*(macs->len + 1));
	
	fromlen = sizeof( from_addr );

	for(i=0,mac=jl_iter_init(&iter, macs);mac;mac=jl_iter(&iter),i++) {
		fds[i].fd = mac->fd;
		fds[i].events = POLLIN;
		fds[i].revents = 0;
	}

	gettimeofday(&ts, NULL);

	if(conf.exec) {
		jl_foreach(macs, mac) event(mac, "RESET", &ts, DELAYOK, (void*)0);
	}
	
	if(conf.verbose > 1) printf("polling %d sockets\n", macs->len);
	
	while(1) {
		polltimeout = 500;
		/* calculate time left of grace period: set gracetime */
		for(mac=jl_iter_init(&iter, macs);mac;mac=jl_iter(&iter)) {
			uint64_t gracetime;

			/* only consider non-failed macs */
			if(mac->fail) continue;

			/* gracets - now */
			mac->gracetime.tv_sec = mac->gracets.tv_sec;
			mac->gracetime.tv_usec = mac->gracets.tv_usec;
			mac->gracetime.tv_sec -= ts.tv_sec;
			if(mac->gracetime.tv_usec > ts.tv_usec) {
				mac->gracetime.tv_usec -= ts.tv_usec;
			} else {
				mac->gracetime.tv_sec--;
				mac->gracetime.tv_usec += (uint64_t)1000000;
				mac->gracetime.tv_usec -= ts.tv_usec;
			}
			gracetime = mac->gracetime.tv_sec * 1000;
			gracetime += (mac->gracetime.tv_usec / 1000);
			
			/* set the lowest polltimeout */
			if((gracetime >= 0) && (gracetime < polltimeout))
				polltimeout = gracetime;
		}

		rc = poll(fds, macs->len, polltimeout);
		if(rc > 0) {
			if(conf.verbose > 2) printf("poll event\n");
			for(i=0;i<macs->len;i++) {
				if( fds[i].revents == 0) continue;
				got = recvfrom( fds[i].fd, buf, sizeof(buf), 0,
						(struct sockaddr *)&from_addr, &fromlen);
				if(got < 18) continue;
				gettimeofday(&ts, NULL);
				if(conf.verbose > 2) printf("got packet from %s [len %d]\n",
							eth_ntoa(from_addr.sll_addr), got);
				if(buf[14] != 'n' || buf[15] != '1') {
					if(conf.verbose > 1) printf("not ethspray packet %x,%x\n", buf[14], buf[15]);
					continue;
				}
				for(mac=jl_iter_init(&iter, macs);mac;mac=jl_iter(&iter)) {
					if(!memcmp(mac->addr.sll_addr, from_addr.sll_addr, 6)) {
						mac->count++;
						memcpy(&mac->ts[mac->pos], &ts, sizeof(struct timeval));
						if(conf.verbose > 1) printf("timestamped %lu.%lu\n", mac->ts[mac->pos].tv_sec, mac->ts[mac->pos].tv_usec);
						if(buf[16]||buf[17])
							mac->rate = (buf[16] << 8) + buf[17];
						{
							uint64_t maxtime;
							memcpy(&mac->gracets, &mac->ts[mac->last], sizeof(struct timeval));
							maxtime = ((uint64_t)1000000/mac->rate)*conf.nr_allow_loss;
							mac->gracets.tv_sec += (maxtime/1000000);
							mac->gracets.tv_usec += (maxtime%1000000);
							if(mac->gracets.tv_usec > 1000000) {
								mac->gracets.tv_usec -= 1000000;
								mac->gracets.tv_sec++;
							}
						}
						mac->last = mac->pos;
						mac->pos++;
						if(mac->pos >= WINDOWSIZE) mac->pos = 0;
						break;
					}
				}
			}
		} else {
			gettimeofday(&ts, NULL);
		}
		
		for(mac=jl_iter_init(&iter, macs);mac;mac=jl_iter(&iter)) {
			int first;
			uint64_t wt;
			uint64_t pps;
			int prevloss;
			
			if(mac->count < WINDOWSIZE) continue;
			
			first = (mac->last + 1) % WINDOWSIZE;
			prevloss = mac->loss;
			
			/* window size in time */
			wt = mac->ts[mac->last].tv_sec - mac->ts[first].tv_sec;
			wt *= 1000000;
			if(wt > 0) {
				wt -= (uint64_t) 1000000;
				wt += ((mac->ts[mac->last].tv_usec + (uint64_t) 1000000) - mac->ts[first].tv_usec);
			} else {
				wt += mac->ts[mac->last].tv_usec - mac->ts[first].tv_usec;
			}
			
			/* nr of packets during window (WINDOWSIZE-1) */

			/* pps = (WINDOWSIZE-1)/time */
			wt = wt / SCALINGFACTOR;
			pps = ((WINDOWSIZE-1)*1000000)/wt;
			
			/* loss = 1 - (pps / mac->rate) */
			mac->loss = (1*SCALINGFACTOR) - (pps / mac->rate);
			if(abs(prevloss - mac->loss) > 1) {
				mac_loss(mac, &ts);
			} else {
				if( (ts.tv_sec > mac->lastlossreport)&&(mac->lastloss != mac->loss) && (mac->lastloss > 0) && (mac->loss < 1)) {
					mac_loss(mac, &ts);
				}
			}
		}
		for(mac=jl_iter_init(&iter, macs);mac;mac=jl_iter(&iter)) {
			if(mac->count == 0) {
				mac_status_fail(mac, &ts);
				continue;
			}
			
			/* 
			 * have we reach gracets?
			 */
			if(mac->gracets.tv_sec > ts.tv_sec) {
				mac_status_ok(mac, &ts);
				continue;
			}
			if(mac->gracets.tv_sec < ts.tv_sec) {
				mac_status_fail(mac, &ts);
				continue;
				}
			if(mac->gracets.tv_usec < ts.tv_usec) {
				mac_status_fail(mac, &ts);
				continue;
			}
			mac_status_ok(mac, &ts);
		}
	}
}

void sender(struct jlhead *macs, int rate)
{
	struct mac *mac;
        ssize_t rc;
	struct timeval now, next;
	uint64_t step = 1000000/rate;
	
	if(gettimeofday(&now, NULL)) {
		if(conf.verbose) fprintf(stderr, "gettimeofday failed\n");
	}
	
	memcpy(&next, &now, sizeof(now));
	
	while(1) {
		next.tv_usec += step;
		if(next.tv_usec > (uint64_t)1000000) {
			next.tv_sec++;
			next.tv_usec -= (uint64_t)1000000;
		}
		jl_foreach(macs, mac) {
			rc = sendto( conf.fd, mac->data, 4, 0,
				     (struct sockaddr *)&mac->addr, sizeof(struct sockaddr_ll));
			if(rc >= 0)
				mac->count++;
			if(rc == -1) {
				if(conf.verbose) fprintf(stderr, "sendto(%d) failed: %s\n", mac->addr.sll_ifindex, strerror(errno));
			}
		}
		
		if(gettimeofday(&now, NULL)) {
			if(conf.verbose) fprintf(stderr, "gettimeofday failed\n");
		}
		if( (now.tv_sec > next.tv_sec) ||
		    ( (now.tv_sec == next.tv_sec) && (now.tv_usec > next.tv_usec) ) ) {
			char buf[64];
			uint64_t ms;
			ms = (now.tv_sec - next.tv_sec) * 1000ULL;
			if(now.tv_sec == next.tv_sec)
				ms += (now.tv_usec -  next.tv_usec)/1000;
			else {
				if(now.tv_usec > next.tv_usec)
					ms += (now.tv_usec -  next.tv_usec)/1000;
				else
					ms -= (next.tv_usec -  now.tv_usec)/1000;
			}	
			snprintf(buf, sizeof(buf), "failed to keep up send rate: %llums overdue", ms);
			if(conf.verbose) fprintf(stderr, "%s\n", buf);
			logmsg((void*)0, buf, &now, 0);
			if(conf.exec) {
				snprintf(buf, sizeof(buf), "%llu", ms);
				event((void*)0, "OVERDUE", &now, 0, buf);
			}
			memcpy(&next, &now, sizeof(now));
			continue;
		}
		{
			struct timespec req;
			req.tv_sec = next.tv_sec - now.tv_sec;
			if(now.tv_usec > next.tv_usec) {
				req.tv_nsec = ((uint64_t)1000000 - now.tv_usec) + next.tv_usec;
				req.tv_sec--;
			} else {
				req.tv_nsec = next.tv_usec - now.tv_usec;
			}
			
			req.tv_nsec *= (uint64_t)1000;
			if(-1 == nanosleep(&req, NULL)) {
				if(conf.verbose) fprintf(stderr, "nanosleep failed\n");
			}
		}
	}
}

void opensyslog()
{
	char buf[64];
	snprintf(buf, sizeof(buf)-1, "ethspray[%d]", getpid());
	openlog(strdup(buf), 0, conf.facility);
}

int main(int argc, char **argv)
{
	int err = 0;
	int rate = 10;
	struct jlhead *macs;

	macs = jl_new();
	conf.facility = LOG_DAEMON;
	conf.nr_allow_loss = 3;
	conf.recoverytime = 200;
	conf.description = "::";
	
	if(jelopt(argv, 'h', "help", 0, &err)) {
	usage:
		printf("ethspray [-v] rx|tx DEV:MAC [DEV:MAC]*\n"
		       " -v              be verbose (also keeps process in foreground)\n"
		       " -r --rate       packets per second [10]\n"
		       " -l --loss N     packet loss trigger level [3]\n"
		       " -R --rtime N    recoverytime in seconds after reconnect until recovered [200]\n"
		       " -F              stay in foreground (no daemon)\n"
		       " -t TEXT         user provided description [::]\n"
		       " -e --exec PRG   run this program to handle events\n"
		       "\n"
		       "Ethspray has two modes: 'rx' and 'tx'\n"
		       "\n"
		       "rx mode is the receiver mode.\n"
		       "The receiver will expect packets from the MAC-addresses listed.\n"
		       "If sequential packet loss is detected the alarm function will trigger.\n"
		       "\n"
		       "tx mode is the transmitter mode.\n"
		       "The transmitter will send packets to all MAC-addresses listed at the given rate.\n"
		       "If the transmitter fails to keep up the sending rate an OVERDUE event triggers.\n"
		       "\n"
		       "Exec program:\n"
		       "The program/script given to the '-e' switch receives event information in argv.\n"
		       " $1 = MAC\n"
		       " $2 = RESET|FAIL|RECONNECT|RECOVER|LOSS|OVERDUE\n"
		       "      RESET is sent at program startup.\n"
		       " $3 = HH:MM:SS.ms\n"
		       " $4 = provided description (see -t)\n"
		       " $5 = (LOSS PERCENTAGE|OVERDUETIME_MS)\n"
			);
		exit(0);
	}
	
	while(jelopt(argv, 'v', "verbose", 0, &err)) conf.verbose++;
	while(jelopt(argv, 'F', (void*)0, 0, &err)) conf.foreground=1;
	while(jelopt(argv, 'e', "exec", &conf.exec, &err));
	while(jelopt(argv, 't', (void*)0, &conf.description, &err));
	while(jelopt_int(argv, 'r', "rate", &rate, &err));
	while(jelopt_int(argv, 'l', "loss", &conf.nr_allow_loss, &err));
	while(jelopt_int(argv, 'R', "rtime", &conf.recoverytime, &err));
	argc = jelopt_final(argv, &err);
	if(err) {
		fprintf(stderr, "ethspray: Syntax error in options.\n");
		exit(2);
	}
	
	if(argc <= 2) {
		fprintf(stderr, "ethspray: unsufficient args.\n");
		exit(2);
	}
	if(strcmp(argv[1], "rx") && strcmp(argv[1], "tx")) {
		fprintf(stderr, "ethspray: only tx|rx accepted\n");
		exit(2);
	}

	while(argc > 2) {
		struct mac *mac;
		char *device, *macaddr;

		if(conf.verbose) printf("mac %s rate %d pkts/s\n", argv[argc-1], rate);
		mac = malloc(sizeof(struct mac));
		memset(mac, 0, sizeof(struct mac));
		mac->addr.sll_family = AF_PACKET;
		mac->addr.sll_protocol = htons(ETH_P_ETHSPRAY); /* Must set protocol here!  else 0x0000 will be used */
		macaddr = strchr(argv[argc-1], ':');
		if(!macaddr) {
			fprintf(stderr, "missing mac addr for %s\n", argv[argc-1]);
			exit(1);
		}
		*macaddr = 0;
		macaddr++;
		device = argv[argc-1];
		mac->addr.sll_ifindex = if_nametoindex(device);
		if(!mac->addr.sll_ifindex)
		{
			fprintf(stderr, "no such device %s\n", device);
			exit(1);
		}
		eth_aton(macaddr, mac->addr.sll_addr);
		mac->rate = rate;
		mac->loss = 0;
		mac->data[0] = 'n';
		mac->data[1] = '1';
		mac->data[2] = mac->rate >> 8;
		mac->data[3] = mac->rate & 0xff;
		gettimeofday(&mac->gracets, NULL);
		mac->gracets.tv_sec += 5; /* no events for 5 seconds */
		jl_append(macs, mac);
		argc--;
	}
	
	{
		struct sigaction act;
		memset(&act, 0, sizeof(act));
		act.sa_handler = SIG_DFL;
		act.sa_flags = SA_NOCLDSTOP|SA_NOCLDWAIT;
		sigaction(SIGCHLD, &act, NULL);
	}
	
	if(!strcmp(argv[1], "rx")) {
		struct mac *mac;
		struct sockaddr_ll my_addr;

		jl_foreach(macs, mac) {
			mac->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ETHSPRAY));
			if(mac->fd == -1) {
				fprintf(stderr, "ethspray: PACKET socket creation failed\n");
				exit(2);
			}
			memset( &my_addr, 0, sizeof(my_addr));
			my_addr.sll_family = AF_PACKET;
			my_addr.sll_protocol = htons(ETH_P_ETHSPRAY);
			my_addr.sll_ifindex = mac->addr.sll_ifindex;
			if(bind(mac->fd, (struct sockaddr *)&my_addr, sizeof( struct sockaddr_ll))) {
				fprintf(stderr, "ethspray: bind failed\n");
				exit(2);
			}
			if(conf.verbose > 2) printf("bound to ifindex %d\n", mac->addr.sll_ifindex);
		}
		if(!conf.verbose) {
			if(conf.foreground) {
				int fd;
				umask(0);
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
			} else {
				daemonize();
			}
		}
		opensyslog();
		receiver(macs);
		exit(1);
	}
	if(!strcmp(argv[1], "tx")) {
		conf.fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ETHSPRAY));
		if(conf.fd == -1) {
			fprintf(stderr, "ethspray: PACKET socket creation failed\n");
			exit(2);
		}
		if(!conf.verbose) {
			if(conf.foreground) {
				int fd;
				umask(0);
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
			} else {
				daemonize();
			}
		}
		opensyslog();
		sender(macs, rate);
		exit(1);
	}
	return 2;
}
