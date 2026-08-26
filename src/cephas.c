/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>

#include <libkyrka/libnyfe.h>
#include <libkyrka/libkyrka.h>

#include "wordlist.h"

/* The KDF label used when deriving our final shared secret. */
#define CEPHAS_KDF_LABEL	"CEPHAS.KDF.SHARED.SECRET"

/* The KDF label used for deriving key material from a passphrase. */
#define CEPHAS_PASS_LABEL	"CEPHAS.PBKDF.PASSPHRASE"

/* The mode we are currently running under. */
#define CEPHAS_MODE_SENDING	1
#define CEPHAS_MODE_RECEIVING	2

/* Helpful macros. */
#define errno_s			strerror(errno)

#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			printf("precondition failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
			abort();					\
		}							\
	} while (0)

/*
 * A protocol message used to transfer data between the two peers.
 *
 * This is either a heartbeat message to help with NAT traversal and
 * keep-alive or the actual contents of the KEK we are trying to transfer.
 */
#define CEPHAS_MSG_HEARTBEAT		1
#define CEPHAS_MSG_KEK_DATA		2
#define CEPHAS_MSG_ACK			3

struct cephas_msg {
	u_int8_t	type;
	u_int8_t	kek[32];
} __attribute__((packed));

static void	usage(void) __attribute__((noreturn));
static void	fatal(const char *, ...) __attribute__((format (printf, 1, 2)))
		    __attribute__((noreturn));

static void	cephas_signal_trap(int);
static void	cephas_signal_hdlr(int);
static void	cephas_signal_memfault(int);

static void	cephas_secret_derive(u_int8_t *, size_t);
static void	cephas_passphrase_from_words(char *, size_t);

static void	cephas_run(void);
static void	cephas_send_ack(void);
static void	cephas_send_kek(void);
static void	cephas_socket_read(void);
static void	cephas_validate_opt(void);
static void	cephas_send_heartbeat(void);
static void	cephas_configure_tunnel(void);
static void	cephas_parse_cathedral(char *);
static void	cephas_passphrase_populate(char *, size_t);
static void	cephas_parse_mode(const char *, const char *);
static void	cephas_digest(const char *, const void *, size_t);

static void	cephas_tunnel_event(KYRKA *, union kyrka_event *, void *);
static void	cephas_heaven_ifc(struct kyrka_packet *, u_int64_t, void *);
static void	cephas_purgatory_ifc(struct kyrka_packet *, u_int64_t, void *);
static void	cephas_cathedral_ifc(struct kyrka_packet *, u_int64_t, void *);

static const char	*cephas_word_select(void);
static int		cephas_word_exists(const char *);
static size_t		cephas_word_autocomplete(char *, size_t, size_t);

/* Local state. */
static struct {
	int				fd;
	struct kyrka_cathedral_cfg	cfg;
	KYRKA				*ctx;
	u_int32_t			remote;

	int				mode;
	int				online;
	int				running;

	const char			*path;
	u_int8_t			kek[32];

	struct sockaddr_in		peer;
	struct sockaddr_in		cathedral;
} state;

/* The most useful of helps. */
static void
usage(void)
{
	printf("Usage: cephas [opt] [ip:port] [send <file> | recv <file>]\n");
	printf("Options:\n");
	printf("    -l    Hexadecimal local cs id\n");
	printf("    -r    Hexadecimal remote cs id\n");
	printf("    -f    Hexadecimal flock\n");
	printf("    -t    Hexadecimal tunnel id\n");
	printf("    -o    The COSK path\n");
	printf("    -s    The cathedral secret path\n");
	exit(1);
}

/*
 * Parse options, get our libkyrka context configured and attempt
 * to establish the tunnel to the peer.
 */
int
main(int argc, char **argv)
{
	int		ch;

	nyfe_zeroize_register(&state, sizeof(state));

	state.remote = 0;
	state.online = 0;

	memset(&state.cfg, 0, sizeof(state.cfg));

	state.cfg.send = cephas_cathedral_ifc;

	while ((ch = getopt(argc, argv, "f:l:t:r:s:o:")) != -1) {
		switch (ch) {
		case 'f':
			if (sscanf(optarg, "%" PRIx64,
			    &state.cfg.flock_src) != 1)
				fatal("-f %s invalid", optarg);
			break;
		case 'l':
			if (sscanf(optarg, "%08x", &state.cfg.identity) != 1)
				fatal("-l %s invalid", optarg);
			break;
		case 't':
			if (sscanf(optarg, "%hx", &state.cfg.tunnel) != 1)
				fatal("-t %s invalid", optarg);
			break;
		case 'r':
			if (sscanf(optarg, "%08x", &state.remote) != 1)
				fatal("-r %s invalid", optarg);
			break;
		case 's':
			state.cfg.secret = optarg;
			break;
		case 'o':
			state.cfg.cosk = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 3)
		usage();

	cephas_validate_opt();

	cephas_signal_trap(SIGINT);
	cephas_signal_trap(SIGHUP);
	cephas_signal_trap(SIGQUIT);
	cephas_signal_trap(SIGTERM);

	cephas_parse_cathedral(argv[0]);
	cephas_parse_mode(argv[1], argv[2]);

	cephas_configure_tunnel();
	cephas_run();

	kyrka_ctx_free(state.ctx);

	nyfe_zeroize(&state, sizeof(state));
	nyfe_zeroize_all();

	return (0);
}

/*
 * Let the given signal be caught by our signal handler.
 */
static void
cephas_signal_trap(int sig)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));

	if (sig == SIGSEGV)
		sa.sa_handler = cephas_signal_memfault;
	else
		sa.sa_handler = cephas_signal_hdlr;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset: %s", errno_s);

	if (sigaction(sig, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
}

/*
 * Signal handler for anything except SIGSEGV.
 */
static void
cephas_signal_hdlr(int sig)
{
	(void)sig;
}

/*
 * Signal handler for SIGSEGV, we just hard die after wiping everything.
 */
static void
cephas_signal_memfault(int sig)
{
	/* Erases all nyfe_zeroize_register()'d memory. */
	kyrka_emergency_erase();
}

/*
 * Validate that we have all the required config options to
 * be able to run properly.
 */
static void
cephas_validate_opt(void)
{
	if (state.cfg.identity == 0)
		fatal("no local identity (-l) set");

	if (state.cfg.flock_src == 0)
		fatal("no flock (-f) set");

	if (state.cfg.tunnel == 0)
		fatal("no tunnel (-t) set");

	if (state.cfg.secret == NULL)
		fatal("no cathedral secret (-s) set");

	if (state.cfg.cosk == NULL)
		fatal("no cosk private key (-o) set");

	if (state.remote == 0)
		fatal("no remote identity (-r) set");
}

/*
 * Configure our libkyrka context.
 */
static void
cephas_configure_tunnel(void)
{
	u_int8_t	secret[32];

	if ((state.ctx = kyrka_ctx_alloc(cephas_tunnel_event, NULL)) == NULL)
		fatal("failed to create libkyrka context");

	if (kyrka_shroud_enable(state.ctx) == -1)
		fatal("failed to enable shroud");

	if (kyrka_mtu_size(state.ctx, 800) == -1)
		fatal("failed to set mtu");

	if (kyrka_heaven_ifc(state.ctx, cephas_heaven_ifc, NULL) == -1)
		fatal("kyrka_heaven_ifc: %d", kyrka_last_error(state.ctx));

	if (kyrka_purgatory_ifc(state.ctx, cephas_purgatory_ifc, NULL) == -1)
		fatal("kyrka_purgatory_ifc: %d", kyrka_last_error(state.ctx));

	nyfe_zeroize_register(secret, sizeof(secret));
	cephas_secret_derive(secret, sizeof(secret));

	if (kyrka_secret_load(state.ctx, secret, sizeof(secret)) == -1)
		fatal("kyrka_secret_load: %d", kyrka_last_error(state.ctx));

	nyfe_zeroize(secret, sizeof(secret));

	if (kyrka_cathedral_config(state.ctx, &state.cfg) == -1) {
		fatal("kyrka_cathedral_config: %d",
		    kyrka_last_error(state.ctx));
	}
}

/*
 * Wait for incoming packets and read them when required.
 *
 * We also do book keeping for the tunnel here every second where
 * we do key management, notify the cathedral about our presence and
 * if the tunnel is alive, send heartbeats.
 */
static void
cephas_run(void)
{
	struct timespec		ts;
	struct pollfd		pfd;
	int			nfd;
	time_t			last;

	if ((state.fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket");

	pfd.fd = state.fd;
	pfd.events = POLLIN;

	last = 0;
	state.running = 1;

	printf("Waiting for peer ...\n");

	while (state.running) {
		if ((nfd = poll(&pfd, 1, 1000)) == -1)
			fatal("poll: %s", errno_s);

		if (nfd > 0) {
			if (pfd.revents & POLLIN)
				cephas_socket_read();
		}

		(void)clock_gettime(CLOCK_MONOTONIC, &ts);

		if ((ts.tv_sec - last) >= 1) {
			last = ts.tv_sec;

			if (kyrka_cathedral_notify(state.ctx) == -1) {
				printf("kyrka_cathedral_notify: %d\n",
				    kyrka_last_error(state.ctx));
			}

			if (kyrka_key_manage(state.ctx) == -1) {
				printf("kyrka_key_manage: %d\n",
				    kyrka_last_error(state.ctx));
			}

			if (state.online) {
				if (state.mode == CEPHAS_MODE_SENDING) {
					cephas_send_kek();
				} else {
					cephas_send_heartbeat();
				}
			}
		}
	}

	if (state.mode == CEPHAS_MODE_RECEIVING) {
		printf("KEK successfully received\n");
	} else {
		cephas_digest("kek-digest", state.kek, sizeof(state.kek));
		printf("KEK successfully sent to peer\n");
	}
}

/*
 * Attempt to read from our socket and push it into the libkyrka tunnel 
 * context so it can handle the packets.
 */
static void
cephas_socket_read(void)
{
	ssize_t			ret;
	size_t			len;
	struct kyrka_packet	pkt;
	void			*ptr;

	for (;;) {
		if ((ptr = kyrka_packet_recvbuf(state.ctx, &pkt, &len)) == NULL)
			fatal("failed to get recvbuf");

		ret = recv(state.fd, ptr, len, MSG_DONTWAIT);
		if (ret == -1) {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				return;
			fatal("recv: %s", errno_s);
		}

		if (ret == 0)
			continue;

		pkt.length = ret;
		pkt.shroud = KYRKA_PACKET_SHROUD_CATHEDRAL;

		if (kyrka_purgatory_input(state.ctx, &pkt) == -1) {
			if (kyrka_last_error(state.ctx) !=
			    KYRKA_ERROR_CATHEDRAL_CONFIG) {
				printf("kyrka_purgatory_input: %d\n",
				    kyrka_last_error(state.ctx));
			}
		}
	}
}

/*
 * Send the KEK to our peer.
 */
static void
cephas_send_kek(void)
{
	size_t			len;
	struct kyrka_packet	pkt;
	struct cephas_msg	*msg;

	PRECOND(state.mode == CEPHAS_MODE_SENDING);

	if ((msg = kyrka_packet_databuf(state.ctx, &pkt, &len)) == NULL)
		fatal("failed to get databuf for KEK");

	if (len < sizeof(*msg))
		fatal("not enough space for KEK");

	nyfe_zeroize_register(&pkt, sizeof(pkt));
	nyfe_mem_zero(msg, sizeof(*msg));

	msg->type = CEPHAS_MSG_KEK_DATA;
	nyfe_memcpy(msg->kek, state.kek, sizeof(state.kek));

	pkt.length = sizeof(*msg);
	pkt.shroud = KYRKA_PACKET_SHROUD_CATHEDRAL;

	if (kyrka_heaven_input(state.ctx, &pkt) == -1)
		fatal("kyrka_heaven_input: %d", kyrka_last_error(state.ctx));

	nyfe_zeroize(&pkt, sizeof(pkt));
}

/*
 * Send a burst of ACKs to our peer, we've gotten the KEK.
 */
static void
cephas_send_ack(void)
{
	int			i;
	struct kyrka_packet	pkt;
	size_t			len;
	struct cephas_msg	*msg;

	PRECOND(state.mode == CEPHAS_MODE_RECEIVING);

	if ((msg = kyrka_packet_databuf(state.ctx, &pkt, &len)) == NULL)
		fatal("failed to get databuf for ack");

	if (len < sizeof(*msg))
		fatal("not enough space for ACK");

	nyfe_mem_zero(msg, sizeof(*msg));
	msg->type = CEPHAS_MSG_ACK;

	pkt.length = sizeof(*msg);
	pkt.shroud = KYRKA_PACKET_SHROUD_CATHEDRAL;

	for (i = 0; i < 10; i++) {
		if (kyrka_heaven_input(state.ctx, &pkt) == -1) {
			fatal("kyrka_heaven_input: %d",
			    kyrka_last_error(state.ctx));
		}

		usleep(10000);
	}
}

/*
 * Send a heartbeat to our peer.
 */
static void
cephas_send_heartbeat(void)
{
	size_t			len;
	struct kyrka_packet	pkt;
	struct cephas_msg	*msg;

	if ((msg = kyrka_packet_databuf(state.ctx, &pkt, &len)) == NULL)
		fatal("failed to get hb databuf");

	if (len < sizeof(*msg))
		fatal("not enough space for heartbeat");

	nyfe_mem_zero(msg, sizeof(*msg));
	msg->type = CEPHAS_MSG_HEARTBEAT;

	pkt.length = sizeof(*msg);
	pkt.shroud = KYRKA_PACKET_SHROUD_CATHEDRAL;

	if (kyrka_heaven_input(state.ctx, &pkt) == -1)
		fatal("kyrka_heaven_input: %d", kyrka_last_error(state.ctx));
}

/*
 * Callback from libkyrka when a tunnel even occurred.
 */
static void
cephas_tunnel_event(KYRKA *ctx, union kyrka_event *evt, void *udata)
{
	PRECOND(ctx == state.ctx);
	PRECOND(evt != NULL);
	PRECOND(udata == NULL);

	switch (evt->type) {
	case KYRKA_EVENT_KEYS_INFO:
		if (evt->keys.tx_spi != 0 && evt->keys.rx_spi != 0) {
			state.online = 1;
			printf("secure link established\n");
		}
		break;
	case KYRKA_EVENT_EXCHANGE_INFO:
		break;
	case KYRKA_EVENT_LOGMSG:
		printf("!! %s\n", evt->logmsg.log);
		break;
	case KYRKA_EVENT_PEER_DISCOVERY:
		if (state.peer.sin_addr.s_addr != evt->peer.ip ||
		    state.peer.sin_port != evt->peer.port) {
			state.peer.sin_port = evt->peer.port;
			state.peer.sin_addr.s_addr = evt->peer.ip;
		}
		break;
	default:
		printf("unknown tunnel event %u\n", evt->type);
		break;
	}
}

/*
 * Callback from libkyrka when there is plaintext data to be handled.
 */
static void
cephas_heaven_ifc(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	int				fd;
	const struct cephas_msg		*msg;

	PRECOND(pkt != NULL);
	PRECOND(udata == NULL);

	if (pkt->length != sizeof(*msg))
		fatal("peer sent wrong sized msg (len: %zu)", pkt->length);

	if (state.online == 0)
		return;

	msg = kyrka_packet_data(pkt);

	switch (msg->type) {
	case CEPHAS_MSG_HEARTBEAT:
		break;
	case CEPHAS_MSG_KEK_DATA:
		if (state.mode != CEPHAS_MODE_RECEIVING)
			fatal("peer sent unexpected CEPHAS_MSG_KEK_DATA");

		fd = nyfe_file_open(state.path, NYFE_FILE_CREATE);
		nyfe_file_write(fd, msg->kek, sizeof(msg->kek));
		if (close(fd) == -1) {
			printf("close: %s\n", errno_s);
			(void)unlink(state.path);
		} else {
			cephas_digest("kek-digest", msg->kek, sizeof(msg->kek));
			cephas_send_ack();
			state.running = 0;
		}
		break;
	case CEPHAS_MSG_ACK:
		if (state.mode != CEPHAS_MODE_SENDING)
			fatal("peer sent unexpected CEPHAS_MSG_ACK");
		state.running = 0;
		break;
	default:
		fatal("peer sent unknown msg type (%u)\n", msg->type);
		break;
	}
}

/*
 * Callback from libkyrka when there is ciphertext to be sent.
 * We simply send it to our current known peer address.
 */
static void
cephas_purgatory_ifc(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	size_t		len;
	void		*data;

	PRECOND(pkt != NULL);
	PRECOND(udata == NULL);

	if ((data = kyrka_packet_sendbuf(state.ctx, pkt, &len)) == NULL)
		fatal("no sendbuf when sending to purgatory");

	if (sendto(state.fd, data, len, 0,
	    (const struct sockaddr *)&state.peer, sizeof(state.peer)) == -1)
		printf("sendto: %s\n", errno_s);
}

/*
 * Callback from libkyrka when there is ciphertext to be sent to our cathedral.
 */
static void
cephas_cathedral_ifc(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	size_t		len;
	void		*data;

	PRECOND(pkt != NULL);
	PRECOND(udata == NULL);

	if ((data = kyrka_packet_sendbuf(state.ctx, pkt, &len)) == NULL)
		fatal("no sendbuf when sending to cathedral");

	if (sendto(state.fd, data, len, 0,
	    (const struct sockaddr *)&state.cathedral,
	    sizeof(state.cathedral)) == -1)
		printf("sendto: %s\n", errno_s);
}

/*
 * Display the SHA3-256 digest for some data.
 */
static void
cephas_digest(const char *name, const void *data, size_t len)
{
	size_t			idx;
	struct nyfe_sha3	ctx;
	u_int8_t		digest[32];

	PRECOND(name != NULL);
	PRECOND(data != NULL);
	PRECOND(len > 0);

	nyfe_sha3_init256(&ctx);
	nyfe_sha3_update(&ctx, data, len);
	nyfe_sha3_final(&ctx, digest, sizeof(digest));

	printf("%s = ", name);
	for (idx = 0; idx < sizeof(digest); idx++)
		printf("%02x", digest[idx]);
	printf("\n");
}

/*
 * Derive the shared secret from a user passphrase.
 *
 * We first run the passphrase through nyfe_passphrase_kdf() which
 * produces 64-bytes of IKM.
 *
 * This IKM is then run through KMAC256() to produce the shared
 * secret in the following manner to produce the tunnel shared secret:
 *
 *    X = len(flock_a) || flock_a || len(flock_b) || flock_b ||
 *        len(identity_a) || identity_a || len(identity_b) || identity_b ||
 *        len(peer_a) || peer_a || len(peer_b) || peer_b
 *
 *    secret = KMAC256(ikm, "CEPHAS.KDF.SHARED.SECRET", X)
 *
 * Note that the tunnel shared secret is one of three inputs to the final
 * session key derivation, the other two parts are ECDH+ML-KEM-1024.
 */
static void
cephas_secret_derive(u_int8_t *secret, size_t len)
{
	struct nyfe_kmac256	kdf;
	char			pass[1024];
	u_int64_t		flock_a, flock_b;
	u_int8_t		okm[64], salt[32];
	u_int32_t		identity_a, identity_b;
	u_int8_t		ilen, peer_a, peer_b, tmp;

	PRECOND(secret != NULL);
	PRECOND(len == 32);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(pass, sizeof(pass));

	nyfe_mem_zero(pass, sizeof(pass));
	nyfe_mem_zero(salt, sizeof(salt));

	if (state.mode == CEPHAS_MODE_SENDING)
		cephas_passphrase_populate(pass, sizeof(pass));
	else
		cephas_passphrase_from_words(pass, sizeof(pass));

	printf("Deriving initial key from passphrase ... ");
	fflush(stdout);

	nyfe_passphrase_kdf(pass, strlen(pass), salt, sizeof(salt),
	    okm, sizeof(okm), CEPHAS_PASS_LABEL, sizeof(CEPHAS_PASS_LABEL) - 1);

	printf("done\n");

	nyfe_zeroize(pass, sizeof(pass));

	if (state.cfg.identity < state.remote) {
		identity_a = htobe32(state.cfg.identity);
		identity_b = htobe32(state.remote);
	} else {
		identity_a = htobe32(state.remote);
		identity_b = htobe32(state.cfg.identity);
	}

	peer_a = (state.cfg.tunnel >> 8) & 0xff;
	peer_b = state.cfg.tunnel & 0xff;

	if (peer_a > peer_b) {
		tmp = peer_a;
		peer_a = peer_b;
		peer_b = tmp;
	}

	if (state.cfg.flock_src < state.cfg.flock_dst) {
		flock_a = htobe64(state.cfg.flock_src);
		flock_b = htobe64(state.cfg.flock_dst);
	} else {
		flock_a = htobe64(state.cfg.flock_dst);
		flock_b = htobe64(state.cfg.flock_src);
	}

	nyfe_kmac256_init(&kdf, okm, sizeof(okm),
	    CEPHAS_KDF_LABEL, sizeof(CEPHAS_KDF_LABEL) - 1);
	nyfe_zeroize(okm, sizeof(okm));

	ilen = 8;
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &flock_a, sizeof(flock_a));

	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &flock_b, sizeof(flock_b));

	ilen = 4;
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &identity_a, sizeof(identity_a));

	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &identity_b, sizeof(identity_b));

	ilen = 1;
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &peer_a, sizeof(peer_a));

	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &peer_b, sizeof(peer_b));

	nyfe_kmac256_final(&kdf, secret, len);
	nyfe_mem_zero(&kdf, sizeof(kdf));
}

/*
 * Construct the passphrase from words entered by the user.
 */
static void
cephas_passphrase_from_words(char *pass, size_t len)
{
	char			word[32];
	struct termios		cur, old;
	size_t			off, poff;
	int			fd, i, slen;

	PRECOND(pass != NULL);
	PRECOND(len > 0);

	printf("Please enter the words as obtained from your peer\n");
	printf("in a one-by-one fashion. You can press TAB to auto-complete\n");
	printf("words or CTRL-C to exit the transfer.\n");

	if ((fd = open(_PATH_TTY, O_RDWR)) == -1)
		fatal("open(%s): %s", _PATH_TTY, errno_s);

	if (tcgetattr(fd, &old) == -1)
		fatal("tcgetattr: %s", errno_s);

	cur = old;
	cur.c_cc[VMIN] = 1;
	cur.c_cc[VTIME] = 0;
	cur.c_oflag &= ~ONLCR;
	cur.c_iflag &= ~ONLCR;
	cur.c_lflag &= ~(ICANON | ECHO | ECHOE);

	if (tcsetattr(fd, TCSAFLUSH, &cur) == -1) {
		(void)tcsetattr(fd, TCSANOW, &old);
		fatal("tcsetattr: %s", errno_s);
	}

	poff = 0;
	memset(pass, 0, len);

	for (i = 0; i < 20; i++) {
		off = 0;
		memset(word, 0, sizeof(word));

		for (;;) {
			printf("\33[2K\r");
			printf("Enter word #%02d: %.*s", i, (int)off, word);
			fflush(stdout);

			if (read(fd, &word[off], 1) == -1) {
				(void)tcsetattr(fd, TCSANOW, &old);
				fatal("failed to read passphrase: %s", errno_s);
			}

			if (word[off] == '\n') {
				word[off] = '\0';
				if (cephas_word_exists(word) == -1) {
					printf("\n\r%s not found\n", word);
					continue;
				}

				break;
			}

			switch (word[off]) {
			case '\b':
			case 0x7f:
				if (off > 0)
					off--;
				break;
			case 0x17:
				off = 0;
				word[0] = '\0';
				break;
			case '\t':
				if (off > 2) {
					off = cephas_word_autocomplete(word,
					    off, sizeof(word));
				}
				break;
			default:
				off++;
				break;
			}
		}

		slen = snprintf(pass + poff, len - poff, "%s ", word);
		if (slen == -1 || (size_t)slen >= (len - poff))
			fatal("failed to construct passphrase");

		poff += slen;
	}

	pass[poff] = '\0';

	if (tcsetattr(fd, TCSANOW, &old) == -1)
		fatal("tcsetattr: %s", errno_s);

	(void)close(fd);

	printf("\n");
}

/*
 * Populate the passphrase using randomly selected words from the
 * eff its diceware word list.
 *
 * We generate 20 words which is approx. 256-bits of entropy.
 */
static void
cephas_passphrase_populate(char *pass, size_t inlen)
{
	size_t		off;
	int		i, len;
	const char	*words[20];

	PRECOND(pass != NULL);
	PRECOND(inlen > 0);

	off = 0;

	for (i = 0; i < 20; i++) {
		words[i] = cephas_word_select();

		len = snprintf(pass + off, inlen - off, "%s ", words[i]);
		if (len == -1 || (size_t)len >= (inlen - off))
			fatal("failed to construct passphrase");

		off += len;
	}

	pass[off] = '\0';

	printf("\n");
	printf("The words to be shared with your peer are:\n");
	printf("\n");

	for (i = 0; i < 5; i++) {
		printf("%s %s %s %s\n",
		    words[(i * 4) + 0],
		    words[(i * 4) + 1],
		    words[(i * 4) + 2],
		    words[(i * 4) + 3]);
	}

	printf("\n");
}

/*
 * Select a random word from our cephas_wordlist.
 */
static const char *
cephas_word_select(void)
{
	u_int32_t		idx, min;
	const u_int32_t		upper = CEPHAS_WORD_COUNT;

	min = -upper % upper;

	for (;;) {
		nyfe_random_bytes(&idx, sizeof(idx));
		if (idx >= min)
			break;
	}

	idx = idx % upper;

	return (cephas_words[idx]);
}

/*
 * Show autocompletion suggestions or even fully autocomplete the
 * word if no alternatives were available.
 */
static size_t
cephas_word_autocomplete(char *word, size_t off, size_t max)
{
	const char	*last;
	int		idx, len, matches;

	PRECOND(word != NULL);
	PRECOND(off < max);
	PRECOND(off <= INT_MAX);

	last = NULL;
	matches = 0;

	for (idx = 0; idx < CEPHAS_WORD_COUNT; idx++) {
		if (strlen(cephas_words[idx]) < off)
			continue;

		if (!memcmp(cephas_words[idx], word, off)) {
			if (matches == 0)
				printf("\r\n");
			matches++;
			last = cephas_words[idx];
			printf("\r%s\n", cephas_words[idx]);
		}
	}

	if (matches == 1) {
		len = snprintf(word, max, "%s", last);
		if (len == -1 || (size_t)len >= max)
			fatal("word does not fit somehow");
	} else {
		len = off;
	}

	return (len);
}

/*
 * Check if the given word exists in the word list.
 */
static int
cephas_word_exists(const char *word)
{
	size_t		idx;

	PRECOND(word != NULL);

	for (idx = 0; idx < CEPHAS_WORD_COUNT; idx++) {
		if (!strcmp(word, cephas_words[idx]))
			return (0);
	}

	return (-1);
}

/*
 * Parse the given cathedral address (in ip:port format) into the
 * cathedral sockaddr_in.
 *
 * We also use it as the initial peer address.
 */
static void
cephas_parse_cathedral(char *host)
{
	int			ret;
	char			*port;
	struct addrinfo		hints, *res, *rp;

	PRECOND(host != NULL);

	if ((port = strchr(host, ':')) == NULL)
		fatal("missing port, address format must be ip:port");

	*(port)++ = '\0';

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	if ((ret = getaddrinfo(host, port, &hints, &res)) != 0)
		fatal("cathedral '%s': %s", host, gai_strerror(ret));

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET && rp->ai_socktype == SOCK_DGRAM)
			break;
	}

	if (rp == NULL)
		fatal("cathedral '%s' failed to resolve", host);

	memcpy(&state.cathedral, rp->ai_addr, sizeof(state.cathedral));
	memcpy(&state.peer, &state.cathedral, sizeof(state.cathedral));
}

/*
 * Check that the requested mode is valid, and remember the path we
 * are reading/writing. We make sure the path is valid for the requested
 * operation before continuing.
 */
static void
cephas_parse_mode(const char *modestr, const char *path)
{
	int			fd;
	struct stat		st;

	PRECOND(modestr != NULL);
	PRECOND(path != NULL);

	if (!strcmp(modestr, "send")) {
		state.mode = CEPHAS_MODE_SENDING;
	} else if (!strcmp(modestr, "recv")) {
		state.mode = CEPHAS_MODE_RECEIVING;
	} else {
		fatal("unknown mode '%s'", modestr);
	}

	switch (state.mode) {
	case CEPHAS_MODE_SENDING:
		if (access(path, R_OK) == -1)
			fatal("cannot read '%s': %s", path, errno_s);
		if (lstat(path, &st) == -1)
			fatal("stat(%s): %s", path, errno_s);
		if (!S_ISREG(st.st_mode))
			fatal("'%s' is not a file", path);

		fd = nyfe_file_open(path, NYFE_FILE_READ);

		if (nyfe_file_read(fd, state.kek,
		    sizeof(state.kek)) != sizeof(state.kek))
			fatal("failed to read kek data");
		(void)close(fd);
		break;
	case CEPHAS_MODE_RECEIVING:
		if (lstat(path, &st) != -1)
			fatal("%s exists", path);
		state.path = path;
		break;
	default:
		fatal("mode somehow messed up (%d)", state.mode);
	}
}

/* Bad juju happened. */
static void
fatal(const char *fmt, ...)
{
	va_list		args;

	/* Erases all nyfe_zeroize_register()'d memory. */
	kyrka_emergency_erase();

	printf("fatal: ");

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	printf("\n");

	exit(1);
}
