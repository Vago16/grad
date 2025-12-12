#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>

/* 
 * Provided (GMP versions):
 *   read_mpz_hex(path, mpz_t out)
 *   write_mpz_hex(path, mpz_t val)
 *   read_buf_hex(path,&buf,&len)
 *   write_buf_hex(path, buf,len)
 *   rand_mpz_bits(mpz_t r, unsigned bits)            // uniform random of 'bits' bits
 *   rand_prime_bits(mpz_t p, unsigned bits)          // probable prime (uses mpz_nextprime)
 *   mpz_modinv_eea(mpz_t inv, const mpz_t a, const mpz_t m) // Extended Euclid inverse
 *   powmod_square_mul(mpz_t r,const mpz_t b,const mpz_t e,const mpz_t m) // square & multiply
 *   sha256_concat(a,alen,b,blen,out32)               // SHA-256 (minimal implementation)
 *   fdh_sha256_concat(a,alen,b,blen,out_len,out_buf) // FDH using SHA-256 blocks
 *   log_line(path,msg)
 */

/* NOTE: The SHA-256 implementation below is a compact, original implementation
 * written for this assignment based on the FIPS 180-4 specification. It is
 * NOT copied from external copyrighted sources. */

#include <stdint.h>
#include <unistd.h> /* getpid */
#include <openssl/sha.h> /* OpenSSL SHA-256 for hashing */

/* -------------------- File / String Utilities -------------------- */

/* Trim at first whitespace. Useful for line-based hex inputs. */
static void trim_first_ws(char *s) {
    for (size_t i = 0; s[i]; ++i) {
        char c = s[i];
        if (c==' ' || c=='\t' || c=='\r' || c=='\n') { s[i] = 0; return; }
    }
}

/* Read entire file into NUL-terminated malloc'ed buffer. NULL on error. */
static char* read_file_all(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = 0;
    return buf;
}

/* Keep only hex chars in place. */
static void keep_hex_only(char *s) {
    size_t j=0;
    for (size_t i=0; s[i]; ++i) {
        char c=s[i];
        if ((c>='0'&&c<='9')||(c>='A'&&c<='F')||(c>='a'&&c<='f')) s[j++]=c;
    }
    s[j]=0;
}

/* Read HEX integer -> BIGNUM*. */
/* Read HEX integer into mpz_t. Returns 1 on success, 0 on failure. */
static int read_mpz_hex(const char *path, mpz_t out) {
    char *file = read_file_all(path);
    if (!file) return 0;
    trim_first_ws(file);
    keep_hex_only(file);
    int ok = (mpz_set_str(out, file, 16) == 0);
    free(file);
    return ok;
}

/* Write mpz_t as UPPERCASE HEX + newline. */
static int write_mpz_hex(const char *path, const mpz_t val) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror("fopen"); return 0; }
    char *hex = mpz_get_str(NULL, 16, val);
    if (!hex) { fclose(f); return 0; }
    /* Uppercase */
    for (char *p = hex; *p; ++p) if (*p >= 'a' && *p <= 'f') *p = (char)(*p - 'a' + 'A');
    fprintf(f, "%s\n", hex);
    free(hex);
    fclose(f);
    return 1;
}

/* Read HEX buffer -> malloc'ed bytes. */
static int read_buf_hex(const char *path, unsigned char **out, size_t *outlen) {
    char *file = read_file_all(path);
    if (!file) return 0;
    trim_first_ws(file);
    keep_hex_only(file);
    size_t L = strlen(file);
    if (L % 2 != 0) { free(file); return 0; }
    size_t n = L/2;
    unsigned char *buf = (unsigned char*)malloc(n);
    if (!buf) { free(file); return 0; }
    for (size_t i=0;i<n;i++) {
        unsigned int v=0; sscanf(file+2*i, "%2x", &v); buf[i]=(unsigned char)v;
    }
    free(file);
    *out=buf; *outlen=n;
    return 1;
}

/* Write bytes as uppercase HEX + newline. */
static int write_buf_hex(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror("fopen"); return 0; }
    for (size_t i=0;i<len;i++) fprintf(f, "%02X", buf[i]);
    fprintf(f, "\n");
    fclose(f);
    return 1;
}

/* Generate 256-bit random; reduce mod 'mod' if non-NULL. */
/* Random number utilities using GMP's RNG. */
static gmp_randstate_t g_rand_state;
static int g_rand_init = 0;
static void ensure_rng() {
    if (g_rand_init) return;
    g_rand_init = 1;
    gmp_randinit_default(g_rand_state);
    /* Seed with time + pid */
    unsigned long seed = (unsigned long)time(NULL) ^ (unsigned long)getpid();
    mpz_t s; mpz_init_set_ui(s, seed); gmp_randseed(g_rand_state, s); mpz_clear(s);
}

static void rand_mpz_bits(mpz_t r, unsigned bits) {
    ensure_rng();
    mpz_urandomb(r, g_rand_state, bits);
}

static void rand_prime_bits(mpz_t p, unsigned bits) {
    /* Generate random odd of desired bits then take next prime. */
    ensure_rng();
    mpz_urandomb(p, g_rand_state, bits);
    mpz_setbit(p, bits-1);  /* ensure high bit set for size */
    mpz_setbit(p, 0);       /* ensure odd */
    mpz_nextprime(p, p);
}

/* 256-bit random optionally reduced modulo 'mod' if mod != NULL */
static void rand_mpz_256_mod(mpz_t r, const mpz_t mod, int use_mod) {
    rand_mpz_bits(r, 256);
    if (use_mod) mpz_mod(r, r, mod);
}

/* out32 = SHA256(a || b) */
/* -------------------- SHA-256 (OpenSSL) -------------------- */
static void sha256(const unsigned char *msg, size_t len, unsigned char out[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, msg, len);
    SHA256_Final(out, &ctx);
}

static int sha256_concat(const unsigned char *a, size_t alen,
                         const unsigned char *b, size_t blen,
                         unsigned char out[32]) {
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) return 0;
    if (alen) SHA256_Update(&ctx, a, alen);
    if (blen) SHA256_Update(&ctx, b, blen);
    if (!SHA256_Final(out, &ctx)) return 0;
    return 1;
}

/* Full-domain hash (FDH) using SHA-256.
 * final = H(m) || H(m||0x01) || H(m||0x02) ... until out_len bytes filled (truncate last).
 * This matches the description: hash(message) + hash(message||1) + hash(message||2) ...
 */
static int fdh_sha256(const unsigned char *m, size_t mlen, size_t out_len, unsigned char *out) {
    size_t produced = 0;
    unsigned char digest[32];
    /* First block: H(m) */
    sha256(m, mlen, digest);
    size_t take = out_len < 32 ? out_len : 32;
    memcpy(out, digest, take);
    produced += take;
    /* Subsequent blocks: H(m || counter) with 1-byte counter 0x01,0x02,... */
    unsigned char ctr;
    for (ctr = 1; produced < out_len; ++ctr) {
        SHA256_CTX ctx;
        if (!SHA256_Init(&ctx)) return 0;
        if (mlen) SHA256_Update(&ctx, m, mlen);
        SHA256_Update(&ctx, &ctr, 1);
        if (!SHA256_Final(digest, &ctx)) return 0;
        size_t need = out_len - produced;
        take = need < 32 ? need : 32;
        memcpy(out + produced, digest, take);
        produced += take;
    }
    return 1;
}

/* FDH over concatenation of two buffers: m = a || b */
static int fdh_sha256_concat(const unsigned char *a, size_t alen,
                             const unsigned char *b, size_t blen,
                             size_t out_len, unsigned char *out) {
    size_t produced = 0;
    unsigned char digest[32];
    /* First block: H(a||b) */
    {
        SHA256_CTX ctx;
        if (!SHA256_Init(&ctx)) return 0;
        if (alen) SHA256_Update(&ctx, a, alen);
        if (blen) SHA256_Update(&ctx, b, blen);
        if (!SHA256_Final(digest, &ctx)) return 0;
    }
    size_t take = out_len < 32 ? out_len : 32;
    memcpy(out, digest, take);
    produced += take;
    /* Subsequent blocks: H(a||b||counter) */
    for (unsigned char ctr = 1; produced < out_len; ++ctr) {
        SHA256_CTX ctx;
        if (!SHA256_Init(&ctx)) return 0;
        if (alen) SHA256_Update(&ctx, a, alen);
        if (blen) SHA256_Update(&ctx, b, blen);
        SHA256_Update(&ctx, &ctr, 1);
        if (!SHA256_Final(digest, &ctx)) return 0;
        size_t need = out_len - produced;
        take = need < 32 ? need : 32;
        memcpy(out + produced, digest, take);
        produced += take;
    }
    return 1;
}

/* -------------------- Number Theory Helpers -------------------- */
/* Extended Euclid modular inverse: inv = a^{-1} mod m (returns 1 success) */
static int mpz_modinv_eea(mpz_t inv, const mpz_t a, const mpz_t m) {
    mpz_t r0,r1,s0,s1,t0,t1,q,tmp;
    mpz_inits(r0,r1,s0,s1,t0,t1,q,tmp,NULL);
    mpz_set(r0, m); mpz_set(r1, a);
    mpz_set_ui(s0, 1); mpz_set_ui(s1, 0);
    mpz_set_ui(t0, 0); mpz_set_ui(t1, 1);
    while (mpz_cmp_ui(r1,0) != 0) {
        mpz_fdiv_q(q, r0, r1);
        mpz_set(tmp, r0); mpz_submul(tmp, q, r1); mpz_set(r0, r1); mpz_set(r1, tmp);
        mpz_set(tmp, s0); mpz_submul(tmp, q, s1); mpz_set(s0, s1); mpz_set(s1, tmp);
        mpz_set(tmp, t0); mpz_submul(tmp, q, t1); mpz_set(t0, t1); mpz_set(t1, tmp);
    }
    if (mpz_cmp_ui(r0,1) != 0) { mpz_clears(r0,r1,s0,s1,t0,t1,q,tmp,NULL); return 0; }
    if (mpz_cmp_ui(t0,0) < 0) mpz_add(t0, t0, m);
    mpz_set(inv, t0);
    mpz_clears(r0,r1,s0,s1,t0,t1,q,tmp,NULL); return 1;
}

/* Square and multiply: r = b^e mod m */
static void powmod_square_mul(mpz_t r, const mpz_t b, const mpz_t e, const mpz_t m) {
    mpz_t base; mpz_init(base); mpz_mod(base, b, m);
    mpz_set_ui(r, 1);
    size_t bits = mpz_sizeinbase(e, 2);
    for (ssize_t i = (ssize_t)bits - 1; i >= 0; --i) {
        mpz_mul(r, r, r); mpz_mod(r, r, m);
        if (mpz_tstbit(e, (mp_bitcnt_t)i)) {
            mpz_mul(r, r, base); mpz_mod(r, r, m);
        }
    }
    mpz_clear(base);
}

/* Append timestamped message to a log file. */
static void log_line(const char *path, const char *msg) {
    FILE *f = fopen(path, "a");
    if (!f) { perror("fopen"); return; }
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char ts[64]; strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
    fprintf(f, "[%s] %s\n", ts, msg);
    fclose(f);
}

