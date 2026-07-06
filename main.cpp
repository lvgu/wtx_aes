#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <windows.h>

#define CALG_SHA256 CALG_SHA_256

#define MAGIC "MYAE"
#define MAGIC_LEN 4
#define SALT_LEN 16
#define IV_LEN 16
#define HASH_LEN 32
#define BUFFER_SIZE 65536
#define PROGRESS_WIDTH 40
#define PROGRESS_UPDATE_INTERVAL 100

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbf597fc7, 0xc67178f2
};

static uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

static uint32_t sigma0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static uint32_t sigma1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static uint32_t gamma0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static uint32_t gamma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

static void sha256_init(uint32_t state[8]) {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}

static void sha256_transform(uint32_t *state, const uint8_t *block) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    uint32_t i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }

    for (i = 16; i < 64; i++) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + sigma1(e) + choose(e, f, g) + k[i] + w[i];
        t2 = sigma0(a) + majority(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_update(uint32_t state[8], const uint8_t *data, uint64_t len) {
    uint64_t i;
    for (i = 0; i + 64 <= len; i += 64) {
        sha256_transform(state, data + i);
    }
}

static void sha256_final(uint32_t state[8], uint8_t hash[32], uint64_t len) {
    uint8_t pad[128];
    uint64_t bits = len * 8;
    uint32_t i, j;

    pad[0] = 0x80;
    for (i = 1; i < 128; i++) pad[i] = 0;

    if (len % 64 < 56) i = 56 - (len % 64);
    else i = 120 - (len % 64);

    for (j = 0; j < 8; j++) pad[i + j] = (bits >> (56 - j * 8)) & 0xff;

    sha256_transform(state, pad);
    if (i > 56) sha256_transform(state, pad + 64);

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 4; j++) {
            hash[i * 4 + j] = (state[i] >> (24 - j * 8)) & 0xff;
        }
    }
}

static void sha256(const uint8_t *data, uint64_t len, uint8_t hash[32]) {
    uint32_t state[8];
    sha256_init(state);
    sha256_update(state, data, len);
    sha256_final(state, hash, len);
}

static int generate_random(uint8_t *buf, size_t len) {
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return 0;
    if (!CryptGenRandom(hProv, len, buf)) { CryptReleaseContext(hProv, 0); return 0; }
    CryptReleaseContext(hProv, 0);
    return 1;
}

static void show_progress(const char *stage, uint64_t processed, uint64_t total, uint64_t start_time, uint64_t *last_update) {
    uint32_t percent = total > 0 ? (uint32_t)((processed * 100) / total) : 0;
    if (processed == total) percent = 100;

    uint64_t current_time = GetTickCount64();
    
    if (processed != total && current_time - *last_update < 100) {
        return;
    }
    *last_update = current_time;

    uint64_t elapsed_ms = current_time - start_time;
    
    double mb_processed = (double)processed / (1024.0 * 1024.0);
    double mb_total = (double)total / (1024.0 * 1024.0);
    double mb_speed = elapsed_ms > 0 ? mb_processed / (elapsed_ms / 1000.0) : 0;
    uint64_t eta = (mb_speed > 0 && processed < total) ? (uint64_t)((mb_total - mb_processed) / mb_speed) : 0;

    uint32_t bar_len = (percent * PROGRESS_WIDTH) / 100;
    
    printf("\r%s: [", stage);
    for (uint32_t i = 0; i < PROGRESS_WIDTH; i++) {
        printf("%c", i < bar_len ? '#' : ' ');
    }
    
    printf("] %3u%% | %.2f/%.2f MB | %.2f MB/s | ETA: ", 
           percent, mb_processed, mb_total, mb_speed);
    
    if (eta >= 3600) {
        printf("%" PRIu64 "h %" PRIu64 "m %" PRIu64 "s", eta / 3600, (eta % 3600) / 60, eta % 60);
    } else if (eta >= 60) {
        printf("%" PRIu64 "m %" PRIu64 "s", eta / 60, eta % 60);
    } else {
        printf("%" PRIu64 "s", eta);
    }
    
    fflush(stdout);

    if (processed == total) {
        printf("\n");
    }
}

static int sha256_file(const char *filename, uint8_t hash[32], uint64_t *file_size) {
    FILE *fin;
    uint8_t *buffer = (uint8_t *)malloc(BUFFER_SIZE);
    uint32_t state[8];
    uint64_t total_len = 0;
    size_t n;

    if (!buffer) { printf("Error: Memory allocation failed\n"); return 0; }

    fin = fopen(filename, "rb");
    if (!fin) { printf("Error: Cannot open file '%s'\n", filename); free(buffer); return 0; }

    fseek(fin, 0, SEEK_END);
    *file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    sha256_init(state);

    uint64_t start_time = GetTickCount64();
    uint64_t last_update = 0;
    while ((n = fread(buffer, 1, BUFFER_SIZE, fin)) > 0) {
        sha256_update(state, buffer, n);
        total_len += n;
        show_progress("Hashing", total_len, *file_size, start_time, &last_update);
    }

    fclose(fin);
    sha256_final(state, hash, total_len);
    free(buffer);
    return 1;
}

static int encrypt_file(const char *input, const char *output, const char *password) {
    FILE *fin, *fout;
    uint8_t iv[IV_LEN];
    uint8_t salt[SALT_LEN];
    uint8_t hash[HASH_LEN];
    uint8_t header[MAGIC_LEN + IV_LEN + SALT_LEN + HASH_LEN];
    uint8_t *buffer = (uint8_t *)malloc(BUFFER_SIZE + IV_LEN);
    uint64_t file_size;
    size_t n;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    int ret = 1;

    if (!buffer) { printf("Error: Memory allocation failed\n"); return 1; }

    printf("Calculating hash...\n");
    if (!sha256_file(input, hash, &file_size)) { free(buffer); return 1; }

    if (!generate_random(iv, IV_LEN)) {
        printf("Error: Generate IV failed\n"); free(buffer); return 1;
    }
    if (!generate_random(salt, SALT_LEN)) {
        printf("Error: Generate salt failed\n"); free(buffer); return 1;
    }

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Error: CryptAcquireContext failed\n"); free(buffer); return 1;
    }

    if (!CryptCreateHash(hProv, CALG_SHA256, 0, 0, &hHash)) {
        printf("Error: CryptCreateHash failed\n"); goto cleanup;
    }

    if (!CryptHashData(hHash, (BYTE*)salt, SALT_LEN, 0)) {
        printf("Error: CryptHashData salt failed\n"); goto cleanup;
    }

    if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) {
        printf("Error: CryptHashData password failed\n"); goto cleanup;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_MODE_CBC, &hKey)) {
        printf("Error: CryptDeriveKey failed\n"); goto cleanup;
    }

    CryptDestroyHash(hHash);
    hHash = 0;

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        printf("Error: CryptSetKeyParam IV failed\n"); goto cleanup;
    }

    fin = fopen(input, "rb");
    if (!fin) { printf("Error: Cannot open input file '%s'\n", input); goto cleanup; }

    fout = fopen(output, "wb");
    if (!fout) { printf("Error: Cannot open output file '%s'\n", output); goto cleanup; }

    memcpy(header, MAGIC, MAGIC_LEN);
    memcpy(header + MAGIC_LEN, iv, IV_LEN);
    memcpy(header + MAGIC_LEN + IV_LEN, salt, SALT_LEN);
    memcpy(header + MAGIC_LEN + IV_LEN + SALT_LEN, hash, HASH_LEN);
    fwrite(header, 1, sizeof(header), fout);

    printf("Encrypting...\n");
    uint64_t processed = 0;
    uint64_t start_time = GetTickCount64();
    uint64_t last_update = 0;
    
    while ((n = fread(buffer, 1, BUFFER_SIZE, fin)) > 0) {
        processed += n;
        int is_final = (processed == file_size);
        DWORD out_len = n;
        DWORD buf_size = BUFFER_SIZE + IV_LEN;

        if (!CryptEncrypt(hKey, 0, is_final, 0, buffer, &out_len, buf_size)) {
            printf("Error: CryptEncrypt failed\n"); goto cleanup;
        }

        if (fwrite(buffer, 1, out_len, fout) != out_len) {
            printf("Error: Write output file failed\n"); goto cleanup;
        }

        show_progress("Encrypting", processed, file_size, start_time, &last_update);
    }

    ret = 0;
    printf("Encrypted '%s' -> '%s' successfully (%.2f MB)\n", 
           input, output, (double)file_size / (1024.0 * 1024.0));

cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (hHash) CryptDestroyHash(hHash);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    free(buffer);
    return ret;
}

static int decrypt_file(const char *input, const char *output, const char *password) {
    FILE *fin, *fout;
    uint8_t header[MAGIC_LEN + IV_LEN + SALT_LEN + HASH_LEN];
    uint8_t iv[IV_LEN];
    uint8_t salt[SALT_LEN];
    uint8_t stored_hash[HASH_LEN];
    uint8_t computed_hash[HASH_LEN];
    uint8_t *buffer = (uint8_t *)malloc(BUFFER_SIZE);
    uint64_t file_size;
    uint64_t data_size;
    uint64_t total_decrypted = 0;
    size_t n;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    uint32_t sha_state[8];
    int ret = 1;

    if (!buffer) { printf("Error: Memory allocation failed\n"); return 1; }

    fin = fopen(input, "rb");
    if (!fin) { printf("Error: Cannot open input file '%s'\n", input); free(buffer); return 1; }

    fseek(fin, 0, SEEK_END);
    file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (file_size < sizeof(header)) {
        printf("Error: Invalid file format - file too small\n"); fclose(fin); free(buffer); return 1;
    }

    if (fread(header, 1, sizeof(header), fin) != sizeof(header)) {
        printf("Error: Read header failed\n"); fclose(fin); free(buffer); return 1;
    }

    if (memcmp(header, MAGIC, MAGIC_LEN) != 0) {
        printf("Error: Invalid file format - bad magic\n"); fclose(fin); free(buffer); return 1;
    }

    memcpy(iv, header + MAGIC_LEN, IV_LEN);
    memcpy(salt, header + MAGIC_LEN + IV_LEN, SALT_LEN);
    memcpy(stored_hash, header + MAGIC_LEN + IV_LEN + SALT_LEN, HASH_LEN);

    data_size = file_size - sizeof(header);

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Error: CryptAcquireContext failed\n"); fclose(fin); free(buffer); return 1;
    }

    if (!CryptCreateHash(hProv, CALG_SHA256, 0, 0, &hHash)) {
        printf("Error: CryptCreateHash failed\n"); CryptReleaseContext(hProv, 0); fclose(fin); free(buffer); return 1;
    }

    if (!CryptHashData(hHash, (BYTE*)salt, SALT_LEN, 0)) {
        printf("Error: CryptHashData salt failed\n"); CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); fclose(fin); free(buffer); return 1;
    }

    if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) {
        printf("Error: CryptHashData password failed\n"); CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); fclose(fin); free(buffer); return 1;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_MODE_CBC, &hKey)) {
        printf("Error: CryptDeriveKey failed\n"); CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); fclose(fin); free(buffer); return 1;
    }

    CryptDestroyHash(hHash);
    hHash = 0;

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        printf("Error: CryptSetKeyParam IV failed\n"); CryptDestroyKey(hKey); CryptReleaseContext(hProv, 0); fclose(fin); free(buffer); return 1;
    }

    fout = fopen(output, "wb");
    if (!fout) { printf("Error: Cannot open output file '%s'\n", output); goto cleanup; }

    sha256_init(sha_state);
    uint64_t processed = 0;
    uint64_t start_time = GetTickCount64();
    uint64_t last_update = 0;

    printf("Decrypting...\n");
    while ((n = fread(buffer, 1, BUFFER_SIZE, fin)) > 0) {
        processed += n;
        int is_final = (processed == data_size);
        DWORD out_len = n;

        if (!CryptDecrypt(hKey, 0, is_final, 0, buffer, &out_len)) {
            printf("Error: CryptDecrypt failed\n"); goto cleanup;
        }

        sha256_update(sha_state, buffer, out_len);
        total_decrypted += out_len;

        if (fwrite(buffer, 1, out_len, fout) != out_len) {
            printf("Error: Write output file failed\n"); goto cleanup;
        }

        show_progress("Decrypting", processed, data_size, start_time, &last_update);
    }

    sha256_final(sha_state, computed_hash, total_decrypted);
    if (memcmp(stored_hash, computed_hash, HASH_LEN) != 0) {
        printf("Error: Hash mismatch - wrong password or corrupted file\n"); goto cleanup;
    }

    ret = 0;
    printf("Decrypted '%s' -> '%s' successfully (%.2f MB)\n", 
           input, output, (double)total_decrypted / (1024.0 * 1024.0));

cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (hHash) CryptDestroyHash(hHash);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    free(buffer);
    return ret;
}

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s -encrypt <input_file> [-o <output_file>] [--key <password>]\n", prog);
    printf("  %s -decrypt <input_file> [-o <output_file>] [--key <password>]\n", prog);
    printf("\nOptions:\n");
    printf("  -encrypt        Encrypt the input file\n");
    printf("  -decrypt        Decrypt the input file\n");
    printf("  -o <file>       Output file name (default: input.enc for encrypt, input without .enc for decrypt)\n");
    printf("  --key <pwd>     Encryption/decryption password (default: 'default')\n");
    printf("  -h, --help      Show this help message\n");
}

static void set_default_output(char *output, const char *input, int is_encrypt) {
    strcpy(output, input);
    if (is_encrypt) {
        strcat(output, ".enc");
    } else {
        size_t len = strlen(input);
        if (len > 4 && strcmp(input + len - 4, ".enc") == 0) {
            output[len - 4] = '\0';
        } else {
            strcat(output, ".dec");
        }
    }
}

int main(int argc, char *argv[]) {
    int mode = 0;
    const char *input_file = NULL;
    char output_file[512] = {0};
    const char *password = "default";

    if (argc < 2) { print_usage(argv[0]); return 1; }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-encrypt") == 0) mode = 1;
        else if (strcmp(argv[i], "-decrypt") == 0) mode = 2;
        else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) { printf("Error: -o requires an argument\n"); return 1; }
            strcpy(output_file, argv[++i]);
        } else if (strcmp(argv[i], "--key") == 0) {
            if (i + 1 >= argc) { printf("Error: --key requires an argument\n"); return 1; }
            password = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { print_usage(argv[0]); return 0; }
        else if (!input_file) input_file = argv[i];
        else { printf("Error: Unknown argument '%s'\n", argv[i]); return 1; }
    }

    if (!mode) { printf("Error: Must specify -encrypt or -decrypt\n"); return 1; }
    if (!input_file) { printf("Error: Input file not specified\n"); return 1; }

    if (!output_file[0]) set_default_output(output_file, input_file, mode == 1);

    if (mode == 1) return encrypt_file(input_file, output_file, password);
    else return decrypt_file(input_file, output_file, password);
}