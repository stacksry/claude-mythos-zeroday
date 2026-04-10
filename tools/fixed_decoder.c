/*
 * fixed_decoder.c
 *
 * Reference fix for the FFmpeg-style OOB write in vulnerable_decoder.c
 * Study this AFTER attempting your own fix.
 *
 * Build:
 *   clang -fsanitize=address -g -o fixed_decoder fixed_decoder.c
 *
 * Run (safe):    ./fixed_decoder 10 10 999   <- should now reject gracefully
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static uint8_t decode_plane(int index) {
    return (uint8_t)(index & 0xFF);
}

int decode_frame_fixed(int width, int height, int num_planes) {
    /* Guard: reject non-positive dimensions */
    if (width <= 0 || height <= 0 || num_planes <= 0) {
        fprintf(stderr, "[fix] invalid dimensions\n");
        return -1;
    }

    /* Guard: check for integer overflow in buf_size calculation */
    if (width > INT32_MAX / height) {
        fprintf(stderr, "[fix] width*height overflow\n");
        return -1;
    }

    int buf_size = width * height;

    /* THE KEY FIX: validate num_planes against the buffer we actually allocated */
    if (num_planes > buf_size) {
        fprintf(stderr, "[fix] num_planes (%d) exceeds buffer size (%d) — rejecting\n",
                num_planes, buf_size);
        return -1;
    }

    uint8_t *buf = malloc(buf_size);
    if (!buf) return -1;

    printf("[fix] buf_size=%d, num_planes=%d — safe\n", buf_size, num_planes);

    for (int i = 0; i < num_planes; i++) {
        buf[i] = decode_plane(i);
    }

    printf("[fix] decoded %d planes successfully\n", num_planes);
    free(buf);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <width> <height> <num_planes>\n", argv[0]);
        return 1;
    }

    int width      = atoi(argv[1]);
    int height     = atoi(argv[2]);
    int num_planes = atoi(argv[3]);

    printf("=== Fixed version ===\n");
    int ret = decode_frame_fixed(width, height, num_planes);
    if (ret != 0) {
        printf("Rejected malformed input — no OOB write.\n");
    }
    return 0;
}
