/*
 * vulnerable_decoder.c
 *
 * Training exercise: FFmpeg-style out-of-bounds write
 * Project Glasswing / claude-mythos-zeroday
 *
 * Mimics the class of bug Claude Mythos found in FFmpeg:
 *   - buffer sized from field A (width * height)
 *   - write loop bounded by field B (num_planes)
 *   - no validation that B <= A
 *
 * Build:
 *   clang -fsanitize=address -g -o vulnerable_decoder vulnerable_decoder.c
 *
 * Run (safe):    ./vulnerable_decoder 10 10 5
 * Run (crash):   ./vulnerable_decoder 10 10 999
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* Simulates decoding a single plane value */
static uint8_t decode_plane(int index) {
    return (uint8_t)(index & 0xFF);
}

/*
 * VULNERABLE version
 * num_planes is never validated against width * height
 */
int decode_frame_vulnerable(int width, int height, int num_planes) {
    int buf_size = width * height;
    uint8_t *buf = malloc(buf_size);
    if (!buf) return -1;

    printf("[vuln] buf_size=%d, num_planes=%d\n", buf_size, num_planes);

    for (int i = 0; i < num_planes; i++) {
        buf[i] = decode_plane(i);   /* OOB write if num_planes > buf_size */
    }

    printf("[vuln] decoded %d planes\n", num_planes);
    free(buf);
    return 0;
}

/*
 * FIXED version
 * YOUR TASK: implement this correctly
 * Hint: validate num_planes <= buf_size before the loop
 */
int decode_frame_fixed(int width, int height, int num_planes) {
    /* TODO: add your fix here */
    return decode_frame_vulnerable(width, height, num_planes);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <width> <height> <num_planes>\n", argv[0]);
        return 1;
    }

    int width      = atoi(argv[1]);
    int height     = atoi(argv[2]);
    int num_planes = atoi(argv[3]);

    printf("=== Vulnerable version ===\n");
    decode_frame_vulnerable(width, height, num_planes);

    /* Uncomment after implementing the fix:
    printf("\n=== Fixed version ===\n");
    decode_frame_fixed(width, height, num_planes);
    */

    return 0;
}
