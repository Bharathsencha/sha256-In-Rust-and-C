#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"       // Must come before raylib to define types
#include "raylib.h"

// External Rust functions
typedef struct {
    unsigned int h[8];
    unsigned char buffer[64];
    unsigned int buflen;
    unsigned long long bitlen;
} RustSha256Ctx;

extern void rust_sha256_init(RustSha256Ctx *ctx);
extern void rust_sha256_update(RustSha256Ctx *ctx, const unsigned char *data, unsigned int len);
extern void rust_sha256_final(RustSha256Ctx *ctx, unsigned char out_hash32[32]);
extern void rust_sha256_to_hex(const unsigned char hash32[32], char hex_out[65]);

// Use system OpenSSL CLI to compute SHA-256
void run_openssl_sha256(const char *input, char *openssl_output) {
    char command[2048];
    snprintf(command, sizeof(command), "echo -n '%s' | openssl dgst -sha256 | awk '{print $2}'", input);

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        strcpy(openssl_output, "ERROR");
        return;
    }
    if (fgets(openssl_output, 65, fp) == NULL) {
        strcpy(openssl_output, "ERROR");
    }
    pclose(fp);

    // Trim newline if present
    openssl_output[strcspn(openssl_output, "\n")] = '\0';
}

#define MAX_INPUT 256

int main(void) {
    const int screenWidth = 1000;
    const int screenHeight = 700;

    InitWindow(screenWidth, screenHeight, "SHA-256 Checker: C vs Rust vs OpenSSL");

    char inputText[MAX_INPUT] = {0};
    int letterCount = 0;

    bool checkPressed = false;
    char cHash[65] = {0};
    char rustHash[65] = {0};
    char opensslHash[65] = {0};
    char cVsOpensslMsg[128] = {0};
    char rustVsOpensslMsg[128] = {0};

    struct sha256_ctx c_ctx;
    RustSha256Ctx rust_ctx;
    unsigned char c_digest[32];
    unsigned char rust_digest[32];

    SetTargetFPS(60);

    while (!WindowShouldClose()) {
        // Handle text input
        int key = GetCharPressed();
        while (key > 0) {
            if ((key >= 32) && (key <= 125) && (letterCount < MAX_INPUT - 1)) {
                inputText[letterCount] = (char)key;
                inputText[letterCount + 1] = '\0';
                letterCount++;
            }
            key = GetCharPressed();
        }

        if (IsKeyPressed(KEY_BACKSPACE)) {
            if (letterCount > 0) {
                letterCount--;
                inputText[letterCount] = '\0';
            }
        }

        // Check button or Enter key
        if (IsKeyPressed(KEY_ENTER) || (IsMouseButtonPressed(MOUSE_LEFT_BUTTON) &&
            CheckCollisionPointRec(GetMousePosition(), (Rectangle){ 800, 50, 150, 40 }))) {
            
            // Compute using C SHA-256
            sha256_init(&c_ctx);
            sha256_update(&c_ctx, (const u8 *)inputText, strlen(inputText));
            sha256_final(&c_ctx, c_digest);
            sha256_to_hex(c_digest, cHash);

            // Compute using Rust SHA-256
            rust_sha256_init(&rust_ctx);
            rust_sha256_update(&rust_ctx, (const unsigned char *)inputText, strlen(inputText));
            rust_sha256_final(&rust_ctx, rust_digest);
            rust_sha256_to_hex(rust_digest, rustHash);

            // Compute using system OpenSSL
            run_openssl_sha256(inputText, opensslHash);

            // Compare C vs OpenSSL
            if (strcmp(cHash, opensslHash) == 0) {
                strcpy(cVsOpensslMsg, "C matches OpenSSL ");
            } else {
                strcpy(cVsOpensslMsg, "C MISMATCH with OpenSSL");
            }

            // Compare Rust vs OpenSSL
            if (strcmp(rustHash, opensslHash) == 0) {
                strcpy(rustVsOpensslMsg, "Rust matches OpenSSL");
            } else {
                strcpy(rustVsOpensslMsg, "Rust MISMATCH with OpenSSL");
            }

            checkPressed = true;
        }

        BeginDrawing();
        ClearBackground(RAYWHITE);

        // Title - Centered
        const char *title = "SHA-256 in Rust and C";
        int titleWidth = MeasureText(title, 30);
        DrawText(title, (screenWidth - titleWidth) / 2, 15, 30, DARKBLUE);

        // Input field
        DrawText("Enter text:", 50, 60, 20, DARKGRAY);
        DrawRectangleLines(180, 55, 600, 40, GRAY);
        DrawText(inputText, 190, 65, 20, BLACK);

        // Check button
        DrawRectangle(800, 50, 150, 40, LIGHTGRAY);
        DrawRectangleLines(800, 50, 150, 40, GRAY);
        DrawText("Check Hash", 815, 60, 20, BLACK);

        if (checkPressed) {
            int yPos = 130;
            
            // C Implementation
            DrawText("C SHA-256:", 50, yPos, 20, DARKGRAY);
            DrawText(cHash, 50, yPos + 30, 18, BLACK);
            
            // Rust Implementation
            DrawText("Rust SHA-256:", 50, yPos + 80, 20, DARKGRAY);
            DrawText(rustHash, 50, yPos + 110, 18, MAROON);

            // OpenSSL Reference
            DrawText("OpenSSL SHA-256 (Reference):", 50, yPos + 160, 20, DARKGRAY);
            DrawText(opensslHash, 50, yPos + 190, 18, DARKGREEN);

            // Comparison results
            DrawText("Verification Results:", 50, yPos + 260, 24, DARKBLUE);
            
            Color cResultColor = (strcmp(cHash, opensslHash) == 0) ? DARKGREEN : RED;
            DrawText(cVsOpensslMsg, 50, yPos + 300, 22, cResultColor);
            
            Color rustResultColor = (strcmp(rustHash, opensslHash) == 0) ? DARKGREEN : RED;
            DrawText(rustVsOpensslMsg, 50, yPos + 340, 22, rustResultColor);

            // Overall status
            if (strcmp(cHash, opensslHash) == 0 && strcmp(rustHash, opensslHash) == 0) {
                DrawText("[PASS] ALL IMPLEMENTATIONS CORRECT!", 50, yPos + 400, 28, DARKGREEN);
            } else {
                DrawText("[FAIL] SOME IMPLEMENTATIONS FAILED", 50, yPos + 400, 28, RED);
            }
        }

        EndDrawing();
    }

    CloseWindow();
    return 0;
}