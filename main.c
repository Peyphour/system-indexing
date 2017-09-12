#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include "md5.c"

#define VERIFICATION_FILENAME "-----VERIFICATION_FILE-----"

typedef struct {
    char file_path[4096];
    unsigned char hash[32];
} file_hash;

void generate_file(int argc, char *paths[], FILE *output_file);

void hash_data(unsigned char *data, size_t length, unsigned char *out) {
    SHA256_CTX *sha256_ctx = malloc(sizeof(SHA256_CTX));
    sha256_init(sha256_ctx);
    sha256_update(sha256_ctx, data, length);

    sha256_final(sha256_ctx, out);
    free(sha256_ctx);
}

file_hash process_file(char *file_path) {
    FILE *file = fopen(file_path, "r");
    size_t file_size;
    file_hash result;


    if (file == NULL) {
        printf("Couldn't open file %s for reading %s\n", file_path, strerror(*_errno()));
        return result;
    }

    fseek(file, 0, SEEK_END);
    file_size = (size_t) ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *data = malloc(file_size);
    fread(data, sizeof(char), file_size, file);

    unsigned char hash[32];

    hash_data(data, file_size, hash);


    free(data);
    fclose(file);

    strcpy(result.file_path, file_path);
    memcpy((char *) result.hash, (char *) hash, 32);

    return result;
}

void process_directory(char *dir, FILE *output_file) {

    DIR *directory = opendir(dir);
    if (directory == NULL)
        return;
    struct dirent *entry;

    while ((entry = readdir(directory)) != NULL) {
        char path[4096];
        sprintf(path, "%s/%s", dir, entry->d_name);

        if (entry->d_type != DT_DIR && strcmp(entry->d_name, VERIFICATION_FILENAME) != 0) {
            file_hash file_hash = process_file(path);
            fwrite(&file_hash, sizeof(file_hash), 1, output_file);
        } else if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            process_directory(path, output_file);
        }
    }

    free(entry);
    closedir(directory);
}

int main(int argc, char *argv[]) {

    if (argc < 3) {
        printf("Usage: %s (generate | !verify) !verify_file [dir1] [dir2] [dir....]\n", argv[0]);
    }

    if (!strcmp(argv[1], "generate")) {

        FILE *output_file = fopen(VERIFICATION_FILENAME, "w");

        if(output_file == NULL) {
            printf("Couldn't open output file!");
            return EXIT_FAILURE;
        }

        generate_file(argc - 2, argv + 2, output_file);

        fclose(output_file);
    }
    else if (!strcmp(argv[1], "verify")) {

    }

    return 0;
}

void generate_file(int argc, char *paths[], FILE *output_file) {
    for (int i = 0; i < argc; i++) {
        char *dir = paths[i];
        printf("Analyzing directory %s\n", dir);
        process_directory(dir, output_file);
    }
}