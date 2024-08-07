/*
Copyright (c) 2017. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stddef.h>
#include <stdint.h>
#include <yara.h>
#include <dirent.h>


YR_RULES* rules = NULL;


extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{

	YR_COMPILER* compiler;
    YR_RULES* rules;
    const char* rules_dir = "generated_rules"; // Specify your rules directory here
    struct dirent* entry;
    DIR* dp;

    if (yr_initialize() != ERROR_SUCCESS)
        return 0;

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
        return 0;

    dp = opendir(rules_dir);
    if (dp == NULL) {
        perror("Failed to open rules directory");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 0;
    }

    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG) { // Check if it is a regular file
            char filepath[256];
            snprintf(filepath, sizeof(filepath), "%s/%s", rules_dir, entry->d_name);
            
            FILE* rule_file = fopen(filepath, "r");
            if (rule_file == NULL) {
                perror("Failed to open rule file");
                continue;
            }
             // Determine the file size
            fseek(rule_file, 0, SEEK_END);
            long file_size = ftell(rule_file);
            fseek(rule_file, 0, SEEK_SET);

            // Allocate memory for the file content
            char* file_content = (char*)malloc(file_size + 1);
            if (file_content == NULL) {
                perror("Failed to allocate memory for file content");
                fclose(rule_file);
                continue;
            }

            // Read the file content
            fread(file_content, 1, file_size, rule_file);
            file_content[file_size] = '\0'; // Null-terminate the string

            fclose(rule_file);

            // Add the file content as a string to the compiler
            int errors = yr_compiler_add_string(compiler, file_content, NULL);
            free(file_content);

            if (errors != 0) {
                fprintf(stderr, "Error loading rules from %s\n", filepath);
            }
        }
    }
    closedir(dp);

    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to get compiled rules\n");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 0;
    }

    yr_compiler_destroy(compiler);

  return 0;

}


int callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  return CALLBACK_CONTINUE;
}

// extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed)
// {
//   YR_RULES* rules;
//   YR_COMPILER* compiler;

//   char* buffer = (char*) malloc(size + 1);

//   if (!buffer)
//     return 0;

//   strncpy(buffer, (const char*) data, size);
//   buffer[size] = 0;

//   if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
//   {
//     free(buffer);
//     return 0;
//   }

//   FILE* log_file = fopen("fuzz_log.txt", "a");
//   if (log_file == NULL)
//   {
//     yr_compiler_destroy(compiler);
//     free(buffer);
//     return 0;
//   }

//   if (yr_compiler_add_string(compiler, (const char*) buffer, NULL) == 0)
//   {
//     if (yr_compiler_get_rules(compiler, &rules) == ERROR_SUCCESS)
//     {
//       fprintf(log_file, "Rules fuzzed successfully.\n");
//       yr_rules_destroy(rules);
//     }
//     else
//     {
//       fprintf(log_file, "Failed to get rules.\n");
//     }
//   }
//   else
//   {
//     fprintf(log_file, "Failed to add string to compiler.\n");
//   }
  
//   fclose(log_file);
//   yr_compiler_destroy(compiler);
//   free(buffer);

//   return 0;
// }
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (rules == NULL)
    return 0;

  yr_rules_scan_mem(
      rules, data, size, SCAN_FLAGS_NO_TRYCATCH, callback, NULL, 0);

  return 0;
}
