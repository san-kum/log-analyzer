#include "include/log_analyzer.h"

static FILE *input_file = NULL;

bool log_collector_open_file(LogAnalyzerContext *ctx) {
  if (!ctx || strlen(ctx->input_path) == 0) return false;

  input_file = fopen(ctx->input_path, "r");
  if (!input_file) {
    perror("Failed to open input file");
    return false;
  }
  return true;
}

bool log_collector_read_line(LogAnalyzerContext *ctx, char *buffer,
                             size_t buffer_size) {
  if (!ctx || !buffer || buffer_size == 0 || !input_file) return false;

  if (fgets(buffer, buffer_size, input_file) == NULL) {
    if (feof(input_file))
      return false;
    else {
      perror("Error reading input file.");
      return false;
    }
  }
  size_t len = strlen(buffer);
  if (len > 0 && buffer[len - 1] == '\n') buffer[len - 1] = '\0';

  return true;
}

void log_collector_close_file(LogAnalyzerContext *ctx) {
  if (input_file) {
    fclose(input_file);
    input_file = NULL;
  }
}
