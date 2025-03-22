#include <stdlib.h>

#include "include/log_analyzer.h"

LogAnalyzerContext *log_analyzer_init(const char *input_path,
                                      const char *output_path,
                                      const char *format) {
  LogAnalyzerContext *ctx =
      (LogAnalyzerContext *)malloc(sizeof(LogAnalyzerContext));
  if (!ctx) return NULL;

  memset(ctx, 0, sizeof(LogAnalyzerContext));

  if (input_path) {
    strncpy(ctx->input_path, input_path, MAX_PATH_LENGTH - 1);
    ctx->input_path[MAX_PATH_LENGTH - 1] = '\0';
  }
  if (output_path) {
    strncpy(ctx->output_path, output_path, MAX_PATH_LENGTH - 1);
    ctx->output_path[MAX_PATH_LENGTH - 1] = '\0';
  }

  if (format) {
    strncpy(ctx->log_format, format, MAX_FORMAT_LENGTH - 1);
    ctx->log_format[MAX_FORMAT_LENGTH - 1] = '\0';
  }

  ctx->verbose = 0;
  ctx->pattern_count = 0;
  ctx->recommendation_count = 0;

  return ctx;
}

void log_analyzer_cleanup(LogAnalyzerContext *ctx) {
  if (!ctx) return;

  /* Memory for patterns */
  for (int i = 0; i < ctx->pattern_count; i++) {
    free(ctx->patterns[i].pattern);
    free(ctx->patterns[i].description);
    free(ctx->patterns[i].category);
  }

  /* For memory for recommendations */
  for (int i = 0; i < ctx->recommendation_count; i++) {
    free(ctx->recommendations[i].title);
    free(ctx->recommendations[i].description);
    free(ctx->recommendations[i].action);
    free(ctx->recommendations[i].category);
  }

  free(ctx);
}

bool cli_parse_arguments(int argc, char **argv, LogAnalyzerContext *ctx) {
  if (argc < 2) return false;

  /* Parse Command-line args */
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      strncpy(ctx->input_path, "--help", MAX_PATH_LENGTH - 1);
      return true;
    } else if (strcmp(argv[i], "--version") == 0) {
      strncpy(ctx->input_path, "--version", MAX_PATH_LENGTH - 1);
      return true;
    } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
      if (i + 1 < argc) {
        strncpy(ctx->output_path, argv[i + 1], MAX_PATH_LENGTH - 1);
        i++;
      } else {
        fprintf(stderr, "Missing arguments for %s\n", argv[i]);
        return false;
      }
    } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--format") == 0) {
      if (i + 1 < argc) {
        strncpy(ctx->log_format, argv[i + 1], MAX_FORMAT_LENGTH - 1);
        i++;
      } else {
        fprintf(stderr, "Missing arguments for %s\n", argv[i]);
        return false;
      }
    } else if (strcmp(argv[i], "-v") == 0 ||
               strcmp(argv[i], "--verbose") == 0) {
      ctx->verbose++;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      return false;
    } else {
      strncpy(ctx->input_path, argv[i], MAX_PATH_LENGTH - 1);
    }
  }

  /* Check if input file was specified */
  if (strlen(ctx->input_path) == 0) {
    fprintf(stderr, "No input file specified\n");
    return false;
  }
  return true;
}
