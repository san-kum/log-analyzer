#include <stdio.h>
#include <string.h>

#include "include/log_analyzer.h"

#define VERSION "0.1.0"
#define MAX_ENTRIES 10000

int main(int argc, char **argv) {
  LogAnalyzerContext *ctx;
  char line_buffer[MAX_LINE_LENGTH];
  LogEntry **entries;
  int entry_count = 0;
  bool success;

  /*Intialize the context with default values*/
  ctx = log_analyzer_init("", "", "");
  if (!ctx) {
    fprintf(stderr, "Failed to intialize log analyzer\n");
    return EXIT_FAILURE;
  }

  /*Parse command-line arguments*/
  if (!cli_parse_arguments(argc, argv, ctx)) {
    cli_print_help();
    log_analyzer_cleanup(ctx);
    return EXIT_FAILURE;
  }
  if (strcmp(ctx->input_path, "--help") == 0) {
    cli_print_help();
    log_analyzer_cleanup(ctx);
    return EXIT_SUCCESS;
  } else if (strcmp(ctx->input_path, "--version") == 0) {
    cli_print_version();
    log_analyzer_cleanup(ctx);
    return EXIT_SUCCESS;
  }

  if (!log_collector_open_file(ctx)) {
    fprintf(stderr, "Failed to open input file: %s\n", ctx->input_path);
    log_analyzer_cleanup(ctx);
    return EXIT_FAILURE;
  }

  entries = (LogEntry **)malloc(MAX_ENTRIES * sizeof(LogEntry *));
  if (!entries) {
    fprintf(stderr, "Failed to allocate memory for long entries\n");
    log_collector_close_file(ctx);
    log_analyzer_cleanup(ctx);
    return EXIT_FAILURE;
  }

  printf("Reading log entries...\n");
  while (log_collector_read_line(ctx, line_buffer, MAX_LINE_LENGTH) &&
         entry_count < MAX_ENTRIES) {
    entries[entry_count] = log_parser_parse_line(ctx, line_buffer);
    if (entries[entry_count]) entry_count++;
  }
  printf("Read %d log entries\n", entry_count);

  log_collector_close_file(ctx);

  /* Patterns */
  printf("Analyzing Patterns...\n");
  success = pattern_detector_analyze(ctx, entries, entry_count);
  if (!success) {
    fprintf(stderr, "Pattern detection failed\n");
    for (int i = 0; i < entry_count; i++) log_parser_free_entry(entries[i]);
    free(entries);
    log_analyzer_cleanup(ctx);
    return EXIT_FAILURE;
  }

  /*Recommendations */
  printf("Generating recommendations...\n");
  success = recommendation_generator_analyze(ctx);
  if (!success) {
    fprintf(stderr, "Recommendation generation failed\n");
    for (int i = 0; i < entry_count; i++) log_parser_free_entry(entries[i]);
    free(entries);
    log_analyzer_cleanup(ctx);
    return EXIT_FAILURE;
  }
  /* Write reports */
  printf("Writing reports...\n");
  success = report_generator_write_summary(ctx);
  if (!success) fprintf(stderr, "Failed to write summary report\n");

  success = report_generator_write_detailed(ctx);
  if (!success) fprintf(stderr, "Failed to write detailed report\n");

  for (int i = 0; i < entry_count; i++) log_parser_free_entry(entries[i]);
  free(entries);

  log_analyzer_cleanup(ctx);
  return EXIT_SUCCESS;
}

void cli_print_version(void) { printf("Log Analyzer version: %s\n", VERSION); }

void cli_print_help(void) {
  printf(
      "Log Analyzer - A tool for analyzing logs and recommending "
      "performance improvements\n\n");
  printf("Usage: log_analyzer [OPTIONS] INPUT_FILE\n\n");
  printf("Options:\n");
  printf("  -o, --output FILE     Write output to FILE (default: stdout)\n");
  printf(
      "  -f, --format FORMAT   Specify the log format (default: "
      "auto-detect)\n");
  printf("  -v, --verbose         Increase verbosity\n");
  printf("  -h, --help            Display this help and exit\n");
  printf("  --version             Display version information and exit\n\n");
  printf("Examples:\n");
  printf("  log_analyzer /var/log/syslog\n");
  printf("  log_analyzer -o recommendations.txt -f syslog /var/log/kern.log\n");
}
