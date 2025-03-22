#ifndef LOG_ANALYZER_H
#define LOG_ANALYZER_H

/* Contstants */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE_LENGTH 4096
#define MAX_PATTERNS 100
#define MAX_RECOMMENDATIONS 50
#define MAX_PATH_LENGTH 256
#define MAX_FORMAT_LENGTH 128

typedef struct {
  char *raw_text;
  char *message;
  time_t timestamp;
  char *source;
  int severity;
  char *thread_id;
  char *process_id;
  char *additional_fields;

} LogEntry;

typedef struct {
  char *pattern;
  int frequency;
  int severity;
  char *description;
  char *category;
} Pattern;

typedef struct {
  char *title;
  char *description;
  char *action;
  int priority;
  char *category;
  float confidence;
} Recommendation;

typedef struct {
  char input_path[MAX_PATH_LENGTH];
  char output_path[MAX_PATH_LENGTH];
  char log_format[MAX_FORMAT_LENGTH];
  int verbose;
  Pattern patterns[MAX_PATTERNS];
  int pattern_count;
  Recommendation recommendations[MAX_RECOMMENDATIONS];
  int recommendation_count;

} LogAnalyzerContext;

LogAnalyzerContext *log_analyzer_init(const char *input_path,
                                      const char *output_path,
                                      const char *format);
void log_analyzer_cleanup(LogAnalyzerContext *ctx);

bool log_collector_open_file(LogAnalyzerContext *ctx);
bool log_collector_read_line(LogAnalyzerContext *ctx, char *buffer,
                             size_t buffer_size);
void log_collector_close_file(LogAnalyzerContext *ctx);

LogEntry *log_parser_parse_line(LogAnalyzerContext *ctx, const char *line);
void log_parser_free_entry(LogEntry *entry);

bool pattern_detector_analyze(LogAnalyzerContext *ctx, LogEntry **entries,
                              int entry_count);
Pattern *pattern_detector_get_patterns(LogAnalyzerContext *ctx,
                                       int *pattern_count);

bool recommendation_genertor_analyze(LogAnalyzerContext *ctx);
Recommendation *recommendation_generator_get_recommendations(
    LogAnalyzerContext *ctx, int *recommendation_count);

bool report_generator_write_summary(LogAnalyzerContext *ctx);
bool report_generator_write_detailed(LogAnalyzerContext *ctx);

/* CLI Functions */
bool cli_parse_arguments(int argc, char **argv, LogAnalyzerContext *ctx);
void cli_print_help(void);
void cli_print_version(void);

#endif  // !LOG_ANALYZER_H
