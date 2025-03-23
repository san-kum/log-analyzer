#include <regex.h>

#include "include/log_analyzer.h"

static bool string_matches_pattern(const char *string, const char *pattern) {
  regex_t regex;
  int result;

  if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
    return false;
  }

  result = regexec(&regex, string, 0, NULL, 0);
  regfree(&regex);

  return (result == 0);
}

static void add_pattern(LogAnalyzerContext *ctx, const char *pattern_str,
                        const char *description, const char *category,
                        int severity) {
  Pattern *pattern;
  if (!ctx || !pattern_str || ctx->pattern_count >= MAX_PATTERNS) return;

  pattern = &ctx->patterns[ctx->pattern_count];

  /* initialize the patterns */
  pattern->pattern = strdup(pattern_str);
  pattern->description = strdup(description);
  pattern->category = strdup(category);
  pattern->severity = severity;
  pattern->frequency = 0;

  ctx->pattern_count++;
}

static void detect_common_patterns(LogAnalyzerContext *ctx) {
  /* CPU-related patterns */
  add_pattern(ctx, ".*cpu usage.*[9][0-9]%.*", "High CPU usage detected", "cpu",
              4);
  add_pattern(ctx, ".*load average:.*[5-9]\\.[0-9].*", "High load average",
              "cpu", 3);
  add_pattern(ctx, ".*process.*using excessive cpu.*",
              "Process using excessive CPU", "cpu", 4);

  /* Memory-related patterns */
  add_pattern(ctx, ".*out of memory.*", "Out of memory condition", "memory", 5);
  add_pattern(ctx, ".*memory allocation failed.*", "Memory allocation failure",
              "memory", 4);
  add_pattern(ctx, ".*free memory: [0-9]+ KB.*", "Low free memory", "memory",
              3);
  add_pattern(ctx, ".*swap used: [8-9][0-9]%.*", "High swap usage", "memory",
              4);

  /* Disk-related patterns */
  add_pattern(ctx, ".*disk full.*", "Disk full condition", "disk", 5);
  add_pattern(ctx, ".*i/o error.*", "Disk I/O error", "disk", 4);
  add_pattern(ctx, ".*device timeout.*", "Device timeout", "disk", 3);
  add_pattern(ctx, ".*filesystem.*[9][0-9]%.*", "Filesystem near capacity",
              "disk", 3);

  /* Network-related patterns */
  add_pattern(ctx, ".*network unreachable.*", "Network unreachable", "network",
              4);
  add_pattern(ctx, ".*connection timed out.*", "Connection timeout", "network",
              3);
  add_pattern(ctx, ".*packet loss.*", "Network packet loss", "network", 3);

  /* Process-related patterns */
  add_pattern(ctx, ".*process.*killed.*", "Process killed", "process", 4);
  add_pattern(ctx, ".*segmentation fault.*", "Segmentation fault", "process",
              5);
  add_pattern(ctx, ".*core dumped.*", "Core dumped", "process", 5);
  add_pattern(ctx, ".*process.*not responding.*", "Process not responding",
              "process", 4);

  /* Database-related patterns */
  add_pattern(ctx, ".*database connection failed.*",
              "Database connection failure", "database", 4);
  add_pattern(ctx, ".*query timeout.*", "Database query timeout", "database",
              3);
  add_pattern(ctx, ".*deadlock detected.*", "Database deadlock", "database", 4);

  /* File descriptor related patterns */
  add_pattern(ctx, ".*too many open files.*", "Too many open files",
              "resources", 4);
  add_pattern(ctx, ".*file descriptor.*limit.*",
              "File descriptor limit reached", "resources", 4);
}

bool pattern_detector_analyze(LogAnalyzerContext *ctx, LogEntry **entries,
                              int entry_count) {
  int i, j;
  Pattern *pattern;

  if (!ctx || !entries || entry_count <= 0) return false;

  detect_common_patterns(ctx);
  for (i = 0; i < entry_count; i++) {
    if (!entries[i] || !entries[i]->message) continue;

    for (j = 0; j < ctx->pattern_count; j++) {
      pattern = &ctx->patterns[j];
      if (string_matches_pattern(entries[i]->message, pattern->pattern))
        pattern->frequency++;
    }
  }

  /* Sort */
  for (i = 0; i < ctx->pattern_count - 1; i++) {
    for (j = 0; j < ctx->pattern_count - 1; j++) {
      if (ctx->patterns[j].frequency < ctx->patterns[j + 1].frequency) {
        Pattern temp = ctx->patterns[j];
        ctx->patterns[j] = ctx->patterns[j + 1];
        ctx->patterns[j + 1] = temp;
      }
    }
  }
  return true;
}

Pattern *pattern_detector_get_patterns(LogAnalyzerContext *ctx,
                                       int *pattern_count) {
  if (!ctx || !pattern_count) return NULL;

  *pattern_count = ctx->pattern_count;
  return ctx->patterns;
}
