#include <stdio.h>

#include "include/log_analyzer.h"

static FILE *get_output_file(LogAnalyzerContext *ctx) {
  if (!ctx || strlen(ctx->output_path) == 0) return stdout;

  FILE *fp = fopen(ctx->output_path, "w");
  if (!fp) {
    perror("Failed to open output file");
    return stdout;
  }

  return fp;
}

static void close_output_file(FILE *fp) {
  if (fp && fp != stdout) fclose(fp);
}

bool report_generator_write_summary(LogAnalyzerContext *ctx) {
  FILE *fp;
  int i;

  if (!ctx) return false;

  fp = get_output_file(ctx);

  fprintf(fp, "============================================================\n");
  fprintf(fp, "                 LOG ANALYZER SUMMARY REPORT                \n");
  fprintf(fp,
          "============================================================\n\n");

  fprintf(fp, "Input file: %s\n", ctx->input_path);
  fprintf(fp, "Log Format: %s\n\n",
          strlen(ctx->log_format) > 0 ? ctx->log_format : "Auto-detected");

  if (ctx->pattern_count > 0) {
    fprintf(fp, "Top Patterns Detected:\n");
    fprintf(fp, "-----------------------------------------------\n");

    for (i = 0; i < ctx->pattern_count && i < 5; i++) {
      if (ctx->patterns[i].frequency > 0) {
        fprintf(fp, "[%d] %s (Frequency: %d, Severity: %d)\n", i + 1,
                ctx->patterns[i].description, ctx->patterns[i].frequency,
                ctx->patterns[i].severity);
      }
    }
    fprintf(fp, "\n");
  } else {
    fprintf(fp, "No significant patterns detected.\n\n");
  }

  if (ctx->recommendation_count > 0) {
    fprintf(fp, "Top Recommendations:\n");
    fprintf(fp, "-----------------------------------------------\n");

    for (i = 0; i < ctx->recommendation_count && i < 5; i++) {
      fprintf(fp, "[%d] %s Priority: %d\n", i + 1,
              ctx->recommendations[i].title, ctx->recommendations[i].priority);
      fprintf(fp, "    %s\n\n", ctx->recommendations[i].action);
    }
  } else {
    fprintf(fp, "No recommendations generated.\n\n");
  }

  fprintf(fp, "============================================================\n");
  fprintf(fp, "For detailed information, see the detailed report.\n");
  fprintf(fp, "============================================================\n");

  close_output_file(fp);
  return true;
}

bool report_generator_write_detailed(LogAnalyzerContext *ctx) {
  FILE *fp;
  int i;
  char detailed_path[MAX_PATH_LENGTH + 16];
  if (!ctx) return false;
  if (strlen(ctx->output_path) > 0) {
    snprintf(detailed_path, sizeof(detailed_path), "%s.detailed",
             ctx->output_path);
  } else {
    snprintf(detailed_path, sizeof(detailed_path), "log_analysis_detailed.txt");
  }

  fp = fopen(detailed_path, "w");
  if (!fp) {
    perror("Failed to open detailed report file");
    return false;
  }

  fprintf(fp, "============================================================\n");
  fprintf(fp, "                LOG ANALYZER DETAILED REPORT                \n");
  fprintf(fp,
          "============================================================\n\n");

  fprintf(fp, "Input File: %s\n", ctx->input_path);
  fprintf(fp, "Log Format: %s\n\n",
          strlen(ctx->log_format) > 0 ? ctx->log_format : "Auto-detected");

  fprintf(fp, "============================================================\n");
  fprintf(fp, "                      DETECTED PATTERNS                     \n");
  fprintf(fp,
          "============================================================\n\n");

  if (ctx->pattern_count > 0) {
    for (i = 0; i < ctx->pattern_count; i++) {
      if (ctx->patterns[i].frequency > 0) {
        fprintf(fp, "Pattern %d:\n", i + 1);
        fprintf(fp, "  Description: %s\n", ctx->patterns[i].description);
        fprintf(fp, "  Category: %s\n", ctx->patterns[i].category);
        fprintf(fp, "  Severity: %d\n", ctx->patterns[i].severity);
        fprintf(fp, "  Frequency: %d\n", ctx->patterns[i].frequency);
        fprintf(fp, "  Regular Expression: %s\n\n", ctx->patterns[i].pattern);
      }
    }
  } else {
    fprintf(fp, "No significant patterns detected.\n\n");
  }

  fprintf(fp, "============================================================\n");
  fprintf(fp, "                     RECOMMENDATIONS                        \n");
  fprintf(fp,
          "============================================================\n\n");

  if (ctx->recommendation_count > 0) {
    for (i = 0; i < ctx->recommendation_count; i++) {
      fprintf(fp, "Recommendation %d:\n", i + 1);
      fprintf(fp, "  Title: %s\n", ctx->recommendations[i].title);
      fprintf(fp, "  Description: %s\n", ctx->recommendations[i].description);
      fprintf(fp, "  Action: %s\n", ctx->recommendations[i].action);
      fprintf(fp, "  Category: %s\n", ctx->recommendations[i].category);
      fprintf(fp, "  Priority: %d\n", ctx->recommendations[i].priority);
      fprintf(fp, "  Confidence: %.2f\n\n", ctx->recommendations[i].confidence);
    }
  } else {
    fprintf(fp, "No recommendations generated.\n\n");
  }

  fprintf(fp, "============================================================\n");
  fprintf(fp, "            End of ML-Based Log Analyzer Report             \n");
  fprintf(fp, "============================================================\n");

  fclose(fp);

  return true;
}
