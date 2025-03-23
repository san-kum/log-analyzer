#include <ctype.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>

#include "include/log_analyzer.h"

#define _POSIX_C_SOURCE 200809L

static char *trim_whitespace(char *str) {
  char *end;

  while (isspace((unsigned char)*str)) str++;
  if (*str == 0) return str;

  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end)) end--;

  *(end + 1) = 0;
  return str;
}

static time_t extract_timestamp(const char *line) {
  struct tm tm_time;
  char month_str[4];
  char *timestamp_str = strdup(line);
  char *end_ptr;

  memset(&tm_time, 0, sizeof(struct tm));

  if (sscanf(timestamp_str, "%3s %d %d:%d:%d", month_str, &tm_time.tm_mday,
             &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec) == 5) {
    if (strcmp(month_str, "Jan") == 0)
      tm_time.tm_mon = 0;
    else if (strcmp(month_str, "Feb") == 0)
      tm_time.tm_mon = 1;
    else if (strcmp(month_str, "Mar") == 0)
      tm_time.tm_mon = 2;
    else if (strcmp(month_str, "Apr") == 0)
      tm_time.tm_mon = 3;
    else if (strcmp(month_str, "May") == 0)
      tm_time.tm_mon = 4;
    else if (strcmp(month_str, "Jun") == 0)
      tm_time.tm_mon = 5;
    else if (strcmp(month_str, "Jul") == 0)
      tm_time.tm_mon = 6;
    else if (strcmp(month_str, "Aug") == 0)
      tm_time.tm_mon = 7;
    else if (strcmp(month_str, "Sep") == 0)
      tm_time.tm_mon = 8;
    else if (strcmp(month_str, "Oct") == 0)
      tm_time.tm_mon = 9;
    else if (strcmp(month_str, "Nov") == 0)
      tm_time.tm_mon = 10;
    else if (strcmp(month_str, "Dec") == 0)
      tm_time.tm_mon = 11;

    tm_time.tm_year = time(NULL) / 31536000 + 70;
    free(timestamp_str);
    return mktime(&tm_time);
  }

  if (sscanf(timestamp_str, "d-%d-%dT%d:%d:%d", &tm_time.tm_year,
             &tm_time.tm_mon, &tm_time.tm_mday, &tm_time.tm_hour,
             &tm_time.tm_min, &tm_time.tm_sec) == 6) {
    tm_time.tm_year -= 1900;
    tm_time.tm_mon--;

    free(timestamp_str);
    return mktime(&tm_time);
  }

  long timestamp = strtol(timestamp_str, &end_ptr, 10);
  if (end_ptr != timestamp_str) {
    free(timestamp_str);
    return (time_t)timestamp;
  }

  free(timestamp_str);
  return time(NULL);
}

static int extract_severity(const char *line) {
  if (strstr(line, "EMERGENCY") || strstr(line, "EMERG") ||
      strstr(line, "fatal"))
    return 0;
  else if (strstr(line, "ALERT"))
    return 1;
  else if (strstr(line, "CRITICAL") || strstr(line, "CRIT"))
    return 2;
  else if (strstr(line, "ERROR") || strstr(line, "ERR"))
    return 3;
  else if (strstr(line, "WARNING") || strstr(line, "WARN"))
    return 4;
  else if (strstr(line, "NOTICE"))
    return 5;
  else if (strstr(line, "INFO") || strstr(line, "information"))
    return 6;
  else if (strstr(line, "DEBUG"))
    return 7;

  return 6;  // default (information)
}

static char *extract_source(const char *line) {
  const char *start, *end;
  char *source;
  size_t length;

  if (line[0] == '[') {
    start = line + 1;
    end = strchr(start, ']');
    if (end) {
      length = end - start;
      source = (char *)malloc(length + 1);
      strncpy(source, start, length);
      source[length] = '\0';
      return source;
    }
  }

  end = strchr(line, ':');
  if (end) {
    length = end - line;
    if (length > 0 && length < 32) {
      source = (char *)malloc(length + 1);
      strncpy(source, line, length);
      source[length] = '\0';
      return source;
    }
  }

  source = strdup("unknown");
  return source;
}

static char *extract_process_id(const char *line) {
  const char *start, *end;
  char *pid;
  size_t length;

  start = strchr(line, '[');
  if (start) {
    start++;
    end = strchr(start, ']');
    if (end) {
      length = end - start;
      pid = (char *)malloc(length + 1);
      strncpy(pid, start, length);
      pid[length] = '\0';
      return pid;
    }
  }

  start = strstr(line, "PID ");
  if (start) {
    start += 4;
    end = start;
    while (isdigit(*end)) end++;

    if (end > start) {
      length = end - start;
      pid = (char *)malloc(length + 1);
      strncpy(pid, start, length);
      pid[length] = '\0';
      return pid;
    }
  }

  return NULL;
}

LogEntry *log_parser_parse_line(LogAnalyzerContext *ctx, const char *line) {
  LogEntry *entry;
  char *message_start;
  size_t message_length;

  if (!ctx || !line) return NULL;

  entry = (LogEntry *)malloc(sizeof(LogEntry));
  if (!entry) return NULL;

  memset(entry, 0, sizeof(LogEntry));
  entry->raw_text = strdup(line);
  entry->timestamp = extract_timestamp(line);
  entry->severity = extract_severity(line);
  entry->source = extract_source(line);
  entry->process_id = extract_process_id(line);

  message_start = strstr(line, ": ");
  if (message_start) {
    message_start += 2;
    message_length = strlen(message_start);
    entry->message = (char *)malloc(message_length + 1);
    strcpy(entry->message, message_start);
  } else {
    entry->message = strdup(line);
  }

  entry->thread_id = NULL;
  entry->additional_fields = NULL;

  return entry;
}

void log_parser_free_entry(LogEntry *entry) {
  if (!entry) return;

  free(entry->raw_text);
  free(entry->message);
  free(entry->source);
  free(entry->process_id);
  free(entry->thread_id);
  free(entry->additional_fields);

  free(entry);
}
