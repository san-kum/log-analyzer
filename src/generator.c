#include "include/log_analyzer.h"

static void add_recommendation(LogAnalyzerContext *ctx, const char *title,
                               const char *description, const char *action,
                               int priority, const char *category,
                               float confidence) {
  Recommendation *rec;

  if (!ctx || !title || ctx->recommendation_count >= MAX_RECOMMENDATIONS)
    return;

  rec = &ctx->recommendations[ctx->recommendation_count];

  rec->title = strdup(title);
  rec->description = strdup(description);
  rec->action = strdup(action);
  rec->priority = priority;
  rec->category = strdup(category);
  rec->confidence = confidence;

  ctx->recommendation_count++;
}

static void generate_cpu_recommendations(LogAnalyzerContext *ctx) {
  int i;
  Pattern *pattern;
  bool high_cpu_usage = false;
  bool high_load_average = false;

  /* Check CPU Patterns */
  for (i = 0; i < ctx->pattern_count; i++) {
    pattern = &ctx->patterns[i];
    if (pattern->frequency <= 0) continue;

    if (strcmp(pattern->category, "cpu") == 0) {
      if (strstr(pattern->description, "High CPU Usage") != NULL) {
        high_cpu_usage = true;
      } else if (strstr(pattern->description, "High Load Average") != NULL) {
        high_load_average = true;
      }
    }
  }

  if (high_cpu_usage || high_load_average) {
    add_recommendation(
        ctx, "Analyze CPU-intensive processes",
        "The system is experiencing high CPU usage or load average.",
        "Use 'top' or 'htop' to identify CPU-intensive processes. Consider "
        "optimizing or throttling these processes.",
        4, "cpu", 0.8);

    add_recommendation(ctx, "Check for runaway processes",
                       "High CPU usage might be caused by runaway processes "
                       "that need to be terminated.",
                       "Use 'ps aux' to identify processes consuming excessive "
                       "CPU and consider terminating them if appropriate.",
                       3, "cpu", 0.7);

    add_recommendation(
        ctx, "Consider resource limits",
        "Setting resource limits can prevent processes from consuming "
        "excessive CPU.",
        "Use 'ulimit' or cgroups to set CPU limits for critical processes.", 3,
        "cpu", 0.6);
  }
}

static void generate_memory_recommendations(LogAnalyzerContext *ctx) {
  int i;
  Pattern *pattern;
  bool memory_issues = false;
  bool oom_killer = false;
  bool high_swap = false;

  /* memory-related patterns */
  for (i = 0; i < ctx->pattern_count; i++) {
    pattern = &ctx->patterns[i];

    if (pattern->frequency <= 0) {
      continue;
    }

    if (strcmp(pattern->category, "memory") == 0) {
      memory_issues = true;

      if (strstr(pattern->description, "Out of memory") != NULL) {
        oom_killer = true;
      } else if (strstr(pattern->description, "High swap usage") != NULL) {
        high_swap = true;
      }
    }
  }

  if (memory_issues) {
    add_recommendation(ctx, "Analyze memory usage",
                       "The system is experiencing memory-related issues.",
                       "Use 'free', 'vmstat', and 'ps' to analyze memory usage "
                       "and identify memory-intensive processes.",
                       4, "memory", 0.8);

    if (oom_killer) {
      add_recommendation(
          ctx, "Address out-of-memory conditions",
          "The system's OOM (Out Of Memory) killer is being triggered.",
          "Increase available memory, reduce memory usage, or adjust the OOM "
          "killer settings using sysctl.",
          5, "memory", 0.9);
    }

    if (high_swap) {
      add_recommendation(
          ctx, "Reduce swap usage",
          "The system is using excessive swap space, which can degrade "
          "performance.",
          "Increase physical memory, decrease swappiness parameter, or "
          "optimize applications to reduce memory footprint.",
          3, "memory", 0.7);
    }

    add_recommendation(ctx, "Consider memory limits",
                       "Setting memory limits can prevent processes from "
                       "consuming excessive memory.",
                       "Use 'ulimit', cgroups, or container limits to restrict "
                       "memory usage for critical processes.",
                       3, "memory", 0.6);
  }
}

static void generate_disk_recommendations(LogAnalyzerContext *ctx) {
  int i;
  Pattern *pattern;
  bool disk_space_issues = false;
  bool io_errors = false;

  /* disk-related patterns */
  for (i = 0; i < ctx->pattern_count; i++) {
    pattern = &ctx->patterns[i];

    if (pattern->frequency <= 0) {
      continue;
    }

    if (strcmp(pattern->category, "disk") == 0) {
      if (strstr(pattern->description, "Disk full") != NULL ||
          strstr(pattern->description, "Filesystem near capacity") != NULL) {
        disk_space_issues = true;
      } else if (strstr(pattern->description, "I/O error") != NULL ||
                 strstr(pattern->description, "Device timeout") != NULL) {
        io_errors = true;
      }
    }
  }

  if (disk_space_issues) {
    add_recommendation(
        ctx, "Free up disk space", "The system is running low on disk space.",
        "Use 'du' and 'df' to identify large files and directories. Consider "
        "removing unnecessary files, archiving old data, or expanding storage.",
        4, "disk", 0.8);

    add_recommendation(
        ctx, "Implement disk space monitoring",
        "Regular monitoring of disk space can prevent unexpected disk full "
        "conditions.",
        "Set up monitoring with tools like Nagios, Zabbix, or custom scripts "
        "with email alerts when disk usage exceeds thresholds.",
        3, "disk", 0.7);
  }

  if (io_errors) {
    add_recommendation(
        ctx, "Check disk health",
        "I/O errors or device timeouts may indicate disk hardware issues.",
        "Use 'smartctl' to check disk health, run 'fsck' to check filesystem "
        "integrity, and consider replacing the disk if hardware issues are "
        "confirmed.",
        5, "disk", 0.8);

    add_recommendation(
        ctx, "Optimize I/O patterns",
        "Excessive or poorly optimized I/O operations can lead to timeouts and "
        "errors.",
        "Use 'iotop' to identify I/O-intensive processes and optimize their "
        "I/O patterns. Consider using buffers, caches, or asynchronous I/O.",
        3, "disk", 0.6);
  }
}

static void generate_network_recommendations(LogAnalyzerContext *ctx) {
  int i;
  Pattern *pattern;
  bool network_issues = false;
  bool timeouts = false;
  bool packet_loss = false;

  /* network-related patterns */
  for (i = 0; i < ctx->pattern_count; i++) {
    pattern = &ctx->patterns[i];

    if (pattern->frequency <= 0) {
      continue;
    }

    if (strcmp(pattern->category, "network") == 0) {
      network_issues = true;

      if (strstr(pattern->description, "Connection timeout") != NULL) {
        timeouts = true;
      } else if (strstr(pattern->description, "packet loss") != NULL) {
        packet_loss = true;
      }
    }
  }

  if (network_issues) {
    add_recommendation(
        ctx, "Check network connectivity",
        "The system is experiencing network connectivity issues.",
        "Use 'ping', 'traceroute', and 'mtr' to diagnose network connectivity "
        "problems. Check DNS resolution, firewalls, and routing.",
        4, "network", 0.8);

    if (timeouts) {
      add_recommendation(
          ctx, "Adjust connection timeouts",
          "Connection timeouts may indicate network congestion or server "
          "overload.",
          "Consider increasing connection timeout settings, implementing retry "
          "logic, or load balancing to reduce timeouts.",
          3, "network", 0.7);
    }

    if (packet_loss) {
      add_recommendation(ctx, "Address packet loss",
                         "Packet loss can degrade network performance and "
                         "cause application errors.",
                         "Check for network congestion, faulty hardware, or "
                         "misconfigured network equipment. Consider QoS "
                         "settings to prioritize critical traffic.",
                         4, "network", 0.7);
    }
  }
}

bool recommendation_generator_analyze(LogAnalyzerContext *ctx) {
  if (!ctx) return false;

  generate_cpu_recommendations(ctx);
  generate_memory_recommendations(ctx);
  generate_disk_recommendations(ctx);
  generate_network_recommendations(ctx);

  if (ctx->pattern_count > 0 && ctx->patterns[0].frequency > 0) {
    add_recommendation(ctx, "Implement regular performance monitoring",
                       "Regular monitoring can help identify and address "
                       "performance issues before they become critical.",
                       "Set up monitoring tools like Prometheus, Grafana, or "
                       "similar to track system metrics and generate alerts.",
                       2, "general", 0.9);

    add_recommendation(
        ctx, "Review system logs regularly",
        "Regular log review can help identify recurring issues and patterns.",
        "Implement log aggregation and analysis tools like ELK stack, Graylog, "
        "or similar to centralize and analyze logs.",
        2, "general", 0.8);
  }

  for (int i = 0; i < ctx->recommendation_count - 1; i++) {
    for (int j = 0; j < ctx->recommendation_count - i - 1; j++) {
      if (ctx->recommendations[j].priority <
          ctx->recommendations[j + 1].priority) {
        Recommendation temp = ctx->recommendations[j];
        ctx->recommendations[j] = ctx->recommendations[j + 1];
        ctx->recommendations[j + 1] = temp;
      }
    }
  }

  return true;
}

Recommendation *recommendation_generator_get_recommendations(
    LogAnalyzerContext *ctx, int *recommendation_count) {
  if (!ctx || !recommendation_count) return NULL;

  *recommendation_count = ctx->recommendation_count;
  return ctx->recommendations;
}
