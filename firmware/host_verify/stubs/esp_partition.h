// Host test stub for ESP-IDF's esp_partition.h -- just the pieces
// ota_verify.h's journal/recovery logic reads (subtype is the field it
// actually compares against the journaled target).
#ifndef HOST_STUB_ESP_PARTITION_H
#define HOST_STUB_ESP_PARTITION_H

#include <stdint.h>

typedef enum { ESP_PARTITION_TYPE_DATA = 1, ESP_PARTITION_TYPE_APP = 0 } esp_partition_type_t;
typedef uint8_t esp_partition_subtype_t;
typedef struct { uint32_t handle; } esp_partition_mmap_handle_t;
typedef enum { ESP_PARTITION_MMAP_DATA } esp_partition_mmap_memory_t;

typedef struct {
  esp_partition_type_t type;
  esp_partition_subtype_t subtype;
  uint32_t address;
  uint32_t size;
  char label[16];
} esp_partition_t;

#endif
