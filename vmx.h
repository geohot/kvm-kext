#include <linux/types.h>

typedef struct vmcs {
  u32 revision_id;
  u32 abort;
  char data[0];
} vmcs;

