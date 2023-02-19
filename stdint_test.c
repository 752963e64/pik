#include "nolibc.h"

int main(void)
{
  printf(
    "%d, %d, %d, %ld, %d, %d, %u, %lu, %d, %d, %d, %d\n",
    INT8_C(0x7FFFFFFFFFFFFFFF),
    INT16_C(0x7FFFFFFFFFFFFFFF),
    INT32_C(0x7FFFFFFFFFFFFFFF),
    INT64_C(0x7FFFFFFFFFFFFFFF),
    (unsigned)UINT8_C(0xFFFFFFFFFFFFFFFF),
    (unsigned)UINT16_C(0xFFFFFFFFFFFFFFFF),
    (unsigned)UINT32_C(0xFFFFFFFFFFFFFFFF),
    (unsigned)UINT64_C(0xFFFFFFFFFFFFFFFF),
    sizeof (INT8_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (INT16_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (INT32_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (INT64_C(0x7FFFFFFFFFFFFFFF))
  );
  return 0;
}

