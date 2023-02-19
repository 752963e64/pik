#include "nolibc.h"

int main(void)
{
  printf(
    "%d, %d, %d, %ld, %d, %d, %u, %lu, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d\n",
    INT8_C(0x7FFFFFFFFFFFFFFF),
    INT16_C(0x7FFFFFFFFFFFFFFF),
    INT32_C(0x7FFFFFFFFFFFFFFF),
    INT64_C(0x7FFFFFFFFFFFFFFF),
    UINT8_C(0xFFFFFFFFFFFFFFFF),
    UINT16_C(0xFFFFFFFFFFFFFFFF),
    UINT32_C(0xFFFFFFFFFFFFFFFF),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
    sizeof (INT8_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (INT16_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (INT32_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (INT64_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (UINT8_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (UINT16_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (UINT32_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (UINT64_C(0x7FFFFFFFFFFFFFFF)),
    sizeof (INT8_C(0x7)),
    sizeof (INT16_C(0x7FF)),
    sizeof (INT32_C(0x7FFF)),
    sizeof (INT64_C(0x7FFFFFFF)),
    sizeof (UINT8_C(0x7)),
    sizeof (UINT16_C(0x7FF)),
    sizeof (UINT32_C(0x7FFFF)),
    sizeof (UINT64_C(0x7FFFFFFF))
  );
  return 0;
}

