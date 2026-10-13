# Bundle validator resource limits

Checklist v3 rejects ZIP inputs that exceed any of these bounds before reading entry contents:

| Limit | Maximum |
| --- | ---: |
| Compressed archive size | 256 MiB |
| Entry count | 4,096 |
| Uncompressed bytes per entry | 64 MiB |
| Total declared uncompressed bytes | 256 MiB |
| Compression ratio for entries larger than 1 KiB | 1,000:1 |

Entry reads are independently capped at 64 MiB. The validator returns a named error code (`ARCHIVE_SIZE_LIMIT`, `ENTRY_COUNT_LIMIT`, `ENTRY_SIZE_LIMIT`, `TOTAL_SIZE_LIMIT`, or `COMPRESSION_RATIO_LIMIT`) for these failures.
