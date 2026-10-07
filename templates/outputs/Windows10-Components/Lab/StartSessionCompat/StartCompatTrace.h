#ifndef START_COMPAT_TRACE_H
#define START_COMPAT_TRACE_H
#define START_TRACE_COUNT 256
#define START_TRACE_CHARS 1024
typedef struct { volatile LONG sequence; wchar_t text[START_TRACE_CHARS]; } START_TRACE_ENTRY;
typedef struct { volatile LONG nextSequence; START_TRACE_ENTRY entries[START_TRACE_COUNT]; } START_TRACE_STATE;
#endif
