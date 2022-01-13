#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <string.h>  /* memcpy() */
#include <stdio.h>   /* sprintf() */

#define EXPECT(c, ch) do { assert(*c->json == (ch)); c->json++; } while(0)

#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')

typedef struct {
    const char* json;
    char* stack;
    size_t size, top;
} lept_context;

static void lept_parse_whitespace(lept_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || 
            *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

static void* lept_context_push(lept_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0) {
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        }
        while (c->top + size >= c->size) {
            c->size += c->size >> 1; /* c->size * 1.5 */
        }
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
    assert(c->top >= size);
    return (c->stack + (c->top -= size));
}

#define PUTC(c, ch) do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

static int lept_parse_value(lept_context* c, lept_value* v);

static const char* lept_parse_hex4(const char* p, unsigned* u) {
    int i;
    *u = 0;
    for (i = 0; i < 4; i++) {
        char ch = *p++;
        *u <<= 4;
        if ('0' <= ch && ch <= '9') {
            *u |= (ch - '0');
        } else if ('a' <= ch && ch <= 'f') {
            *u |= (ch - ('a' - 10));
        } else if ('A' <= ch && ch <= 'F') {
            *u |= (ch - ('A' - 10));
        } else {
            return NULL;
        }
    }
    return p;
}

static void lept_encode_utf8(lept_context* c, unsigned u) {
    assert(u >= 0x0000);

    if (u <= 0x007F) {
        PUTC(c, u & 0xFF);
    } else if (u <= 0x07FF) {
        PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
        PUTC(c, 0x80 | (u        & 0x3F));
    } else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    } else {
        assert(u <= 0x100FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >> 6)  & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
}

static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
    size_t head = c->top;
    const char* p;
    unsigned u, u2;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                *len = c->top - head;
                *str = lept_context_pop(c, *len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20) {
                    STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                }
                PUTC(c, ch);
                break;
            case '\\':
                switch (*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/' ); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = lept_parse_hex4(p, &u)))
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        if (0xD800 <= u && u <= 0xDBFF) {
                            if (*p++ != '\\') {
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            }

                            if (*p++ != 'u') {
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            }

                            if (!(p = lept_parse_hex4(p, &u2))) {
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                            }

                            if (u2 < 0xDC00 || u2 > 0xDFFF) {
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            }

                            u = 0x10000 + (u - 0xD800) * 0x400 + (u2 - 0xDC00);
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
        }
    }
}

static int lept_parse_string(lept_context* c, lept_value* v) {
    int ret;
    char* s;
    size_t len;
    if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK) {
        lept_set_string(v, s, len);
    }
    return ret;
}

static int lept_parse_object(lept_context* c, lept_value* v) {
    size_t size;
    size_t i;
    lept_member m;
    int ret;
    EXPECT(c, '{');
    lept_parse_whitespace(c);
    if (*c->json == '}') {
        c->json++;
        v->type = LEPT_OBJECT;
        v->u.o.m = 0;
        v->u.o.size = 0;
        return LEPT_PARSE_OK;
    }
    m.k = NULL;
    size = 0;
    for (;;) {
        char *str;
        lept_init(&m.v);
        /* parse key to m.k, m.klen */
        if (*c->json != '"') {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }
        if ((ret = lept_parse_string_raw(c, &str, &m.klen)) != LEPT_PARSE_OK) {
            break;
        }
        memcpy(m.k = (char*)malloc(m.klen + 1), str, m.klen);
        m.k[m.klen] = '\0';

        /* parse ws colon ws */
        lept_parse_whitespace(c);
        if (*c->json != ':') {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        lept_parse_whitespace(c);
        /* parse value */
        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK)
            break;
        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        m.k = NULL; /* ownership is transferred to member on stack */
        /* parse ws [comma | right-curly-brace] ws */
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        } else if (*c->json == '}') {
            size_t s = sizeof(lept_member) * size;
            c->json++;
            v->type = LEPT_OBJECT;
            v->u.o.size = size;
            memcpy(v->u.o.m = (lept_member*)malloc(s), lept_context_pop(c, s), s);
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    /* Pop and free members on the stack */
    free(m.k);
    for (i = 0; i < size; i++) {
        lept_member* m = (lept_member*)lept_context_pop(c, sizeof(lept_member));
        free(m->k);
        lept_free(&m->v);
    }
    v->type = LEPT_NULL;
    return ret;
}

static int lept_parse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type) {
    size_t i;
    for (i = 0; literal[i]; i++) {
        if (c->json[i] != literal[i]) {
            return LEPT_PARSE_INVALID_VALUE;
        }
    }
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v) {
    const char* p = c->json;
    
    if (*p == '-') {
        p++;
    }

    if (*p == '0') {
        p++;
    } else {
        if (!ISDIGIT1TO9(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++)
            ;
    }

    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++)
            ;
    }

    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++)
            ;
    }
    
    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE && 
        (v->u.n == HUGE_VAL || 
         v->u.n == -HUGE_VAL )) {
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static int lept_parse_array(lept_context* c, lept_value* v) {
    size_t size = 0;
    int ret, i;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    
    if (*c->json == ']') {
        c->json++;
        v->type = LEPT_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
        return LEPT_PARSE_OK;
    }

    for (;;) {
        lept_value e;
        lept_init(&e);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK) {
            break;
        }

        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;

        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        } else if (*c->json == ']') {
            c->json++;
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            size *= sizeof(lept_value);
            memcpy(v->u.a.e = (lept_value*)malloc(size), lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    /* Pop and free values on the stack */
    for (i = 0; i < size; i++)
        lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
    return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 'n':   return lept_parse_literal(c, v, "null", LEPT_NULL);
        case 'f':   return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case 't':   return lept_parse_literal(c, v, "true", LEPT_TRUE);
        default:    return lept_parse_number(c, v);
        case '"':   return lept_parse_string(c, v);
        case '[':   return lept_parse_array(c, v);
        case '\0':  return LEPT_PARSE_EXPECT_VALUE;
        case '{':   return lept_parse_object(c, v);
    }
}

void lept_free(lept_value* v) {
    size_t i;
    assert(v != NULL);
    switch (v->type) {
        case LEPT_STRING:
            /* code */
            free(v->u.s.s);
            break;
        case LEPT_ARRAY:
            for (i = 0; i < v->u.a.size; i++)
                lept_free(&v->u.a.e[i]);
            free(v->u.a.e);
            break;
        case LEPT_OBJECT:
            for (i = 0; i < v->u.o.size; i++) {
                free(v->u.o.m[i].k);
                lept_free(&v->u.o.m[i].v);
            }
            free(v->u.o.m);
            break;
        default:
            break;
    }
    v->type = LEPT_NULL;
}

int lept_parse(lept_value* v, const char* json) {
    int ret;
    lept_context c;

    assert(v != NULL);

    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;

    lept_init(v);
    lept_parse_whitespace(&c);
    
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define PUTS(c, s, len)     memcpy(lept_context_push(c, len), s, len)

static void lept_stringify_string(lept_context* c, const char* s, size_t len) {
    size_t i;
    assert(s != NULL);
    PUTC(c, '"');
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char) s[i];
        switch(ch) {
            case '\"': PUTS(c, "\\\"", 2); break;
            case '\\': PUTS(c, "\\\\", 2); break;
            case '\b': PUTS(c, "\\b",  2); break;
            case '\f': PUTS(c, "\\f",  2); break;
            case '\n': PUTS(c, "\\n",  2); break;
            case '\r': PUTS(c, "\\r",  2); break;
            case '\t': PUTS(c, "\\t",  2); break;
            default:
                if (ch < 0x20) {
                    char buffer[7];
                    sprintf(buffer, "\\u%04X", ch);
                    PUTS(c, buffer, 6);
                } else {
                    PUTC(c, s[i]);
                }
        }
    }
    PUTC(c, '"');
}

static int lept_stringify_value(lept_context* c, const lept_value* v) {
    size_t i;
    switch (v->type)
    {
        case LEPT_NULL: PUTS(c, "null", 4); break;
        case LEPT_FALSE: PUTS(c, "false", 5); break;
        case LEPT_TRUE:  PUTS(c, "true",  4); break;
        case LEPT_NUMBER: 
            c->top -= 32 - sprintf(lept_context_push(c, 32), "%.17g", v->u.n); 
            break;
        case LEPT_STRING: 
            lept_stringify_string(c, v->u.s.s, v->u.s.len); 
            break;
        case LEPT_ARRAY:
            PUTC(c, '[');
            for (i = 0; i < v->u.a.size; i++) {
                if (i > 0) {
                    PUTC(c, ',');
                }
                lept_stringify_value(c, &v->u.a.e[i]);
            }
            PUTC(c, ']');
            break;
        case LEPT_OBJECT:
            PUTC(c, '{');
            for (i = 0; i < v->u.o.size; i++) {
                if (i > 0) {
                    PUTC(c, ',');
                }
                lept_stringify_string(c, v->u.o.m[i].k, v->u.o.m[i].klen);
                PUTC(c, ':');
                lept_stringify_value(c, &v->u.o.m[i].v);
            }
            PUTC(c, '}');
            break;
        default: 
            assert("invalid type");
    }
    return LEPT_STRINGIFY_OK;
}

char* lept_stringify(const lept_value* v, size_t* length) {
    lept_context c;
    assert(v != NULL);
    c.stack = (char*) malloc(c.size = LEPT_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    lept_stringify_value(&c, v);
    if (length) {
        *length = c.top;
    }
    PUTC(&c, '\0');
    return c.stack;
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

void lept_set_number(lept_value* v, double n) {
    lept_free(v);
    v->u.n = n;
    v->type = LEPT_NUMBER;
}

int lept_get_boolean(const lept_value* v) {
    assert(v != NULL && (v->type == LEPT_FALSE || v->type == LEPT_TRUE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b) {
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

void lept_set_string(lept_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->u.s.s = (char*)malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}

void lept_set_array(lept_value* dst, size_t size) {
    assert(dst != NULL);
    lept_free(dst);
    dst->type = LEPT_ARRAY;
    dst->u.a.size = size;
    dst->u.a.e = (lept_value*) malloc(sizeof(lept_value) * dst->u.a.size);
    assert(dst->u.a.e != NULL);
}

void lept_set_object(lept_value* dst, size_t size) {
    assert(dst != NULL);
    lept_free(dst);
    dst->type = LEPT_OBJECT;
    dst->u.o.size = size;
    dst->u.o.m = (lept_member*) malloc(sizeof(lept_member) * dst->u.o.size);
    assert(dst->u.o.m != NULL);
}

const char* lept_get_string(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_string_length(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

size_t lept_get_array_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

lept_value* lept_get_array_element(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}

lept_value* lept_set_object_value(lept_value* v, const char* key, size_t klen) {
    size_t index = LEPT_KEY_NOT_EXIST;
    index = lept_find_object_index(v, key, klen);
    if (index != LEPT_KEY_NOT_EXIST) {
        return &v->u.o.m[index].v;
    }
    v->u.o.m = realloc(v->u.o.m, (v->u.o.size + 1) * sizeof(lept_member));
    v->u.o.m[v->u.o.size].k = (char*) malloc(sizeof(char) * (klen + 1));
    strncpy(v->u.o.m[v->u.o.size].k, key, klen);
    v->u.o.m[v->u.o.size].k[klen] = '\0';
    return &v->u.o.m[v->u.o.size++].v;
}

size_t lept_get_object_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.size;
}

const char* lept_get_object_key(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

lept_value* lept_get_object_value(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}

size_t lept_find_object_index(const lept_value* v, const char* key, size_t klen) {
    size_t i;
    assert(v != NULL && v->type == LEPT_OBJECT && key != NULL);
    for (i = 0; i < v->u.o.size; i++) {
        if (v->u.o.m[i].klen == klen && memcmp(v->u.o.m[i].k, key, klen) == 0) {
            return i;
        }
    }
    return LEPT_KEY_NOT_EXIST;
}

lept_value* lept_find_object_value(lept_value* v, const char* key, size_t klen) {
    size_t index = lept_find_object_index(v, key, klen);
    return index != LEPT_KEY_NOT_EXIST ? &v->u.o.m[index].v : NULL;
}

int lept_is_equal(const lept_value* lhs, const lept_value* rhs) {
    size_t i;
    assert(lhs != NULL && rhs != NULL);
    if (lhs->type != rhs->type) {
        return 0;
    }

    switch (lhs->type) {
        case LEPT_STRING:
            return lhs->u.s.len == rhs->u.s.len &&
                memcmp(lhs->u.s.s, rhs->u.s.s, lhs->u.s.len) == 0;
        case LEPT_NUMBER:
            return lhs->u.n == rhs->u.n;
        case LEPT_ARRAY:
            if (lhs->u.a.size != rhs->u.a.size) {
                return 0;
            }
            for (i = 0; i < lhs->u.a.size; i++) {
                if (!lept_is_equal(&lhs->u.a.e[i], &rhs->u.a.e[i])) {
                    return 0;
                }
            }
            return 1;
        case LEPT_OBJECT:
            if (lhs->u.o.size != rhs->u.o.size) {
                return 0;
            }
            for (i = 0; i < lhs->u.o.size; i++) {
                int idx = lept_find_object_index(rhs, lhs->u.o.m[i].k, lhs->u.o.m[i].klen);
                if (LEPT_KEY_NOT_EXIST == idx) {
                    return 0;
                }
                if (!lept_is_equal(&lhs->u.o.m[i].v, &rhs->u.o.m[idx].v)) {
                    return 0;
                }
            }
            return 1;
        default:
            return 1;
    }
}

void lept_copy(lept_value* dst, const lept_value* src) {
    size_t i;
    assert(src != NULL && dst != NULL && src != dst);
    
    switch (src->type) {
        case LEPT_STRING:
            lept_set_string(dst, src->u.s.s, src->u.s.len);
            break;
        case LEPT_ARRAY:
            lept_set_array(dst, src->u.a.size);
            for (i = 0; i < src->u.a.size; i++) {
                lept_copy(&dst->u.a.e[i], &src->u.a.e[i]);
            }
            break;
        case LEPT_OBJECT:
            lept_set_object(dst, src->u.o.size);
            for (i = 0; i < src->u.o.size; i++) {
                dst->u.o.m[i].klen = src->u.o.m[i].klen;
                dst->u.o.m[i].k = (char*) malloc(sizeof(char) * (dst->u.o.m[i].klen + 1));
                strncpy(dst->u.o.m[i].k, src->u.o.m[i].k, dst->u.o.m[i].klen);
                dst->u.o.m[i].k[dst->u.o.m[i].klen] = '\0';
                lept_init(&dst->u.o.m[i].v);
                lept_copy(&dst->u.o.m[i].v, &src->u.o.m[i].v);
            }
            break;
        default:
            lept_free(dst);
            memcpy(dst, src, sizeof(lept_value));
            break;
    }
}

void lept_move(lept_value* dst, lept_value* src) {
    assert(dst != NULL && src != NULL && src != dst);
    lept_free(dst);
    memcpy(dst, src, sizeof(lept_value));
    lept_init(src);
}

void lept_swap(lept_value* lhs, lept_value* rhs) {
    lept_value temp;
    assert(lhs != NULL && rhs != NULL);
    if (lhs != rhs) {
        memcpy(&temp, lhs, sizeof(lept_value));
        memcpy(lhs, rhs, sizeof(lept_value));
        memcpy(rhs, &temp, sizeof(lept_value));
    }
}
