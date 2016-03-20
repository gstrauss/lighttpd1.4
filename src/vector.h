#ifndef LI_VECTOR_H
#define LI_VECTOR_H
#include "first.h"

#ifndef SIZE_MAX
# ifdef SIZE_T_MAX
#  define SIZE_MAX SIZE_T_MAX
# else
#  define SIZE_MAX ((size_t)~0)
# endif
#endif

#include <stdlib.h>
#include <string.h>

static inline size_t vector_align_size(size_t s) {
	size_t a = (s + 16) & ((size_t)~15);
	return (a < s) ? s : a;
}

void *vector_realloc(void *data, size_t elem_size, size_t size, size_t used);

#define DEFINE_TYPED_VECTOR(name, entry, release) \
	typedef struct vector_ ## name { \
		entry* data; \
		size_t used; \
		size_t size; \
	} vector_ ## name; \
	static inline void vector_ ## name ## _init(vector_ ## name *v) { \
		v->data = NULL; \
		v->used = v->size = 0; \
	} \
	static inline vector_ ## name *vector_ ## name ## _alloc() { \
		vector_ ## name *v = (vector_ ## name *)malloc(sizeof(*v)); \
		force_assert(NULL != v); \
		vector_ ## name ## _init(v); \
		return v; \
	} \
	static inline void vector_ ## name ## _clear(vector_ ## name *v) { \
		size_t ndx; \
		if (release) for (ndx = 0; ndx < v->used; ++ndx) release(v->data[ndx]); \
		free(v->data); \
		vector_ ## name ## _init(v); \
	} \
	static inline void vector_ ## name ## _free(vector_ ## name *v) { \
		if (NULL != v) { \
			vector_ ## name ## _clear(v); \
			free(v); \
		} \
	} \
	static inline void vector_ ## name ## _reserve(vector_ ## name *v, size_t p) { \
		if (p <= v->size - v->used) return; \
		force_assert(p <= SIZE_MAX - v->used); \
		v->size = vector_align_size(v->used + p); \
		force_assert(v->size <= SIZE_MAX / sizeof(entry)); \
		v->data = (entry *)realloc(v->data, v->size * sizeof(entry)); \
		force_assert(NULL != v->data); \
	} \
	static inline void vector_ ## name ## _push(vector_ ## name *v, entry e) { \
		vector_ ## name ## _reserve(v, 1); \
		v->data[v->used++] = e; \
	} \
	static inline entry vector_ ## name ## _pop(vector_ ## name *v) { \
		force_assert(v->used > 0); \
		return v->data[--v->used]; \
	} \
	struct vector_ ## name /* expect trailing semicolon */ \
	/* end of DEFINE_TYPED_VECTOR */

#define DEFINE_TYPED_VECTOR_NO_RELEASE(name, entry) \
	DEFINE_TYPED_VECTOR(name, entry, ((void(*)(entry)) NULL)) \
	/* end of DEFINE_TYPED_VECTOR_NO_RELEASE */


#endif
