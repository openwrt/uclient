#ifndef __PROGRESS_H
#define __PROGRESS_H

#include <sys/types.h>

struct progress {
	unsigned int last_size;
	unsigned int last_update_sec;
	unsigned int last_change_sec;
	unsigned int start_sec;
	char *curfile;
};


void progress_init(struct progress *p, const char *curfile);
void progress_update(struct progress *p, off_t beg_size,
		     off_t transferred, off_t totalsize);

static inline void
progress_free(struct progress *p)
{
	free(p->curfile);
}

#endif
