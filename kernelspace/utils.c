#include <linux/time.h>

__kernel_time_t get_time(void) {
	struct timespec ts;
	getnstimeofday(&ts);
	return ts.tv_sec;
}
