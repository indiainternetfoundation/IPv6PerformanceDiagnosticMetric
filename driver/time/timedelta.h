#include <linux/ktime.h>
#include <linux/math.h>

#ifndef TIMEDELTA
struct time {
    uint16_t delta;
    uint8_t scale;
};
#define TIMEDELTA
#endif


unsigned int countBits(unsigned int n);
struct time _nstoas(uint64_t delta_ns);
uint64_t _astons(struct time timedelta);
void __dump_time(struct time _time);