#include <linux/ktime.h>
#include <linux/math.h>
#include "timedelta.h"

unsigned int countBits(unsigned int n) {
    unsigned int count = 0;
    while(n) {
        count++;
        n >>= 1;
    }
    return count;
}
struct time _nstoas(uint64_t delta_ns){
    uint64_t atto_now = delta_ns;

    atto_now *= 1000;
    atto_now >>= 16;
    atto_now *= 1000;
    atto_now *= 1000;

    uint8_t scale = 16;         // Removed last 3 bytes = removed last 3*4 = 12 bits

    while(countBits(atto_now) > 16) {
        atto_now >>= 1;
        scale += 1;
    }

    return (struct time) {.delta = atto_now, .scale = scale};
}
uint64_t _astons(struct time timedelta){
    uint64_t ns_time = timedelta.delta;
    ns_time <<= (timedelta.scale - 12);

    ns_time /= 100000;
    ns_time *= 16*16*16;
    ns_time /= 10000;
    return ns_time;
}
void __dump_time(struct time _time){
    pr_info("static struct time {");
    pr_info("    uint16_t delta : 0x%x;", _time.delta);
    pr_info("    uint8_t scale : %u;", _time.scale);
    pr_info("}");
}