#include <linux/ktime.h>
#include <linux/math.h>

static struct time {
    uint16_t delta;
    uint8_t scale;
};

static struct time _nstoas(uint64_t delta_ns);
static uint64_t _astons(struct time timedelta);
static void __dump_time(struct time _time);

unsigned int countBits(unsigned int n) {
    unsigned int count = 0;
    while(n) {
        count++;
        n >>= 1;
    }
    return count;
}
static struct time _nstoas(uint64_t delta_ns){
    uint64_t atto_now = delta_ns;   // ns_now * 10**9
                                    // ns_now * 10**3 * 10**3 * 10**3
    // atto_now = (atto_now * 1000000000) / (16*16);
    //           `----------------------'  `-------'
    //                  nanosecond to      Remove the
    //                   attosecond        last 2 bytes
    atto_now = (atto_now * 100000) / (16*16);
    atto_now *= 10000;

    uint8_t scale = 8;         // Removed last 3 bytes = removed last 3*4 = 12 bits

    while(countBits(atto_now) > 16) {
        atto_now >>= 1;
        scale += 1;
    }

    return (struct time) {.delta = atto_now, .scale = scale};
    // struct time _time =  {.delta = delta, .scale = scale};
    // return _time;

}
static uint64_t _astons(struct time timedelta){
    uint64_t ns_time = timedelta.delta;
    ns_time <<= (timedelta.scale - 12);


    ns_time /= 100000;
    ns_time *= 16*16;
    ns_time /= 10000;
    return ns_time;
}

static void __dump_time(struct time _time){
    printk("static struct time {");
    printk("    uint16_t delta : %x;", _time.delta);
    printk("    uint8_t scale : %u;", _time.scale);
    printk("}");
}
