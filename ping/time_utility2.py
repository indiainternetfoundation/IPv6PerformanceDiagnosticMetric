def countBits(n):
    count = 0;
    while(n):
        count+=1;
        n = int(n) >> 1;
    return count;

def _nstoas(delta_ns):
    # __int128 ns_now = ktime_get_real_ns();
    atto_now = delta_ns;   # ns_now * 10**9
                                    # ns_now * 10**3 * 10**3 * 10**3
    # atto_now = (atto_now * 1000000000)/ (16*16*16);
    atto_now = (atto_now * 1000000000) / (16*16);

    # scale = 12;         # Removed last 3 bytes = removed last 3*4 = 12 bits
    scale = 8;         # Removed last 3 bytes = removed last 3*4 = 12 bits

    # printk("atto_now: 0x%x", atto_now);

    while(countBits(atto_now) > 16):
        atto_now = int(atto_now) >> 1;
        scale += 1;

    return atto_now, scale

def _astons(delta, scale):
    ns_time = delta
    ns_time = int(ns_time) << (scale - 8)


    ns_time *= 16*16
    ns_time /= 10000
    ns_time /= 100000
    return int(ns_time)


print(_nstoas(0x9b9e * 1000))
print(_nstoas(0x785E3D500))
print(_nstoas(3*1000000000))
print(hex(_astons(*_nstoas(0x785E3D500))))