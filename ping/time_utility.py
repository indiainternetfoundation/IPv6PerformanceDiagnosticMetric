import sys

def get_value_ot_time_from_sec(delta, scale = 40):
    usec = int(delta * (10**6))
    nsec = int(delta * (10**9))
    atto = usec * (10**12)
    print(f"{usec = }")
    print(f"{hex(usec) = }")
    print(f"{hex(atto) = }")
    # print(f"{clamp_size(atto, 16) = }")

    return delta, scale

def countBits(n):
    count = 0
    while n:
        count+=1
        n >>= 1
    return count

def _time_attosec(nsec):
    atto_now = nsec

    atto_now = (atto_now * 1000000000) / (16*16*16)
    atto_now = int(atto_now)
    scale = 12

    while(countBits(atto_now) > 16):
        atto_now >>= 1
        scale += 1

    return atto_now, scale

def _attosec_time(delta, scale):
    delta = delta << (scale - 12)
    delta /= 1000000000
    delta *= (16*16)
    return delta




if __name__ == "__main__":
    atto_now, scale = _time_attosec(0x9b9e * 1000)
    print("time =", hex(int(_attosec_time(atto_now, scale) / 1000)))
    time = 32.311072
    print(get_value_ot_time_from_sec(delta = time, scale = 40))