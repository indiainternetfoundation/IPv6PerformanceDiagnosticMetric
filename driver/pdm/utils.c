#include<linux/kernel.h>    // included for KERN_INFO
// #include<linux/arch/x86/boot/string.h>
#include<linux/string.h>

static void pkt_hex_dump(struct sk_buff *skb);
void remove_section(unsigned char *array, size_t length, unsigned char *start_ptr, unsigned char *end_ptr);

static void pkt_hex_dump(struct sk_buff *skb)
{
    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch;

    // printk("Packet hex dump:\n");
    // data = (uint8_t *) skb_mac_header(skb);

    if (skb_is_nonlinear(skb)) {
        len = skb->data_len;
    } else {
        len = skb->len;
    }

    // printk("%06d\t", li);
    // printk(KERN_CONT "%02X ", (uint32_t) ch);

    print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 1, skb->data, len, true);
    // print_hex_dump(KERN_DEBUG, "raw data: ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, len, true);



    // remaining = len;
    // for (i = 0; i < len; i += rowsize) {
    //     printk("%06d\t", li);

    //     linelen = min(remaining, rowsize);
    //     remaining -= rowsize;

    //     for (l = 0; l < linelen; l++) {
    //         ch = data[l];
    //         printk(KERN_CONT "%02X ", (uint32_t) ch);
    //     }

    //     data += linelen;
    //     li += 10;

    //     printk(KERN_CONT "\n");
    // }
}
void remove_section(unsigned char *array, size_t length, unsigned char *start_ptr, unsigned char *end_ptr) {
    // Calculate the start and end indices based on pointers
    size_t start_index = start_ptr - array;
    size_t end_index = end_ptr - array;

    // Validate the indices
    if (start_index >= length || end_index >= length || start_index > end_index) {
        printk("Invalid start or end pointers.\n");
        return;
    }

    // Calculate the number of elements to remove
    size_t num_elements_to_remove = end_index - start_index + 1;

    // Shift the remaining elements to the left
    memmove(array + start_index, array + end_index + 1, length - end_index - 1);

    // Adjust the length of the array
    length -= num_elements_to_remove;

    // // Optionally, you can zero out the rest of the array (for debugging purposes)
    // memset(array + length, 0, num_elements_to_remove);

}
