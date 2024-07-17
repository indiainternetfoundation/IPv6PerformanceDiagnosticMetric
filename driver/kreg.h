#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/ktime.h>

static struct pdm_segmented_key_array {
    uint64_t id_value;
    uint64_t time;
    uint16_t psntp;
    uint8_t  proto_type;
};
// #define K_REG_DT int*
// #define K_REG_DT uint64_t
#define K_REG_DT struct pdm_segmented_key_array
#define K_SEG_SIZE 1
#define K_REG_SIZE 16 // 32
#define IDX(key, segment) (segment * K_REG_SIZE) + (key % K_REG_SIZE)
// #define IDX(key) key % K_REG_SIZE

static K_REG_DT *KREG;  // Pointer to the dynamically allocated array
static K_REG_DT *KREG_NULL;  // Pointer to the dynamically allocated array

static int kreg_init(void);
static int is_null(K_REG_DT value);
static int kreg_destroy(void);
static void printk_kreg(void);
static int kreg_push(int key, int segment, K_REG_DT value);
static K_REG_DT kreg_fetch(int key, int segment);
static K_REG_DT kreg_pop(int key, int segment);
static void __dump_pdm_segmented_key_array(struct pdm_segmented_key_array pdm_element);

static int kreg_init() {

    // Allocate memory for the array
    KREG = kmalloc(K_REG_SIZE * K_SEG_SIZE * sizeof(K_REG_DT), GFP_KERNEL);
    KREG_NULL = kmalloc(sizeof(K_REG_DT), GFP_KERNEL);
    if (!KREG) {
        pr_debug("PDM Error : Failed to allocate memory\n");
        return -1;
    }

    // Initialize all elements to NULL
    for (int i = 0; i < K_REG_SIZE * K_SEG_SIZE; i++) {
        KREG[i] = *KREG_NULL;
    }

    // Success
    return 1;
}
static int is_null(K_REG_DT value){
    return value.proto_type == 0 && value.psntp == 0 && value.time == 0 && value.id_value == 0;
}
static int make_null(K_REG_DT *value){
    value->proto_type = 0;
    value->psntp = 0;
    value->time = 0;
    value->id_value = 0;

    return 1;
}
static int are_equal(K_REG_DT first, K_REG_DT second){
    return first.proto_type == second.proto_type && first.psntp == second.psntp && first.time == second.time && first.id_value == second.id_value;
}
static int kreg_push(int key, int segment, K_REG_DT value) {
    if ( !is_null(KREG[IDX(key, segment)]))
        pr_debug("PDM ERROR : Collision Occured! Overwriting element at %d, from value %llx to %llx\n", IDX(key, segment), KREG[IDX(key, segment)], value);
    KREG[IDX(key, segment)] = value;
    // __dump_pdm_segmented_key_array(KREG[IDX(key, segment)]);
    if ( are_equal(KREG[IDX(key, segment)], value ) )
        // Success
        return 1;
    return -1;
}
static K_REG_DT kreg_fetch(int key, int segment) {
    return KREG[IDX(key, segment)];
}
static K_REG_DT kreg_pop(int key, int segment) {
    K_REG_DT result = KREG[IDX(key, segment)];
    make_null(&KREG[IDX(key, segment)]);
    return result;
}
static int kreg_destroy() {

    // Free the allocated memory
    if (KREG != NULL) {
        kfree(KREG);
        KREG = NULL;
    }
    if (KREG_NULL != NULL) {
        kfree(KREG_NULL);
        KREG_NULL = NULL;
    }

    // Unable to clear memory
    if (KREG)
        return -ENOMEM;
    if (KREG_NULL)
        return -ENOMEM;

    // Success
    return 1;
}
static void printk_kreg(){
    for (int i = 0; i < K_REG_SIZE * K_SEG_SIZE; i++){
        // if( memcmp( &KREG[i], &KREG_NULL, sizeof(K_REG_DT)))
        if( !is_null(KREG[i]) )
            pr_debug("[%d][%02d] value (%llx) : %llx", i / K_REG_SIZE, i % K_REG_SIZE, kreg_fetch(i, i / K_REG_SIZE), &KREG[i]);
        else
            pr_debug("[%d][%02d] value (%llx) : Empty", i / K_REG_SIZE, i % K_REG_SIZE, &KREG[i]);
    }
}
static void printk_kreg_segment(int segment){
    for (int i = IDX(0, segment); i < IDX(K_REG_SIZE, segment); i++){
        // if( memcmp( &KREG[i], &KREG_NULL, sizeof(K_REG_DT)))
        if( !is_null(KREG[i]) )
            pr_debug("[%d][%02d] value (%llx) : %llx", i / K_REG_SIZE, i % K_REG_SIZE, kreg_fetch(i, i / K_REG_SIZE), &KREG[i]);
        else
            pr_debug("[%d][%02d] value (%llx) : Empty", i / K_REG_SIZE, i % K_REG_SIZE, &KREG[i]);
    }
}
static void __dump_pdm_segmented_key_array(struct pdm_segmented_key_array pdm_element){
    pr_debug("struct pdm_segmented_key_array pdm_element = {");
    pr_debug("    .id_value = %llu,", pdm_element.id_value);
    pr_debug("    .time = %llu,", pdm_element.time);
    pr_debug("    .psntp = %d,", pdm_element.psntp);
    pr_debug("    .proto_type = %u", pdm_element.proto_type);
    pr_debug("};");
}


