#define FIN_REG_DT uint64_t
#define FIN_REG_SIZE 255

static FIN_REG_DT FINREG[FIN_REG_SIZE];

static int push_report_reg(uint8_t index, uint64_t value);
static FIN_REG_DT pop_report_reg(uint8_t index);
static FIN_REG_DT fetch_report_reg(uint8_t index);
static int print_report_reg(void);


static int push_report_reg(uint8_t index, uint64_t value){
    if(FINREG[index] != NULL) {
        pr_err("Collision when pushing the value 0x%llx at index %u.", value, index);
    }
    FINREG[index] = value;
    return 1;
}
static FIN_REG_DT pop_report_reg(uint8_t index){
    FIN_REG_DT result = FINREG[index];
    FINREG[index] = NULL;
    return result;
}
static FIN_REG_DT fetch_report_reg(uint8_t index){
    return FINREG[index];
}
static int print_report_reg(){
    for (uint8_t i = 0; i < FIN_REG_SIZE; i++){
        if( FINREG[i] != NULL )
            pr_info("[%02d] value (%llx) : %llx", i, &FINREG[i], fetch_report_reg(i));
        else
            pr_info("[%02d] value (%llx) : Empty", i, &FINREG[i]);
    }
    return 1;
}