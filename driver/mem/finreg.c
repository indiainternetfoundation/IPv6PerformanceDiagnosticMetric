#ifndef FINREGDEF

#define FIN_REG_DT uint64_t
#define FIN_REG_SIZE 255

static FIN_REG_DT FINREG[FIN_REG_SIZE] = {0};

int push_report_reg(uint8_t index, uint64_t value);
FIN_REG_DT pop_report_reg(uint8_t index);
FIN_REG_DT fetch_report_reg(uint8_t index);
int print_report_reg(void);


int push_report_reg(uint8_t index, uint64_t value){
    if(FINREG[index] != 0) {
        pr_err("Collision when pushing the value 0x%llx at index %u.", value, index);
    }
    FINREG[index] = value;
    return 1;
}
FIN_REG_DT pop_report_reg(uint8_t index){
    FIN_REG_DT result = FINREG[index];
    FINREG[index] = 0;
    return result;
}
FIN_REG_DT fetch_report_reg(uint8_t index){
    return FINREG[index];
}
int print_report_reg(){
    for (uint8_t i = 0; i < FIN_REG_SIZE; i++){
        if( FINREG[i] != 0 )
            pr_info("[%02d] => %p", i, &FINREG[i]);
        else
            pr_info("[%02d] => Empty", i);
    }
    return 1;
}
#define FINREGDEF
#endif