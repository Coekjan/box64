#define INIT
#define FINI
#define EMIT(A)

#define MESSAGE(A, ...)
#define NEW_INST
#define INST_EPILOG
#define INST_NAME(name)

#define TABLE64(A, V)   {int val64offset = Table64(dyn, (V), 4); MESSAGE(LOG_DUMP, "  Table64: 0x%lx\n", (V)); AUIPC(A, SPLIT20(val64offset)); LD(A, A, SPLIT12(val64offset));}
#define FTABLE64(A, V)  {mmx87_regs_t v = {.d = V}; int val64offset = Table64(dyn, v.q, 4); MESSAGE(LOG_DUMP, "  FTable64: %g\n", v.d); AUIPC(x1, SPLIT20(val64offset)); FLD(A, x1, SPLIT12(val64offset));}
