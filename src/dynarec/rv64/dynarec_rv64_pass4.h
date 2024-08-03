#define INIT
#define FINI
#define EMIT(A)

#define MESSAGE(A, ...)
#define NEW_INST
#define INST_EPILOG
#define INST_NAME(name)

#define TABLE64(A, V)   {int val64offset = Table64(dyn, (V), 4);}
#define FTABLE64(A, V)  {mmx87_regs_t v = {.d = V}; int val64offset = Table64(dyn, v.q, 4);}
