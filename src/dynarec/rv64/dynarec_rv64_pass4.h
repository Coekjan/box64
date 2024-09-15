#define INIT
#define FINI        \
    if(ninst)       \
        addInst(dyn->instsize, &dyn->insts_size, dyn->insts[ninst].x64.size, dyn->insts[ninst].size/4); \
    addInst(dyn->instsize, &dyn->insts_size, 0, 0);
#define EMIT(A) do { dyn->insts[ninst].size += 4; } while (0)

#define MESSAGE(A, ...)
#define NEW_INST                                                                                                 \
    if (ninst)                                                                                                   \
        addInst(dyn->instsize, &dyn->insts_size, dyn->insts[ninst - 1].x64.size, dyn->insts[ninst - 1].size / 4);
#define INST_EPILOG
#define INST_NAME(name)

#define TABLE64(A, V)   {int val64offset = Table64(dyn, (V), 4); EMIT(0); EMIT(0); }
#define FTABLE64(A, V)  {mmx87_regs_t v = {.d = V}; int val64offset = Table64(dyn, v.q, 4); EMIT(0); EMIT(0); }
