#import <substrate.h>
#import "capstone.h"
static CFStringRef (*old_MGCA)(CFStringRef Key);
CFStringRef new_MGCA(CFStringRef Key){
        CFStringRef Ret=old_MGCA(Key);
        NSLog(@"MGHooker:%@\nReturn Value:%@",Key,Ret);
        return Ret;
}
%ctor {
        void * Symbol=MSFindSymbol(MSGetImageByName("/usr/lib/libMobileGestalt.dylib"), "_MGCopyAnswer");
        NSLog(@"MG: %p",Symbol);
        csh handle;
        cs_insn *insn;
        cs_insn BLInstruction;
        size_t count;
        unsigned long realMGAddress=0;
        //MSHookFunction(Symbol,(void*)new_MGCA, (void**)&old_MGCA);
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) == CS_ERR_OK) {
          /*cs_disasm(csh handle,
          		const uint8_t *code, size_t code_size,
          		uint64_t address,
          		size_t count,
          		cs_insn **insn);*/
                count=cs_disasm(handle,(const uint8_t *)Symbol,0x1000,(uint64_t)Symbol,0,&insn);
                if (count > 0) {
                        NSLog(@"Found %lu instructions",count);
                        for (size_t j = 0; j < count; j++) {
                              NSLog(@"0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,insn[j].op_str);
                                if(insn[j].id==ARM64_INS_B){
                                  BLInstruction=insn[j];
                                  sscanf(BLInstruction.op_str, "#%lx", &realMGAddress);
                                  break;
                                }
                        }

                        cs_free(insn, count);
                } else{
                  NSLog(@"ERROR: Failed to disassemble given code!%i \n",cs_errno(handle));
                }


                cs_close(&handle);

                //Now perform actual hook
                MSHookFunction((void*)realMGAddress,(void*)new_MGCA, (void**)&old_MGCA);
}
else{
        NSLog(@"MGHooker: CSE Failed");
}
}
