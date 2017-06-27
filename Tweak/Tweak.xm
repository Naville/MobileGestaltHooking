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
                        /*
                        0000000180d2c294 010080D2               movz       x1, #0x0                     ; CODE XREF=sub_180d295ac+48, sub_180d29eac+40, sub_180d2a568+32, __MGWriteCache+152, __MGWriteCache+388, sub_180d3a278+968, sub_180d3a278+1252, sub_180d3a278+1468, sub_180d3a278+3148, sub_180d3ef74+1236
                        0000000180d2c298 01000014               b          loc_180d2c29c
                        loc_180d2c29c:
                        ...
                        0000000180d2c2c0 B7FDFF97               bl         sub_180d2b99c
                        ...
                        0000000180d2c2cc DBFDFF97               bl         sub_180d2ba38
                        ...
                        We need to hook the second BL
                        */
                        //size_t counter=0;
                        for (size_t j = 0; j < count; j++) {
                              //  if(strcmp(insn[j].mnemonic,"bl")==0){
                              //    counter++;
                              //  }
                              NSLog(@"0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,insn[j].op_str);
                                if(insn[j].id==ARM64_INS_B){
                                  //Found the second BL
                                  BLInstruction=insn[j];
                                  //NSLog(@"0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,insn[j].op_str);
                                  //NSLog(@"%s",BLInstruction.op_str);
                                  sscanf(BLInstruction.op_str, "#%lx", &realMGAddress);
                                  //NSLog(@"0x%lx",realMGAddress);
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
