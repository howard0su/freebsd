//===-- RegisterContextCorePOSIX_arm64.h -----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===---------------------------------------------------------------------===//

#ifndef liblldb_RegisterContextCorePOSIX_arm64_H_
#define liblldb_RegisterContextCorePOSIX_arm64_H_

#include "lldb/Core/DataBufferHeap.h"
#include "Plugins/Process/Utility/RegisterContextPOSIX_arm64.h"

class RegisterContextCorePOSIX_arm64 :
    public RegisterContextPOSIX_arm64
{
public:
    RegisterContextCorePOSIX_arm64 (lldb_private::Thread &thread,
                                     lldb_private::RegisterInfoInterface *register_info,
                                     const lldb_private::DataExtractor &gpregset,
                                     const lldb_private::DataExtractor &fpregset);

    ~RegisterContextCorePOSIX_arm64();

    virtual bool
    ReadRegister(const lldb_private::RegisterInfo *reg_info, lldb_private::RegisterValue &value);

    virtual bool
    WriteRegister(const lldb_private::RegisterInfo *reg_info, const lldb_private::RegisterValue &value);

    bool
    ReadAllRegisterValues(lldb::DataBufferSP &data_sp);

    bool
    WriteAllRegisterValues(const lldb::DataBufferSP &data_sp);

    bool
    HardwareSingleStep(bool enable);

protected:
    bool
    ReadGPR();

    bool
    ReadFPR();

    bool
    WriteGPR();

    bool
    WriteFPR();

private:
    lldb::DataBufferSP m_gpr_buffer;
    lldb_private::DataExtractor m_gpr;
};

#endif // #ifndef liblldb_RegisterContextCorePOSIX_arm64_H_
