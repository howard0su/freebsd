#include <machine/asmacros.h>
#include <machine/specialreg.h>

#include "assym.s"

/*
 * This is the Hyper-V vmbus channel direct callback interrupt.
 * Only used when it is running on Hyper-V.
 */
        .text
        SUPERALIGN_TEXT
IDTVEC(hv_vmbus_callback)
        PUSH_FRAME
        SET_KERNEL_SREGS
        cld
        FAKE_MCOUNT(TF_EIP(%esp))
        pushl   %esp
        call    hv_vector_handler
        add     $4, %esp
        MEXITCOUNT
        jmp     doreti
