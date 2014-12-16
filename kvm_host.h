/* copied from include/asm/kvm_host.h */
#include <linux/types.h>
#include <asm/vmx.h>

// hacks
#define __ex(x) x
#define __ex_clear(x,y) x
#define test_bit(x,y) (((1<<x) & *y) != 0)
#define unlikely(x) x

enum kvm_reg {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
	VCPU_REGS_RIP,
	NR_VCPU_REGS
};

enum kvm_reg_ex {
	VCPU_EXREG_PDPTR = NR_VCPU_REGS,
	VCPU_EXREG_CR3,
	VCPU_EXREG_RFLAGS,
	VCPU_EXREG_SEGMENTS,
};

enum {
	VCPU_SREG_ES,
	VCPU_SREG_CS,
	VCPU_SREG_SS,
	VCPU_SREG_DS,
	VCPU_SREG_FS,
	VCPU_SREG_GS,
	VCPU_SREG_TR,
	VCPU_SREG_LDTR,
};

struct kvm_vcpu_arch {
	unsigned long regs[NR_VCPU_REGS];
	u32 regs_avail;
	u32 regs_dirty;

	unsigned long cr0;
	unsigned long cr0_guest_owned_bits;
	unsigned long cr2;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long cr4_guest_owned_bits;
	unsigned long cr8;
};

struct kvm_vcpu {
	struct kvm_vcpu_arch arch;
};

typedef struct vmcs {
  u32 revision_id;
  u32 abort;
  char data[0];
} vmcs;

/*
 * Track a VMCS that may be loaded on a certain CPU. If it is (cpu!=-1), also
 * remember whether it was VMLAUNCHed, and maintain a linked list of all VMCSs
 * loaded on this CPU (so we can clear them if the CPU goes down).
 */
struct loaded_vmcs {
	struct vmcs *vmcs;
	int cpu;
	int launched;
};

// this is what we allocate
struct vcpu_vmx {
	struct kvm_vcpu       vcpu;
	unsigned long         host_rsp;
	u8                    fail;
	bool                  nmi_known_unmasked;
	u32                   exit_intr_info;
	u32                   idt_vectoring_info;
	ulong                 rflags;
	struct loaded_vmcs    vmcs01;
	struct loaded_vmcs   *loaded_vmcs;
	bool                  __launched; /* temporary, used in vmx_vcpu_run */
	int vpid;
	bool emulation_required;
	u32 exit_reason;
};


#define container_of(ptr, type, member) ({                      \
  const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
  (type *)( (char *)__mptr - offsetof(type,member) );})

static inline struct vcpu_vmx *to_vmx(struct kvm_vcpu *vcpu) {
  return container_of(vcpu, struct vcpu_vmx, vcpu);
}

