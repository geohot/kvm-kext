static inline unsigned long vmcs_readl(unsigned long field)
{
  //if (vmcs_loaded == 0) { printf("ERROR VMCS NOT LOADED\n"); }
	unsigned long value = 0xBADC0DE;
	u8 error;

	asm volatile (__ex_clear(ASM_VMX_VMREAD_RDX_RAX "; setna %1", "%0")
		      : "=a"(value), "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error))
    printf("vmread error: reg %lx value %lx\n", field, value);
	return value;
}

static inline u16 vmcs_read16(unsigned long field)
{
	return vmcs_readl(field);
}

static inline u32 vmcs_read32(unsigned long field)
{
	return vmcs_readl(field);
}

static inline u64 vmcs_read64(unsigned long field)
{
	return vmcs_readl(field);
}

static void vmcs_writel(unsigned long field, unsigned long value)
{
  //if (vmcs_loaded == 0) { printf("ERROR VMCS NOT LOADED\n"); }
  //printf("write: %lx <- %lx\n", field, value);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error))
    printf("vmwrite error: reg %lx value %lx (err %d)\n", field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
}

static void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write64(unsigned long field, u64 value)
{
	vmcs_writel(field, value);
}

/*static void vmcs_clear_bits(unsigned long field, u32 mask)
{
	vmcs_writel(field, vmcs_readl(field) & ~mask);
}

static void vmcs_set_bits(unsigned long field, u32 mask)
{
	vmcs_writel(field, vmcs_readl(field) | mask);
}*/

static void vmcs_load(struct vmcs *vmcs) {
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMPTRLD_RAX) "; setna %0"
			: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
			: "cc", "memory");
	if (error)
		printf("kvm: vmptrld %p/%llx failed\n", vmcs, phys_addr);
}


static void vmcs_clear(struct vmcs *vmcs) {
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMCLEAR_RAX) "; setna %0"
		      : "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");
	if (error)
		printf("kvm: vmclear fail: %p/%llx\n", vmcs, phys_addr);
}

typedef u64            gpa_t;
static inline void __invept(int ext, u64 eptp, gpa_t gpa) {
  struct {
    u64 eptp, gpa; 
  } operand = {eptp, gpa};

  asm volatile (__ex(ASM_VMX_INVEPT)
      /* CF==1 or ZF==1 --> rc = -1 */
      : : "a" (&operand), "c" (ext) : "cc", "memory");
}


