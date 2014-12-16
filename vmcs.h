static inline unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (__ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}

/*static inline u16 vmcs_read16(unsigned long field)
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
}*/

static inline void vmwrite_error(unsigned long field, unsigned long value)
{
	printf("vmwrite error: reg %lx value %lx (err %d)\n", field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
}

static void vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (__ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error))
		vmwrite_error(field, value);
}

/*static void vmcs_write16(unsigned long field, u16 value)
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

static void vmcs_clear_bits(unsigned long field, u32 mask)
{
	vmcs_writel(field, vmcs_readl(field) & ~mask);
}

static void vmcs_set_bits(unsigned long field, u32 mask)
{
	vmcs_writel(field, vmcs_readl(field) | mask);
}*/

