
void init_guest_values_from_host() {
  u64 value;
  u16 selector;
  struct dtr gdtb, idtb;

  vmcs_writel(GUEST_CR0, get_cr0()); 
  vmcs_writel(GUEST_CR3, get_cr3_raw()); 
  vmcs_writel(GUEST_CR4, get_cr4());

  u16 sel_value;
  u32 unusable_ar = 0x10000;
  u32 usable_ar; 
  vmcs_write32(GUEST_ES_LIMIT,0xFFFFFFFF); 
  vmcs_write32(GUEST_DS_LIMIT,0xFFFFFFFF); 
  vmcs_write32(GUEST_FS_LIMIT,0xFFFFFFFF); 
  vmcs_write32(GUEST_GS_LIMIT,0xFFFFFFFF); 
  vmcs_write32(GUEST_LDTR_LIMIT,0); 
  vmcs_write32(GUEST_SS_LIMIT,0xFFFFFFFF); 
  vmcs_write32(GUEST_CS_LIMIT,0xFFFFFFFF); 

  vmcs_write32(GUEST_ES_AR_BYTES, unusable_ar);
  vmcs_write32(GUEST_DS_AR_BYTES, unusable_ar);
  vmcs_write32(GUEST_FS_AR_BYTES, unusable_ar);
  vmcs_write32(GUEST_GS_AR_BYTES, unusable_ar);
  vmcs_write32(GUEST_LDTR_AR_BYTES, unusable_ar);

  asm ("movw %%cs, %%ax\n" : "=a"(sel_value));
  asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
  usable_ar = usable_ar>>8;
  usable_ar &= 0xf0ff; //clear bits 11:8 
  vmcs_write32(GUEST_CS_AR_BYTES, usable_ar);

  asm ("movw %%ss, %%ax\n" : "=a"(sel_value));
  asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
  usable_ar = usable_ar>>8;
  usable_ar &= 0xf0ff; //clear bits 11:8 
  vmcs_write32(GUEST_SS_AR_BYTES, usable_ar);

  asm ("movw %%cs, %%ax\n" : "=a"(selector));
  vmcs_write16(GUEST_CS_SELECTOR, selector);
  vmcs_write16(GUEST_SS_SELECTOR, get_ss());
  vmcs_write16(GUEST_DS_SELECTOR, get_ds());
  vmcs_write16(GUEST_ES_SELECTOR, get_es());
  vmcs_write16(GUEST_FS_SELECTOR, get_fs());
  vmcs_write16(GUEST_GS_SELECTOR, get_gs());
  vmcs_write16(GUEST_TR_SELECTOR, get_tr()); 

  asm("mov $0x40, %rax\n");
  asm("lsl %%eax, %%eax\n" :"=a"(value));
  vmcs_write32(GUEST_TR_LIMIT,value); 

  asm("str %%ax\n" : "=a"(sel_value));
  asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
  usable_ar = usable_ar>>8;
  vmcs_write32(GUEST_TR_AR_BYTES, usable_ar);

  vmcs_writel(GUEST_FS_BASE, rdmsr64(MSR_IA32_FS_BASE)); 
  vmcs_writel(GUEST_GS_BASE, rdmsr64(MSR_IA32_GS_BASE));  // KERNEL_GS_BASE or GS_BASE?

  // HOST_TR_BASE?
  //printf("get_tr: %X %llx\n", get_tr(), segment_base(get_tr()));
  vmcs_writel(GUEST_TR_BASE, segment_base(get_tr()));

  asm("sgdt %0\n" : :"m"(gdtb));
  vmcs_writel(GUEST_GDTR_BASE, gdtb.base);
  vmcs_writel(GUEST_GDTR_LIMIT, gdtb.limit);

  asm("sidt %0\n" : :"m"(idtb));
  vmcs_writel(GUEST_IDTR_BASE, gdtb.base);
  vmcs_writel(GUEST_IDTR_LIMIT, gdtb.limit);

  vmcs_writel(GUEST_SYSENTER_CS, rdmsr64(MSR_IA32_SYSENTER_CS));
  vmcs_writel(GUEST_SYSENTER_ESP, rdmsr64(MSR_IA32_SYSENTER_ESP));
  vmcs_writel(GUEST_SYSENTER_EIP, rdmsr64(MSR_IA32_SYSENTER_EIP));

  // PERF_GLOBAL_CTRL, PAT, and EFER are all disabled

  vmcs_writel(GUEST_RIP, (unsigned long)&guest_entry_point);
  vmcs_writel(GUEST_RSP, 0);
}

void initialize_naturalwidth_control(void){
  vmcs_write64(CR0_GUEST_HOST_MASK, 0);
  vmcs_write64(CR4_GUEST_HOST_MASK, 0);

  vmcs_write64(CR0_READ_SHADOW, 0);
  vmcs_write64(CR4_READ_SHADOW, 0);

  vmcs_write64(CR3_TARGET_VALUE0, 0);
  vmcs_write64(CR3_TARGET_VALUE1, 0);
  vmcs_write64(CR3_TARGET_VALUE2, 0);
  vmcs_write64(CR3_TARGET_VALUE3, 0);
}
  

// copies all host selectors, 0xc00 - 0xc0c
static void initialize_16bit_host_guest_state(void) {
  u16 	    value;
  asm ("movw %%es, %%ax\n" :"=a"(value));
  vmcs_write16(HOST_ES_SELECTOR,value); 
  vmcs_write16(GUEST_ES_SELECTOR,value); 

  asm ("movw %%cs, %%ax\n" : "=a"(value));
  vmcs_write16(HOST_CS_SELECTOR,value); 
  vmcs_write16(GUEST_CS_SELECTOR,value); 

  asm ("movw %%ss, %%ax\n" : "=a"(value));
  vmcs_write16(HOST_SS_SELECTOR,value); 
  vmcs_write16(GUEST_SS_SELECTOR,value); 

  asm ("movw %%ds, %%ax\n" : "=a"(value));
  vmcs_write16(HOST_DS_SELECTOR,value); 
  vmcs_write16(GUEST_DS_SELECTOR,value); 

  asm ("movw %%fs, %%ax\n" : "=a"(value));
  vmcs_write16(HOST_FS_SELECTOR,value); 
  vmcs_write16(GUEST_FS_SELECTOR,value); 

  asm ("movw %%gs, %%ax\n" : "=a"(value));
  vmcs_write16(HOST_GS_SELECTOR,value); 
  vmcs_write16(GUEST_GS_SELECTOR,value); 

  asm("str %%ax\n" : "=a"(value));
  vmcs_write16(HOST_TR_SELECTOR,value); 
  vmcs_write16(GUEST_TR_SELECTOR,value); 

  asm("sldt %%ax\n" : "=a"(value));
  vmcs_write16(GUEST_LDTR_SELECTOR,value); 
}

// host gdtr, idtr, tr, sysenter_cs
static void initialize_32bit_host_guest_state(void) {
   unsigned long field;
   u32 	    value;
   u64      gdtb = 0;
   u64      idtb = 0;
   u64      trbase;
   u64      trbase_lo;
   u64      trbase_hi;
   u64 	    realtrbase;
   u32      unusable_ar = 0x10000;
   u32      usable_ar; 
   u16      sel_value; 

   vmcs_write32(GUEST_ES_LIMIT,0xFFFFFFFF); 
   vmcs_write32(GUEST_DS_LIMIT,0xFFFFFFFF); 
   vmcs_write32(GUEST_FS_LIMIT,0xFFFFFFFF); 
   vmcs_write32(GUEST_GS_LIMIT,0xFFFFFFFF); 
   vmcs_write32(GUEST_LDTR_LIMIT,0); 
   vmcs_write32(GUEST_SS_LIMIT,0xFFFFFFFF); 
   vmcs_write32(GUEST_CS_LIMIT,0xFFFFFFFF); 

   vmcs_write32(GUEST_ES_AR_BYTES, unusable_ar);
   vmcs_write32(GUEST_DS_AR_BYTES, unusable_ar);
   vmcs_write32(GUEST_FS_AR_BYTES, unusable_ar);
   vmcs_write32(GUEST_GS_AR_BYTES, unusable_ar);
   vmcs_write32(GUEST_LDTR_AR_BYTES, unusable_ar);

   asm ("movw %%cs, %%ax\n" : "=a"(sel_value));
   asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
   usable_ar = usable_ar>>8;
   usable_ar &= 0xf0ff; //clear bits 11:8 
   vmcs_write32(GUEST_CS_AR_BYTES, usable_ar);
   
   asm ("movw %%ss, %%ax\n" : "=a"(sel_value));
   asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
   usable_ar = usable_ar>>8;
   usable_ar &= 0xf0ff; //clear bits 11:8 
   vmcs_write32(GUEST_SS_AR_BYTES, usable_ar);

  // other tr things
   asm("mov $0x40, %rax\n");
   asm("lsl %%eax, %%eax\n" :"=a"(value));
   vmcs_write32(GUEST_TR_LIMIT,value); 

   asm("str %%ax\n" : "=a"(sel_value));
   asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
   usable_ar = usable_ar>>8;
   vmcs_write32(GUEST_TR_AR_BYTES, usable_ar);

  // gdt things
   asm("sgdt %0\n" : :"m"(gdtb));
   value = gdtb&0x0ffff;
   gdtb = gdtb>>16; //base

   if(((gdtb>>47)&0x1)){ gdtb |= 0xffff000000000000ull; }
   vmcs_write32(GUEST_GDTR_LIMIT,value); 
   vmcs_writel(GUEST_GDTR_BASE, gdtb);
   vmcs_writel(HOST_GDTR_BASE, gdtb);

  // tr things
   trbase = gdtb + 0x40;
   if(((trbase>>47)&0x1)){ trbase |= 0xffff000000000000ull; }

   // SS segment override
   asm("mov %0,%%rax\n" 
       ".byte 0x36\n"
       "movq (%%rax),%%rax\n"
        :"=a"(trbase_lo) :"0"(trbase) 
       );

   realtrbase = ((trbase_lo>>16) & (0x0ffff)) | (((trbase_lo>>32)&0x000000ff) << 16) | (((trbase_lo>>56)&0xff) << 24);

   // SS segment override for upper32 bits of base in ia32e mode
   asm("mov %0,%%rax\n" 
       ".byte 0x36\n"
       "movq 8(%%rax),%%rax\n"
        :"=a"(trbase_hi) :"0"(trbase) 
       );

   realtrbase = realtrbase | (trbase_hi<<32) ;
   printf("realtrbase: %lx\n", realtrbase);
   vmcs_writel(GUEST_TR_BASE, realtrbase);
   vmcs_writel(HOST_TR_BASE, realtrbase);

   asm("sidt %0\n" : :"m"(idtb));
   value = idtb&0x0ffff;
   idtb = idtb>>16; //base

   if(((idtb>>47)&0x1)){ idtb |= 0xffff000000000000ull; }
   vmcs_write32(GUEST_IDTR_LIMIT, value); 
   vmcs_writel(GUEST_IDTR_BASE, idtb);
   vmcs_writel(HOST_IDTR_BASE, idtb);

   vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0); 
   vmcs_write32(GUEST_ACTIVITY_STATE, 0); 
}


// host cr0, cr3, cr4, fs_base, gs_base, sysenter esp, eip, cs
static void initialize_naturalwidth_host_guest_state(void) {
  unsigned long field,field1;
  u64 	    value;
  int      fs_low;
  int      gs_low;

  vmcs_writel(GUEST_CR4,value); 

  value = rdmsr64(0xc0000100);
  printf("fs_base %lx\n", value);
  vmcs_writel(HOST_FS_BASE,value); 
  vmcs_writel(GUEST_FS_BASE,value); 

  value = rdmsr64(0xc0000101);
  printf("gs_base %lx\n", value);
  vmcs_writel(HOST_GS_BASE,value); 
  vmcs_writel(GUEST_GS_BASE,value);

  value = rdmsr64(0x176);
  printf("sysenter_esp %lx\n", value);
  vmcs_writel(GUEST_SYSENTER_ESP, value);
  vmcs_writel(HOST_IA32_SYSENTER_ESP, value);

  value = rdmsr64(0x175);
  printf("sysenter_eip %lx\n", value);
  vmcs_writel(GUEST_SYSENTER_EIP, value);
  vmcs_writel(HOST_IA32_SYSENTER_EIP, value);

  value = rdmsr64(0x174);
  printf("sysenter_cs %lx\n", value);
  vmcs_write32(GUEST_SYSENTER_CS, value);
  vmcs_write32(HOST_IA32_SYSENTER_CS, value);
}

void *io_bitmap_a_region, *io_bitmap_b_region, *msr_bitmap_phy_region, *virtual_apic_page;

static void initialize_64bit_control(void) {
  io_bitmap_a_region = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
  io_bitmap_b_region = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
  msr_bitmap_phy_region = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
  virtual_apic_page = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);

	bzero(io_bitmap_a_region, PAGE_SIZE);
	bzero(io_bitmap_b_region, PAGE_SIZE);
	bzero(msr_bitmap_phy_region, PAGE_SIZE);
	bzero(virtual_apic_page, PAGE_SIZE);

  vmcs_writel(IO_BITMAP_A, __pa(io_bitmap_a_region));
  vmcs_writel(IO_BITMAP_B, __pa(io_bitmap_b_region));
  vmcs_writel(MSR_BITMAP, __pa(msr_bitmap_phy_region));
  vmcs_writel(VIRTUAL_APIC_PAGE_ADDR, __pa(virtual_apic_page));
  vmcs_writel(0x200C, 0);
  vmcs_writel(TSC_OFFSET, 0);
}

