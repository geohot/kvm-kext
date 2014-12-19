
struct desc_struct {
        union {
                struct {
                        unsigned int a;
                        unsigned int b;
                };
                struct {
                        u16 limit0;
                        u16 base0;
                        unsigned base1: 8, type: 4, s: 1, dpl: 2, p: 1;
                        unsigned limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
                };
        };
} __attribute__((packed));

struct ldttss_desc64 {
  u16 limit0;
  u16 base0;
  unsigned base1 : 8, type : 5, dpl : 2, p : 1;
  unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
  u32 base3;
  u32 zero1;
} __attribute__((packed));
 

static inline unsigned long get_desc_base(const struct desc_struct *desc) {
  return (unsigned)(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static inline u16 kvm_read_ldt(void) {
  u16 ldt;
  asm("sldt %0" : "=g"(ldt));
  return ldt;
}

static unsigned long segment_base(u16 selector) {
  u64 gdtb = 0;
  asm("sgdt %0\n" : :"m"(gdtb));
  gdtb = gdtb>>16;
  if(((gdtb>>47)&0x1)){ gdtb |= 0xffff000000000000ull; }

	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (!(selector & ~3))
		return 0;

	table_base = gdtb;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector = kvm_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);
  if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
         v |= ((unsigned long)((struct ldttss_desc64 *)d)->base3) << 32;
  return v;
}

