
struct kvm_run_abi10 {
	/* in */
	__u32 io_completed; /* mmio/pio request completed */
	__u8 request_interrupt_window;
	__u8 padding1[3];

	/* out */
	__u32 exit_reason;
	__u32 instruction_length;
	__u8 ready_for_interrupt_injection;
	__u8 if_flag;
	__u8 padding2[6];

	/* in (pre_kvm_run), out (post_kvm_run) */
	__u64 cr8;
	__u64 apic_base;

	union {
		/* KVM_EXIT_UNKNOWN */
		struct {
			__u64 hardware_exit_reason;
		} hw;
		/* KVM_EXIT_FAIL_ENTRY */
		struct {
			__u64 hardware_entry_failure_reason;
		} fail_entry;
		/* KVM_EXIT_EXCEPTION */
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;
		/* KVM_EXIT_IO */
		struct kvm_io_abi10 {
			__u8 direction;
			__u8 size; /* bytes */
			__u16 port;
			__u32 count;
			__u64 data_offset; /* relative to kvm_run start */
		} io;
		struct {
		} debug;
		/* KVM_EXIT_MMIO */
		struct {
			__u64 phys_addr;
			__u8  data[8];
			__u32 len;
			__u8  is_write;
		} mmio;
		/* KVM_EXIT_HYPERCALL */
		struct {
			__u64 args[6];
			__u64 ret;
			__u32 longmode;
			__u32 pad;
		} hypercall;
	};
};

