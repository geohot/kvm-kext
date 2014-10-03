#include <libkern/libkern.h>
#include <mach/mach_types.h>
 
kern_return_t MyKextStart(kmod_info_t * ki, void * d) {
  printf("MyKext has started.\n");
  return KERN_SUCCESS;
}
 
kern_return_t MyKextStop(kmod_info_t * ki, void * d) {
    printf("MyKext has stopped.\n");
    return KERN_SUCCESS;
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(com.geohot.virt.kvm, "1.0.0d1", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = MyKextStart;
__private_extern__ kmod_stop_func_t *_antimain = MyKextStop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;

