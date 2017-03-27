#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifdef CONFIG_X86_32

#include <linux/raid/pq.h>
#include "x86.h"

const struct raid6_mmx_constants {
	u64 x1d;
} raid6_mmx_constants = {
	0x1d1d1d1d1d1d1d1dULL,
};

static int raid6_have_mmx(void)
{
	 
	return boot_cpu_has(X86_FEATURE_MMX);
}

static void raid6_mmx1_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;		 
	p = dptr[z0+1];		 
	q = dptr[z0+2];		 

	kernel_fpu_begin();

	asm volatile("movq %0,%%mm0" : : "m" (raid6_mmx_constants.x1d));
	asm volatile("pxor %mm5,%mm5");	 

	for ( d = 0 ; d < bytes ; d += 8 ) {
		asm volatile("movq %0,%%mm2" : : "m" (dptr[z0][d]));  
		asm volatile("movq %mm2,%mm4");	 
		for ( z = z0-1 ; z >= 0 ; z-- ) {
			asm volatile("movq %0,%%mm6" : : "m" (dptr[z][d]));
			asm volatile("pcmpgtb %mm4,%mm5");
			asm volatile("paddb %mm4,%mm4");
			asm volatile("pand %mm0,%mm5");
			asm volatile("pxor %mm5,%mm4");
			asm volatile("pxor %mm5,%mm5");
			asm volatile("pxor %mm6,%mm2");
			asm volatile("pxor %mm6,%mm4");
		}
		asm volatile("movq %%mm2,%0" : "=m" (p[d]));
		asm volatile("pxor %mm2,%mm2");
		asm volatile("movq %%mm4,%0" : "=m" (q[d]));
		asm volatile("pxor %mm4,%mm4");
	}

	kernel_fpu_end();
}

const struct raid6_calls raid6_mmxx1 = {
	raid6_mmx1_gen_syndrome,
#ifdef MY_ABC_HERE
	NULL,			 
#endif  
	raid6_have_mmx,
	"mmxx1",
	0
};

static void raid6_mmx2_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;		 
	p = dptr[z0+1];		 
	q = dptr[z0+2];		 

	kernel_fpu_begin();

	asm volatile("movq %0,%%mm0" : : "m" (raid6_mmx_constants.x1d));
	asm volatile("pxor %mm5,%mm5");	 
	asm volatile("pxor %mm7,%mm7");  

	for ( d = 0 ; d < bytes ; d += 16 ) {
		asm volatile("movq %0,%%mm2" : : "m" (dptr[z0][d]));  
		asm volatile("movq %0,%%mm3" : : "m" (dptr[z0][d+8]));
		asm volatile("movq %mm2,%mm4");  
		asm volatile("movq %mm3,%mm6");  
		for ( z = z0-1 ; z >= 0 ; z-- ) {
			asm volatile("pcmpgtb %mm4,%mm5");
			asm volatile("pcmpgtb %mm6,%mm7");
			asm volatile("paddb %mm4,%mm4");
			asm volatile("paddb %mm6,%mm6");
			asm volatile("pand %mm0,%mm5");
			asm volatile("pand %mm0,%mm7");
			asm volatile("pxor %mm5,%mm4");
			asm volatile("pxor %mm7,%mm6");
			asm volatile("movq %0,%%mm5" : : "m" (dptr[z][d]));
			asm volatile("movq %0,%%mm7" : : "m" (dptr[z][d+8]));
			asm volatile("pxor %mm5,%mm2");
			asm volatile("pxor %mm7,%mm3");
			asm volatile("pxor %mm5,%mm4");
			asm volatile("pxor %mm7,%mm6");
			asm volatile("pxor %mm5,%mm5");
			asm volatile("pxor %mm7,%mm7");
		}
		asm volatile("movq %%mm2,%0" : "=m" (p[d]));
		asm volatile("movq %%mm3,%0" : "=m" (p[d+8]));
		asm volatile("movq %%mm4,%0" : "=m" (q[d]));
		asm volatile("movq %%mm6,%0" : "=m" (q[d+8]));
	}

	kernel_fpu_end();
}

const struct raid6_calls raid6_mmxx2 = {
	raid6_mmx2_gen_syndrome,
#ifdef MY_ABC_HERE
	NULL,			 
#endif  
	raid6_have_mmx,
	"mmxx2",
	0
};

#endif
