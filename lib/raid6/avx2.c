#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifdef CONFIG_AS_AVX2

#include <linux/raid/pq.h>
#include "x86.h"

static const struct raid6_avx2_constants {
	u64 x1d[4];
} raid6_avx2_constants __aligned(32) = {
	{ 0x1d1d1d1d1d1d1d1dULL, 0x1d1d1d1d1d1d1d1dULL,
	  0x1d1d1d1d1d1d1d1dULL, 0x1d1d1d1d1d1d1d1dULL,},
};

static int raid6_have_avx2(void)
{
	return boot_cpu_has(X86_FEATURE_AVX2) && boot_cpu_has(X86_FEATURE_AVX);
}

static void raid6_avx21_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;		 
	p = dptr[z0+1];		 
	q = dptr[z0+2];		 

	kernel_fpu_begin();

	asm volatile("vmovdqa %0,%%ymm0" : : "m" (raid6_avx2_constants.x1d[0]));
	asm volatile("vpxor %ymm3,%ymm3,%ymm3");	 

	for (d = 0; d < bytes; d += 32) {
		asm volatile("prefetchnta %0" : : "m" (dptr[z0][d]));
		asm volatile("vmovdqa %0,%%ymm2" : : "m" (dptr[z0][d])); 
		asm volatile("prefetchnta %0" : : "m" (dptr[z0-1][d]));
		asm volatile("vmovdqa %ymm2,%ymm4"); 
		asm volatile("vmovdqa %0,%%ymm6" : : "m" (dptr[z0-1][d]));
		for (z = z0-2; z >= 0; z--) {
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d]));
			asm volatile("vpcmpgtb %ymm4,%ymm3,%ymm5");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm6,%ymm2,%ymm2");
			asm volatile("vpxor %ymm6,%ymm4,%ymm4");
			asm volatile("vmovdqa %0,%%ymm6" : : "m" (dptr[z][d]));
		}
		asm volatile("vpcmpgtb %ymm4,%ymm3,%ymm5");
		asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
		asm volatile("vpand %ymm0,%ymm5,%ymm5");
		asm volatile("vpxor %ymm5,%ymm4,%ymm4");
		asm volatile("vpxor %ymm6,%ymm2,%ymm2");
		asm volatile("vpxor %ymm6,%ymm4,%ymm4");

		asm volatile("vmovntdq %%ymm2,%0" : "=m" (p[d]));
		asm volatile("vpxor %ymm2,%ymm2,%ymm2");
		asm volatile("vmovntdq %%ymm4,%0" : "=m" (q[d]));
		asm volatile("vpxor %ymm4,%ymm4,%ymm4");
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

const struct raid6_calls raid6_avx2x1 = {
	raid6_avx21_gen_syndrome,
#ifdef MY_ABC_HERE
	NULL,			 
#endif  
	raid6_have_avx2,
	"avx2x1",
	1			 
};

static void raid6_avx22_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;		 
	p = dptr[z0+1];		 
	q = dptr[z0+2];		 

	kernel_fpu_begin();

	asm volatile("vmovdqa %0,%%ymm0" : : "m" (raid6_avx2_constants.x1d[0]));
	asm volatile("vpxor %ymm1,%ymm1,%ymm1");  

	for (d = 0; d < bytes; d += 64) {
		asm volatile("prefetchnta %0" : : "m" (dptr[z0][d]));
		asm volatile("prefetchnta %0" : : "m" (dptr[z0][d+32]));
		asm volatile("vmovdqa %0,%%ymm2" : : "m" (dptr[z0][d])); 
		asm volatile("vmovdqa %0,%%ymm3" : : "m" (dptr[z0][d+32])); 
		asm volatile("vmovdqa %ymm2,%ymm4");  
		asm volatile("vmovdqa %ymm3,%ymm6");  
		for (z = z0-1; z >= 0; z--) {
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+32]));
			asm volatile("vpcmpgtb %ymm4,%ymm1,%ymm5");
			asm volatile("vpcmpgtb %ymm6,%ymm1,%ymm7");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpaddb %ymm6,%ymm6,%ymm6");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpand %ymm0,%ymm7,%ymm7");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
			asm volatile("vmovdqa %0,%%ymm5" : : "m" (dptr[z][d]));
			asm volatile("vmovdqa %0,%%ymm7" : : "m" (dptr[z][d+32]));
			asm volatile("vpxor %ymm5,%ymm2,%ymm2");
			asm volatile("vpxor %ymm7,%ymm3,%ymm3");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
		}
		asm volatile("vmovntdq %%ymm2,%0" : "=m" (p[d]));
		asm volatile("vmovntdq %%ymm3,%0" : "=m" (p[d+32]));
		asm volatile("vmovntdq %%ymm4,%0" : "=m" (q[d]));
		asm volatile("vmovntdq %%ymm6,%0" : "=m" (q[d+32]));
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

const struct raid6_calls raid6_avx2x2 = {
	raid6_avx22_gen_syndrome,
#ifdef MY_ABC_HERE
	NULL,			 
#endif  
	raid6_have_avx2,
	"avx2x2",
	1			 
};

#ifdef CONFIG_X86_64

static void raid6_avx24_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;		 
	p = dptr[z0+1];		 
	q = dptr[z0+2];		 

	kernel_fpu_begin();

	asm volatile("vmovdqa %0,%%ymm0" : : "m" (raid6_avx2_constants.x1d[0]));
	asm volatile("vpxor %ymm1,%ymm1,%ymm1");	 
	asm volatile("vpxor %ymm2,%ymm2,%ymm2");	 
	asm volatile("vpxor %ymm3,%ymm3,%ymm3");	 
	asm volatile("vpxor %ymm4,%ymm4,%ymm4");	 
	asm volatile("vpxor %ymm6,%ymm6,%ymm6");	 
	asm volatile("vpxor %ymm10,%ymm10,%ymm10");	 
	asm volatile("vpxor %ymm11,%ymm11,%ymm11");	 
	asm volatile("vpxor %ymm12,%ymm12,%ymm12");	 
	asm volatile("vpxor %ymm14,%ymm14,%ymm14");	 

	for (d = 0; d < bytes; d += 128) {
		for (z = z0; z >= 0; z--) {
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+32]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+64]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+96]));
			asm volatile("vpcmpgtb %ymm4,%ymm1,%ymm5");
			asm volatile("vpcmpgtb %ymm6,%ymm1,%ymm7");
			asm volatile("vpcmpgtb %ymm12,%ymm1,%ymm13");
			asm volatile("vpcmpgtb %ymm14,%ymm1,%ymm15");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpaddb %ymm6,%ymm6,%ymm6");
			asm volatile("vpaddb %ymm12,%ymm12,%ymm12");
			asm volatile("vpaddb %ymm14,%ymm14,%ymm14");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpand %ymm0,%ymm7,%ymm7");
			asm volatile("vpand %ymm0,%ymm13,%ymm13");
			asm volatile("vpand %ymm0,%ymm15,%ymm15");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
			asm volatile("vpxor %ymm13,%ymm12,%ymm12");
			asm volatile("vpxor %ymm15,%ymm14,%ymm14");
			asm volatile("vmovdqa %0,%%ymm5" : : "m" (dptr[z][d]));
			asm volatile("vmovdqa %0,%%ymm7" : : "m" (dptr[z][d+32]));
			asm volatile("vmovdqa %0,%%ymm13" : : "m" (dptr[z][d+64]));
			asm volatile("vmovdqa %0,%%ymm15" : : "m" (dptr[z][d+96]));
			asm volatile("vpxor %ymm5,%ymm2,%ymm2");
			asm volatile("vpxor %ymm7,%ymm3,%ymm3");
			asm volatile("vpxor %ymm13,%ymm10,%ymm10");
			asm volatile("vpxor %ymm15,%ymm11,%ymm11");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
			asm volatile("vpxor %ymm13,%ymm12,%ymm12");
			asm volatile("vpxor %ymm15,%ymm14,%ymm14");
		}
		asm volatile("vmovntdq %%ymm2,%0" : "=m" (p[d]));
		asm volatile("vpxor %ymm2,%ymm2,%ymm2");
		asm volatile("vmovntdq %%ymm3,%0" : "=m" (p[d+32]));
		asm volatile("vpxor %ymm3,%ymm3,%ymm3");
		asm volatile("vmovntdq %%ymm10,%0" : "=m" (p[d+64]));
		asm volatile("vpxor %ymm10,%ymm10,%ymm10");
		asm volatile("vmovntdq %%ymm11,%0" : "=m" (p[d+96]));
		asm volatile("vpxor %ymm11,%ymm11,%ymm11");
		asm volatile("vmovntdq %%ymm4,%0" : "=m" (q[d]));
		asm volatile("vpxor %ymm4,%ymm4,%ymm4");
		asm volatile("vmovntdq %%ymm6,%0" : "=m" (q[d+32]));
		asm volatile("vpxor %ymm6,%ymm6,%ymm6");
		asm volatile("vmovntdq %%ymm12,%0" : "=m" (q[d+64]));
		asm volatile("vpxor %ymm12,%ymm12,%ymm12");
		asm volatile("vmovntdq %%ymm14,%0" : "=m" (q[d+96]));
		asm volatile("vpxor %ymm14,%ymm14,%ymm14");
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

const struct raid6_calls raid6_avx2x4 = {
	raid6_avx24_gen_syndrome,
#ifdef MY_ABC_HERE
	NULL,			 
#endif  
	raid6_have_avx2,
	"avx2x4",
	1			 
};
#endif

#endif  
