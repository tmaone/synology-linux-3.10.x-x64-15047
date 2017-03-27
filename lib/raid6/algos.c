#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/raid/pq.h>
#ifndef __KERNEL__
#include <sys/mman.h>
#include <stdio.h>
#else
#include <linux/module.h>
#include <linux/gfp.h>
#if !RAID6_USE_EMPTY_ZERO_PAGE
 
const char raid6_empty_zero_page[PAGE_SIZE] __attribute__((aligned(256)));
EXPORT_SYMBOL(raid6_empty_zero_page);
#endif
#endif

struct raid6_calls raid6_call;
EXPORT_SYMBOL_GPL(raid6_call);

const struct raid6_calls * const raid6_algos[] = {
#if defined(__ia64__)
	&raid6_intx16,
	&raid6_intx32,
#endif
#if defined(__i386__) && !defined(__arch_um__)
	&raid6_mmxx1,
	&raid6_mmxx2,
	&raid6_sse1x1,
	&raid6_sse1x2,
	&raid6_sse2x1,
	&raid6_sse2x2,
#ifdef CONFIG_AS_AVX2
	&raid6_avx2x1,
	&raid6_avx2x2,
#endif
#endif
#if defined(__x86_64__) && !defined(__arch_um__)
	&raid6_sse2x1,
	&raid6_sse2x2,
	&raid6_sse2x4,
#ifdef CONFIG_AS_AVX2
	&raid6_avx2x1,
	&raid6_avx2x2,
	&raid6_avx2x4,
#endif
#endif
#ifdef CONFIG_ALTIVEC
	&raid6_altivec1,
	&raid6_altivec2,
	&raid6_altivec4,
	&raid6_altivec8,
#endif
	&raid6_intx1,
	&raid6_intx2,
	&raid6_intx4,
	&raid6_intx8,
	NULL
};

void (*raid6_2data_recov)(int, size_t, int, int, void **);
EXPORT_SYMBOL_GPL(raid6_2data_recov);

void (*raid6_datap_recov)(int, size_t, int, void **);
EXPORT_SYMBOL_GPL(raid6_datap_recov);

const struct raid6_recov_calls *const raid6_recov_algos[] = {
#if (defined(__i386__) || defined(__x86_64__)) && !defined(__arch_um__)
#ifdef CONFIG_AS_AVX2
	&raid6_recov_avx2,
#endif
	&raid6_recov_ssse3,
#endif
	&raid6_recov_intx1,
	NULL
};

#ifdef __KERNEL__
#define RAID6_TIME_JIFFIES_LG2	4
#else
 
#define RAID6_TIME_JIFFIES_LG2	9
#define time_before(x, y) ((x) < (y))
#endif

static inline const struct raid6_recov_calls *raid6_choose_recov(void)
{
	const struct raid6_recov_calls *const *algo;
	const struct raid6_recov_calls *best;

	for (best = NULL, algo = raid6_recov_algos; *algo; algo++)
		if (!best || (*algo)->priority > best->priority)
			if (!(*algo)->valid || (*algo)->valid())
				best = *algo;

	if (best) {
		raid6_2data_recov = best->data2;
		raid6_datap_recov = best->datap;

		printk("raid6: using %s recovery algorithm\n", best->name);
	} else
		printk("raid6: Yikes! No recovery algorithm found!\n");

	return best;
}

static inline const struct raid6_calls *raid6_choose_gen(
	void *(*const dptrs)[(65536/PAGE_SIZE)+2], const int disks)
{
#ifdef MY_ABC_HERE
	unsigned long perf, bestgenperf, bestxorperf, j0, j1;
	int start = (disks>>1)-1, stop = disks-3;	 
#else  
	unsigned long perf, bestperf, j0, j1;
#endif  
	const struct raid6_calls *const *algo;
	const struct raid6_calls *best;

#ifdef MY_ABC_HERE
	for (bestgenperf = 0, bestxorperf = 0, best = NULL, algo = raid6_algos; *algo; algo++) {
#else  
	for (bestperf = 0, best = NULL, algo = raid6_algos; *algo; algo++) {
#endif  
		if (!best || (*algo)->prefer >= best->prefer) {
			if ((*algo)->valid && !(*algo)->valid())
				continue;

			perf = 0;

			preempt_disable();
			j0 = jiffies;
			while ((j1 = jiffies) == j0)
				cpu_relax();
			while (time_before(jiffies,
					    j1 + (1<<RAID6_TIME_JIFFIES_LG2))) {
				(*algo)->gen_syndrome(disks, PAGE_SIZE, *dptrs);
				perf++;
			}
			preempt_enable();

#ifdef MY_ABC_HERE
			if (perf > bestgenperf) {
				bestgenperf = perf;
#else  
			if (perf > bestperf) {
				bestperf = perf;
#endif  
				best = *algo;
			}
#ifdef MY_ABC_HERE
			printk("raid6: %-8s gen() %5ld MB/s\n", (*algo)->name,
#else  
			printk("raid6: %-8s %5ld MB/s\n", (*algo)->name,
#endif  
			       (perf*HZ) >> (20-16+RAID6_TIME_JIFFIES_LG2));
#ifdef MY_ABC_HERE

			if (!(*algo)->xor_syndrome)
				continue;

			perf = 0;

			preempt_disable();
			j0 = jiffies;
			while ((j1 = jiffies) == j0)
				cpu_relax();
			while (time_before(jiffies,
					    j1 + (1<<RAID6_TIME_JIFFIES_LG2))) {
				(*algo)->xor_syndrome(disks, start, stop,
						      PAGE_SIZE, *dptrs);
				perf++;
			}
			preempt_enable();

			if (best == *algo)
				bestxorperf = perf;

			printk("raid6: %-8s xor() %5ld MB/s\n", (*algo)->name,
				(perf*HZ) >> (20-16+RAID6_TIME_JIFFIES_LG2+1));
#endif  
		}
	}

	if (best) {
#ifdef MY_ABC_HERE
		printk("raid6: using algorithm %s gen() (%ld MB/s)\n",
#else  
		printk("raid6: using algorithm %s (%ld MB/s)\n",
#endif  
		       best->name,
#ifdef MY_ABC_HERE
		       (bestgenperf*HZ) >> (20-16+RAID6_TIME_JIFFIES_LG2));
#else  
		       (bestperf*HZ) >> (20-16+RAID6_TIME_JIFFIES_LG2));
#endif  
#ifdef MY_ABC_HERE
		if (best->xor_syndrome)
			printk("raid6: .... xor() %ld MB/s, rmw enabled\n",
			       (bestxorperf*HZ) >> (20-16+RAID6_TIME_JIFFIES_LG2+1));
#endif  
		raid6_call = *best;
	} else
		printk("raid6: Yikes!  No algorithm found!\n");

	return best;
}

int __init raid6_select_algo(void)
{
	const int disks = (65536/PAGE_SIZE)+2;

	const struct raid6_calls *gen_best;
	const struct raid6_recov_calls *rec_best;
	char *syndromes;
	void *dptrs[(65536/PAGE_SIZE)+2];
	int i;

	for (i = 0; i < disks-2; i++)
		dptrs[i] = ((char *)raid6_gfmul) + PAGE_SIZE*i;

	syndromes = (void *) __get_free_pages(GFP_KERNEL, 1);

	if (!syndromes) {
		printk("raid6: Yikes!  No memory available.\n");
		return -ENOMEM;
	}

	dptrs[disks-2] = syndromes;
	dptrs[disks-1] = syndromes + PAGE_SIZE;

	gen_best = raid6_choose_gen(&dptrs, disks);

	rec_best = raid6_choose_recov();

	free_pages((unsigned long)syndromes, 1);

	return gen_best && rec_best ? 0 : -EINVAL;
}

static void raid6_exit(void)
{
	do { } while (0);
}

subsys_initcall(raid6_select_algo);
module_exit(raid6_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RAID6 Q-syndrome calculations");
