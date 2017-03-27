#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _ELPUTILS_H_
#define _ELPUTILS_H_
#include "m86xxx_types.h"
#define BIGENDIAN       1
#define LITTLEENDIAN    0

#ifndef htons
#define htons(x) \
({ \
   U16 __x = (x); \
   ((U16)( \
      (((U16)(__x) & (U16)0x00ffU) << 8) | \
      (((U16)(__x) & (U16)0xff00U) >> 8) )); \
})

#define ntohs(x) htons(x)
#endif
#ifndef htonl

#define htonl(x) \
({ \
   U32 __x = (x); \
   ((U32)( \
      (((U32)(__x) & (U32)0x000000ffUL) << 24) | \
      (((U32)(__x) & (U32)0x0000ff00UL) <<  8) | \
      (((U32)(__x) & (U32)0x00ff0000UL) >>  8) | \
      (((U32)(__x) & (U32)0xff000000UL) >> 24) )); \
})
#define ntohl(x) htonl(x)
#endif
#define htonl_e(x) \
({ \
   U32 __x = (x); \
   ((U32)( \
      (((U32)(__x) & (U32)0x0000ffffUL) << 16) | \
      (((U32)(__x) & (U32)0xffff0000UL) >> 16) )); \
})

void   dumpword_ex(U32 *mem, int size, char *msg,int col,int bige);
void    dumpword(U32 *from, int size, char *msg);
void    dumpmem(char *mem, int size, char *msg,U32 bige);
void    memcpy32htonl(U32 *dst, U32 *src, int len);
void memcpy32skipdst(U32 *dst, U32 *src, int len);
void memcpy32skipsrc(U32 *dst, U32 *src, int len);
void    memcpy32(volatile U32 *dst, volatile U32 *src, int len);
void    memcpy32htonl_r(U32 *dst, U32 *src, int len);
void    memcpy32_e(U32 *dst, U32 *src, int len);
void    memcpy32_re(U32 *dst, U32 *src, int len);
void    memcpy32_r(U32 *dst, U32 *src, int len);
void    memset32(U32 *dst, U32 val, int len);
void    memset8(U8 *dst, U8 val, int len);
int    wcopy(U32 *src, U32 *dst, U32 size);
int    wcopyton(U32 *src, U32 *dst, U32 size);
int    wcmp(U32 *src, U32 *dst, U32 size);
int    bytecmp(U8 *src, U8 *dst, U32 size);
 
int elp_processor_endian(void);

#if defined (ELPSEC_LINUX)
void dumpstruct(FILE *out, char *mem, int size, char *sname,char *msg);
#endif

#define DUMPWORD_(m,t,z,f)      
#define MEMCPY(d,s,z)		memcpy((d),(s),(z))
#define MEMSET32(d,v,z)		memset32((U32 *)(d),(v),(z))
#define MEMSET(d,v,z)		memset8((U8 *)(d),(v),(z))
#define BTOW(i)			((((i)?(i):-3)-1)/4+1)

#include <linux/kernel.h>        
#include <linux/wait.h>           
            
#define MEMCPY32W(d,s,z)                 do { memcpy_toio((void *)(d),(void *)(s),(int)(z<<2)); wmb(); } while(0)
#define MEMCPY32R(d,s,z)                 do { memcpy_fromio((void *)(d),(void *)(s),(int)(z<<2)); rmb(); } while(0)

#define MEMCPY32_RW(buf,d,s,z)           do { memcpy32_r((U32 *)(buf),(U32 *)(s),(S16)(z)); memcpy_toio((void *)(d),(void *)(buf),((int)(z)<<2)); wmb(); } while(0)
#define MEMCPY32_RR(buf,d,s,z)           do { memcpy32_r((U32 *)(buf),(U32 *)(s),(S16)(z)); memcpy_fromio((void *)(d),(void *)(buf),((int)(z)<<2)); rmb(); } while(0)

#define MEMCPY32HTONLW(buf,d,s,z)        do { memcpy32htonl((U32 *)(buf),(U32 *)(s),(S16)(z)); memcpy_toio((void *)(d),(void *)(buf),((int)(z)<<2)); wmb(); } while(0)
#define MEMCPY32HTONLR(buf,d,s,z)        do { memcpy32htonl((U32 *)(buf),(U32 *)(s),(S16)(z)); memcpy_fromio((void *)(d),(void *)(buf),((int)(z)<<2)); rmb(); } while(0)

#define MEMCPY32HTONL_RW(buf,d,s,z)      do { memcpy32htonl_r((U32 *)(buf),(U32 *)(s),(S16)(z)); memcpy_toio((void *)(d),(void *)(buf),((int)(z)<<2)); wmb(); } while(0)
#define MEMCPY32HTONL_RR(buf,d,s,z)      do { memcpy32htonl_r((U32 *)(buf),(U32 *)(s),(S16)(z)); memcpy_fromio((void *)(d),(void *)(buf),((int)(z)<<2)); rmb(); } while(0)

#define ELPSEC_WRITE_UINT(val,addr)    do { iowrite32((u32)(val),(void *)(addr)); wmb(); } while(0)
#define ELPSEC_READ_UINT(addr)       ioread32((void *)(addr))

#define SIZE_QUANT   64
void   minit(void *buffer, long len);
void  *mget(long size);
void   mfree(void *buf);

#define ELP_ERR		(1 << 0)
#define ELP_WRN		(1 << 1)
#define ELP_DBG		(1 << 2)
#define ELP_DUMP	(1 << 3)
#define EDDUMP      	0

#define PDUMPWORD(t,b,s,m,e)     do {if(1){ dumpword(b,s,m);}}  while(0)

#if defined(MY_DEF_HERE)

extern int elp_debug;
#define	DPRINTF(flags, a...)	if (flags&ELP_ERR) {\
					printk("%s: ", __func__); \
					printk(a);\
				}
#else
#if 1
extern int elp_debug;
#define	DPRINTF(flags, a...)	if (elp_debug&flags) {\
					printk("%s: ", __func__); \
					printk(a);\
				}
#else
#define	DPRINTF(a...)
#endif
#endif

#endif
