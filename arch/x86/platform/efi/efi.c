#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/efi.h>
#include <linux/efi-bgrt.h>
#include <linux/export.h>
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/io.h>
#include <linux/reboot.h>
#include <linux/bcd.h>

#include <asm/setup.h>
#include <asm/efi.h>
#include <asm/time.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/x86_init.h>
#include <asm/rtc.h>

#define EFI_DEBUG	1

#define EFI_MIN_RESERVE 5120

#define EFI_DUMMY_GUID \
	EFI_GUID(0x4424ac57, 0xbe4b, 0x47dd, 0x9e, 0x97, 0xed, 0x50, 0xf0, 0x9f, 0x92, 0xa9)

static efi_char16_t efi_dummy_name[6] = { 'D', 'U', 'M', 'M', 'Y', 0 };

struct efi __read_mostly efi = {
	.mps        = EFI_INVALID_TABLE_ADDR,
	.acpi       = EFI_INVALID_TABLE_ADDR,
	.acpi20     = EFI_INVALID_TABLE_ADDR,
	.smbios     = EFI_INVALID_TABLE_ADDR,
	.sal_systab = EFI_INVALID_TABLE_ADDR,
	.boot_info  = EFI_INVALID_TABLE_ADDR,
	.hcdp       = EFI_INVALID_TABLE_ADDR,
	.uga        = EFI_INVALID_TABLE_ADDR,
	.uv_systab  = EFI_INVALID_TABLE_ADDR,
};
EXPORT_SYMBOL(efi);

struct efi_memory_map memmap;

static struct efi efi_phys __initdata;
static efi_system_table_t efi_systab __initdata;

unsigned long x86_efi_facility;

int efi_enabled(int facility)
{
	return test_bit(facility, &x86_efi_facility) != 0;
}
EXPORT_SYMBOL(efi_enabled);

#ifdef MY_DEF_HERE
static bool __initdata disable_runtime = true;
static int __init setup_withefi(char *arg)
{
	disable_runtime = false;
	return 0;
}
early_param("withefi", setup_withefi);
#else  
static bool __initdata disable_runtime = false;
static int __init setup_noefi(char *arg)
{
	disable_runtime = true;
	return 0;
}
early_param("noefi", setup_noefi);
#endif  

int add_efi_memmap;
EXPORT_SYMBOL(add_efi_memmap);

static int __init setup_add_efi_memmap(char *arg)
{
	add_efi_memmap = 1;
	return 0;
}
early_param("add_efi_memmap", setup_add_efi_memmap);

static bool efi_no_storage_paranoia;

static int __init setup_storage_paranoia(char *arg)
{
	efi_no_storage_paranoia = true;
	return 0;
}
early_param("efi_no_storage_paranoia", setup_storage_paranoia);

static efi_status_t virt_efi_get_time(efi_time_t *tm, efi_time_cap_t *tc)
{
	unsigned long flags;
	efi_status_t status;

	spin_lock_irqsave(&rtc_lock, flags);
	status = efi_call_virt2(get_time, tm, tc);
	spin_unlock_irqrestore(&rtc_lock, flags);
	return status;
}

static efi_status_t virt_efi_set_time(efi_time_t *tm)
{
	unsigned long flags;
	efi_status_t status;

	spin_lock_irqsave(&rtc_lock, flags);
	status = efi_call_virt1(set_time, tm);
	spin_unlock_irqrestore(&rtc_lock, flags);
	return status;
}

static efi_status_t virt_efi_get_wakeup_time(efi_bool_t *enabled,
					     efi_bool_t *pending,
					     efi_time_t *tm)
{
	unsigned long flags;
	efi_status_t status;

	spin_lock_irqsave(&rtc_lock, flags);
	status = efi_call_virt3(get_wakeup_time,
				enabled, pending, tm);
	spin_unlock_irqrestore(&rtc_lock, flags);
	return status;
}

static efi_status_t virt_efi_set_wakeup_time(efi_bool_t enabled, efi_time_t *tm)
{
	unsigned long flags;
	efi_status_t status;

	spin_lock_irqsave(&rtc_lock, flags);
	status = efi_call_virt2(set_wakeup_time,
				enabled, tm);
	spin_unlock_irqrestore(&rtc_lock, flags);
	return status;
}

static efi_status_t virt_efi_get_variable(efi_char16_t *name,
					  efi_guid_t *vendor,
					  u32 *attr,
					  unsigned long *data_size,
					  void *data)
{
	return efi_call_virt5(get_variable,
			      name, vendor, attr,
			      data_size, data);
}

static efi_status_t virt_efi_get_next_variable(unsigned long *name_size,
					       efi_char16_t *name,
					       efi_guid_t *vendor)
{
	return efi_call_virt3(get_next_variable,
			      name_size, name, vendor);
}

static efi_status_t virt_efi_set_variable(efi_char16_t *name,
					  efi_guid_t *vendor,
					  u32 attr,
					  unsigned long data_size,
					  void *data)
{
	return efi_call_virt5(set_variable,
			      name, vendor, attr,
			      data_size, data);
}

static efi_status_t virt_efi_query_variable_info(u32 attr,
						 u64 *storage_space,
						 u64 *remaining_space,
						 u64 *max_variable_size)
{
	if (efi.runtime_version < EFI_2_00_SYSTEM_TABLE_REVISION)
		return EFI_UNSUPPORTED;

	return efi_call_virt4(query_variable_info, attr, storage_space,
			      remaining_space, max_variable_size);
}

static efi_status_t virt_efi_get_next_high_mono_count(u32 *count)
{
	return efi_call_virt1(get_next_high_mono_count, count);
}

static void virt_efi_reset_system(int reset_type,
				  efi_status_t status,
				  unsigned long data_size,
				  efi_char16_t *data)
{
	efi_call_virt4(reset_system, reset_type, status,
		       data_size, data);
}

static efi_status_t virt_efi_update_capsule(efi_capsule_header_t **capsules,
					    unsigned long count,
					    unsigned long sg_list)
{
	if (efi.runtime_version < EFI_2_00_SYSTEM_TABLE_REVISION)
		return EFI_UNSUPPORTED;

	return efi_call_virt3(update_capsule, capsules, count, sg_list);
}

static efi_status_t virt_efi_query_capsule_caps(efi_capsule_header_t **capsules,
						unsigned long count,
						u64 *max_size,
						int *reset_type)
{
	if (efi.runtime_version < EFI_2_00_SYSTEM_TABLE_REVISION)
		return EFI_UNSUPPORTED;

	return efi_call_virt4(query_capsule_caps, capsules, count, max_size,
			      reset_type);
}

static efi_status_t __init phys_efi_set_virtual_address_map(
	unsigned long memory_map_size,
	unsigned long descriptor_size,
	u32 descriptor_version,
	efi_memory_desc_t *virtual_map)
{
	efi_status_t status;
	unsigned long flags;

	efi_call_phys_prelog();

	local_irq_save(flags);
	status = efi_call_phys4(efi_phys.set_virtual_address_map,
				memory_map_size, descriptor_size,
				descriptor_version, virtual_map);
	local_irq_restore(flags);

	efi_call_phys_epilog();

	return status;
}

static efi_status_t __init phys_efi_get_time(efi_time_t *tm,
					     efi_time_cap_t *tc)
{
	unsigned long flags;
	efi_status_t status;

	spin_lock_irqsave(&rtc_lock, flags);
	efi_call_phys_prelog();
	status = efi_call_phys2(efi_phys.get_time, virt_to_phys(tm),
				virt_to_phys(tc));
	efi_call_phys_epilog();
	spin_unlock_irqrestore(&rtc_lock, flags);
	return status;
}

int efi_set_rtc_mmss(unsigned long nowtime)
{
	efi_status_t 	status;
	efi_time_t 	eft;
	efi_time_cap_t 	cap;
	struct rtc_time	tm;

	status = efi.get_time(&eft, &cap);
	if (status != EFI_SUCCESS) {
		pr_err("Oops: efitime: can't read time!\n");
		return -1;
	}

	rtc_time_to_tm(nowtime, &tm);
	if (!rtc_valid_tm(&tm)) {
		eft.year = tm.tm_year + 1900;
		eft.month = tm.tm_mon + 1;
		eft.day = tm.tm_mday;
		eft.minute = tm.tm_min;
		eft.second = tm.tm_sec;
		eft.nanosecond = 0;
	} else {
		printk(KERN_ERR
		       "%s: Invalid EFI RTC value: write of %lx to EFI RTC failed\n",
		       __FUNCTION__, nowtime);
		return -1;
	}

	status = efi.set_time(&eft);
	if (status != EFI_SUCCESS) {
		pr_err("Oops: efitime: can't write time!\n");
		return -1;
	}
	return 0;
}

unsigned long efi_get_time(void)
{
	efi_status_t status;
	efi_time_t eft;
	efi_time_cap_t cap;

	status = efi.get_time(&eft, &cap);
	if (status != EFI_SUCCESS)
		pr_err("Oops: efitime: can't read time!\n");

	return mktime(eft.year, eft.month, eft.day, eft.hour,
		      eft.minute, eft.second);
}

static void __init do_add_efi_memmap(void)
{
	void *p;

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		efi_memory_desc_t *md = p;
		unsigned long long start = md->phys_addr;
		unsigned long long size = md->num_pages << EFI_PAGE_SHIFT;
		int e820_type;

		switch (md->type) {
		case EFI_LOADER_CODE:
		case EFI_LOADER_DATA:
		case EFI_BOOT_SERVICES_CODE:
		case EFI_BOOT_SERVICES_DATA:
		case EFI_CONVENTIONAL_MEMORY:
			if (md->attribute & EFI_MEMORY_WB)
				e820_type = E820_RAM;
			else
				e820_type = E820_RESERVED;
			break;
		case EFI_ACPI_RECLAIM_MEMORY:
			e820_type = E820_ACPI;
			break;
		case EFI_ACPI_MEMORY_NVS:
			e820_type = E820_NVS;
			break;
		case EFI_UNUSABLE_MEMORY:
			e820_type = E820_UNUSABLE;
			break;
		default:
			 
			e820_type = E820_RESERVED;
			break;
		}
		e820_add_region(start, size, e820_type);
	}
	sanitize_e820_map(e820.map, ARRAY_SIZE(e820.map), &e820.nr_map);
}

int __init efi_memblock_x86_reserve_range(void)
{
	struct efi_info *e = &boot_params.efi_info;
	unsigned long pmap;

#ifdef CONFIG_X86_32
	 
	if (e->efi_memmap_hi) {
		pr_err("Memory map is above 4GB, disabling EFI.\n");
		return -EINVAL;
	}
	pmap =  e->efi_memmap;
#else
	pmap = (e->efi_memmap |	((__u64)e->efi_memmap_hi << 32));
#endif
	memmap.phys_map		= (void *)pmap;
	memmap.nr_map		= e->efi_memmap_size /
				  e->efi_memdesc_size;
	memmap.desc_size	= e->efi_memdesc_size;
	memmap.desc_version	= e->efi_memdesc_version;

	memblock_reserve(pmap, memmap.nr_map * memmap.desc_size);

	return 0;
}

#if EFI_DEBUG
static void __init print_efi_memmap(void)
{
	efi_memory_desc_t *md;
	void *p;
	int i;

	for (p = memmap.map, i = 0;
	     p < memmap.map_end;
	     p += memmap.desc_size, i++) {
		md = p;
		pr_info("mem%02u: type=%u, attr=0x%llx, "
			"range=[0x%016llx-0x%016llx) (%lluMB)\n",
			i, md->type, md->attribute, md->phys_addr,
			md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT),
			(md->num_pages >> (20 - EFI_PAGE_SHIFT)));
	}
}
#endif   

void __init efi_reserve_boot_services(void)
{
	void *p;

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		efi_memory_desc_t *md = p;
		u64 start = md->phys_addr;
		u64 size = md->num_pages << EFI_PAGE_SHIFT;

		if (md->type != EFI_BOOT_SERVICES_CODE &&
		    md->type != EFI_BOOT_SERVICES_DATA)
			continue;
		 
		if ((start + size > __pa_symbol(_text)
				&& start <= __pa_symbol(_end)) ||
			!e820_all_mapped(start, start+size, E820_RAM) ||
			memblock_is_region_reserved(start, size)) {
			 
			md->num_pages = 0;
			memblock_dbg("Could not reserve boot range "
					"[0x%010llx-0x%010llx]\n",
						start, start+size-1);
		} else
			memblock_reserve(start, size);
	}
}

void __init efi_unmap_memmap(void)
{
	clear_bit(EFI_MEMMAP, &x86_efi_facility);
	if (memmap.map) {
		early_iounmap(memmap.map, memmap.nr_map * memmap.desc_size);
		memmap.map = NULL;
	}
}

void __init efi_free_boot_services(void)
{
	void *p;

	if (!efi_is_native())
		return;

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		efi_memory_desc_t *md = p;
		unsigned long long start = md->phys_addr;
		unsigned long long size = md->num_pages << EFI_PAGE_SHIFT;

		if (md->type != EFI_BOOT_SERVICES_CODE &&
		    md->type != EFI_BOOT_SERVICES_DATA)
			continue;

		if (!size)
			continue;

		free_bootmem_late(start, size);
	}

	efi_unmap_memmap();
}

static int __init efi_systab_init(void *phys)
{
	if (efi_enabled(EFI_64BIT)) {
		efi_system_table_64_t *systab64;
		u64 tmp = 0;

		systab64 = early_ioremap((unsigned long)phys,
					 sizeof(*systab64));
		if (systab64 == NULL) {
			pr_err("Couldn't map the system table!\n");
			return -ENOMEM;
		}

		efi_systab.hdr = systab64->hdr;
		efi_systab.fw_vendor = systab64->fw_vendor;
		tmp |= systab64->fw_vendor;
		efi_systab.fw_revision = systab64->fw_revision;
		efi_systab.con_in_handle = systab64->con_in_handle;
		tmp |= systab64->con_in_handle;
		efi_systab.con_in = systab64->con_in;
		tmp |= systab64->con_in;
		efi_systab.con_out_handle = systab64->con_out_handle;
		tmp |= systab64->con_out_handle;
		efi_systab.con_out = systab64->con_out;
		tmp |= systab64->con_out;
		efi_systab.stderr_handle = systab64->stderr_handle;
		tmp |= systab64->stderr_handle;
		efi_systab.stderr = systab64->stderr;
		tmp |= systab64->stderr;
		efi_systab.runtime = (void *)(unsigned long)systab64->runtime;
		tmp |= systab64->runtime;
		efi_systab.boottime = (void *)(unsigned long)systab64->boottime;
		tmp |= systab64->boottime;
		efi_systab.nr_tables = systab64->nr_tables;
		efi_systab.tables = systab64->tables;
		tmp |= systab64->tables;

		early_iounmap(systab64, sizeof(*systab64));
#ifdef CONFIG_X86_32
		if (tmp >> 32) {
			pr_err("EFI data located above 4GB, disabling EFI.\n");
			return -EINVAL;
		}
#endif
	} else {
		efi_system_table_32_t *systab32;

		systab32 = early_ioremap((unsigned long)phys,
					 sizeof(*systab32));
		if (systab32 == NULL) {
			pr_err("Couldn't map the system table!\n");
			return -ENOMEM;
		}

		efi_systab.hdr = systab32->hdr;
		efi_systab.fw_vendor = systab32->fw_vendor;
		efi_systab.fw_revision = systab32->fw_revision;
		efi_systab.con_in_handle = systab32->con_in_handle;
		efi_systab.con_in = systab32->con_in;
		efi_systab.con_out_handle = systab32->con_out_handle;
		efi_systab.con_out = systab32->con_out;
		efi_systab.stderr_handle = systab32->stderr_handle;
		efi_systab.stderr = systab32->stderr;
		efi_systab.runtime = (void *)(unsigned long)systab32->runtime;
		efi_systab.boottime = (void *)(unsigned long)systab32->boottime;
		efi_systab.nr_tables = systab32->nr_tables;
		efi_systab.tables = systab32->tables;

		early_iounmap(systab32, sizeof(*systab32));
	}

	efi.systab = &efi_systab;

	if (efi.systab->hdr.signature != EFI_SYSTEM_TABLE_SIGNATURE) {
		pr_err("System table signature incorrect!\n");
		return -EINVAL;
	}
	if ((efi.systab->hdr.revision >> 16) == 0)
		pr_err("Warning: System table version "
		       "%d.%02d, expected 1.00 or greater!\n",
		       efi.systab->hdr.revision >> 16,
		       efi.systab->hdr.revision & 0xffff);

	return 0;
}

static int __init efi_config_init(u64 tables, int nr_tables)
{
	void *config_tables, *tablep;
	int i, sz;

	if (efi_enabled(EFI_64BIT))
		sz = sizeof(efi_config_table_64_t);
	else
		sz = sizeof(efi_config_table_32_t);

	config_tables = early_ioremap(tables, nr_tables * sz);
	if (config_tables == NULL) {
		pr_err("Could not map Configuration table!\n");
		return -ENOMEM;
	}

	tablep = config_tables;
	pr_info("");
	for (i = 0; i < efi.systab->nr_tables; i++) {
		efi_guid_t guid;
		unsigned long table;

		if (efi_enabled(EFI_64BIT)) {
			u64 table64;
			guid = ((efi_config_table_64_t *)tablep)->guid;
			table64 = ((efi_config_table_64_t *)tablep)->table;
			table = table64;
#ifdef CONFIG_X86_32
			if (table64 >> 32) {
				pr_cont("\n");
				pr_err("Table located above 4GB, disabling EFI.\n");
				early_iounmap(config_tables,
					      efi.systab->nr_tables * sz);
				return -EINVAL;
			}
#endif
		} else {
			guid = ((efi_config_table_32_t *)tablep)->guid;
			table = ((efi_config_table_32_t *)tablep)->table;
		}
		if (!efi_guidcmp(guid, MPS_TABLE_GUID)) {
			efi.mps = table;
			pr_cont(" MPS=0x%lx ", table);
		} else if (!efi_guidcmp(guid, ACPI_20_TABLE_GUID)) {
			efi.acpi20 = table;
			pr_cont(" ACPI 2.0=0x%lx ", table);
		} else if (!efi_guidcmp(guid, ACPI_TABLE_GUID)) {
			efi.acpi = table;
			pr_cont(" ACPI=0x%lx ", table);
		} else if (!efi_guidcmp(guid, SMBIOS_TABLE_GUID)) {
			efi.smbios = table;
			pr_cont(" SMBIOS=0x%lx ", table);
#ifdef CONFIG_X86_UV
		} else if (!efi_guidcmp(guid, UV_SYSTEM_TABLE_GUID)) {
			efi.uv_systab = table;
			pr_cont(" UVsystab=0x%lx ", table);
#endif
		} else if (!efi_guidcmp(guid, HCDP_TABLE_GUID)) {
			efi.hcdp = table;
			pr_cont(" HCDP=0x%lx ", table);
		} else if (!efi_guidcmp(guid, UGA_IO_PROTOCOL_GUID)) {
			efi.uga = table;
			pr_cont(" UGA=0x%lx ", table);
		}
		tablep += sz;
	}
	pr_cont("\n");
	early_iounmap(config_tables, efi.systab->nr_tables * sz);
	return 0;
}

static int __init efi_runtime_init(void)
{
	efi_runtime_services_t *runtime;

	runtime = early_ioremap((unsigned long)efi.systab->runtime,
				sizeof(efi_runtime_services_t));
	if (!runtime) {
		pr_err("Could not map the runtime service table!\n");
		return -ENOMEM;
	}
	 
	efi_phys.get_time = (efi_get_time_t *)runtime->get_time;
	efi_phys.set_virtual_address_map =
		(efi_set_virtual_address_map_t *)
		runtime->set_virtual_address_map;
	 
	efi.get_time = phys_efi_get_time;
	early_iounmap(runtime, sizeof(efi_runtime_services_t));

	return 0;
}

static int __init efi_memmap_init(void)
{
	 
	memmap.map = early_ioremap((unsigned long)memmap.phys_map,
				   memmap.nr_map * memmap.desc_size);
	if (memmap.map == NULL) {
		pr_err("Could not map the memory map!\n");
		return -ENOMEM;
	}
	memmap.map_end = memmap.map + (memmap.nr_map * memmap.desc_size);

	if (add_efi_memmap)
		do_add_efi_memmap();

	return 0;
}

void __init efi_init(void)
{
	efi_char16_t *c16;
	char vendor[100] = "unknown";
	int i = 0;
	void *tmp;

#ifdef CONFIG_X86_32
	if (boot_params.efi_info.efi_systab_hi ||
	    boot_params.efi_info.efi_memmap_hi) {
		pr_info("Table located above 4GB, disabling EFI.\n");
		return;
	}
	efi_phys.systab = (efi_system_table_t *)boot_params.efi_info.efi_systab;
#else
	efi_phys.systab = (efi_system_table_t *)
			  (boot_params.efi_info.efi_systab |
			  ((__u64)boot_params.efi_info.efi_systab_hi<<32));
#endif

	if (efi_systab_init(efi_phys.systab))
		return;

	set_bit(EFI_SYSTEM_TABLES, &x86_efi_facility);

	c16 = tmp = early_ioremap(efi.systab->fw_vendor, 2);
	if (c16) {
		for (i = 0; i < sizeof(vendor) - 1 && *c16; ++i)
			vendor[i] = *c16++;
		vendor[i] = '\0';
	} else
		pr_err("Could not map the firmware vendor!\n");
	early_iounmap(tmp, 2);

	pr_info("EFI v%u.%.02u by %s\n",
		efi.systab->hdr.revision >> 16,
		efi.systab->hdr.revision & 0xffff, vendor);

	if (efi_config_init(efi.systab->tables, efi.systab->nr_tables))
		return;

	set_bit(EFI_CONFIG_TABLES, &x86_efi_facility);

	if (!efi_is_native())
		pr_info("No EFI runtime due to 32/64-bit mismatch with kernel\n");
	else {
		if (disable_runtime || efi_runtime_init())
			return;
		set_bit(EFI_RUNTIME_SERVICES, &x86_efi_facility);
	}

	if (efi_memmap_init())
		return;

	set_bit(EFI_MEMMAP, &x86_efi_facility);

#ifdef MY_DEF_HERE
	 
	reboot_type = BOOT_EFI;
#endif

#if EFI_DEBUG
	print_efi_memmap();
#endif
}

void __init efi_late_init(void)
{
	efi_bgrt_init();
}

void __init efi_set_executable(efi_memory_desc_t *md, bool executable)
{
	u64 addr, npages;

	addr = md->virt_addr;
	npages = md->num_pages;

	memrange_efi_to_native(&addr, &npages);

	if (executable)
		set_memory_x(addr, npages);
	else
		set_memory_nx(addr, npages);
}

static void __init runtime_code_page_mkexec(void)
{
	efi_memory_desc_t *md;
	void *p;

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		md = p;

		if (md->type != EFI_RUNTIME_SERVICES_CODE)
			continue;

		efi_set_executable(md, true);
	}
}

void __iomem *efi_lookup_mapped_addr(u64 phys_addr)
{
	void *p;
	if (WARN_ON(!memmap.map))
		return NULL;
	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		efi_memory_desc_t *md = p;
		u64 size = md->num_pages << EFI_PAGE_SHIFT;
		u64 end = md->phys_addr + size;
		if (!(md->attribute & EFI_MEMORY_RUNTIME) &&
		    md->type != EFI_BOOT_SERVICES_CODE &&
		    md->type != EFI_BOOT_SERVICES_DATA)
			continue;
		if (!md->virt_addr)
			continue;
		if (phys_addr >= md->phys_addr && phys_addr < end) {
			phys_addr += md->virt_addr - md->phys_addr;
			return (__force void __iomem *)(unsigned long)phys_addr;
		}
	}
	return NULL;
}

void efi_memory_uc(u64 addr, unsigned long size)
{
	unsigned long page_shift = 1UL << EFI_PAGE_SHIFT;
	u64 npages;

	npages = round_up(size, page_shift) / page_shift;
	memrange_efi_to_native(&addr, &npages);
	set_memory_uc(addr, npages);
}

void __init efi_enter_virtual_mode(void)
{
	efi_memory_desc_t *md, *prev_md = NULL;
	efi_status_t status;
	unsigned long size;
	u64 end, systab, start_pfn, end_pfn;
	void *p, *va, *new_memmap = NULL;
	int count = 0;

	efi.systab = NULL;

	if (!efi_is_native()) {
		efi_unmap_memmap();
		return;
	}

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		u64 prev_size;
		md = p;

		if (!prev_md) {
			prev_md = md;
			continue;
		}

		if (prev_md->type != md->type ||
		    prev_md->attribute != md->attribute) {
			prev_md = md;
			continue;
		}

		prev_size = prev_md->num_pages << EFI_PAGE_SHIFT;

		if (md->phys_addr == (prev_md->phys_addr + prev_size)) {
			prev_md->num_pages += md->num_pages;
			md->type = EFI_RESERVED_TYPE;
			md->attribute = 0;
			continue;
		}
		prev_md = md;
	}

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		md = p;
		if (!(md->attribute & EFI_MEMORY_RUNTIME)) {
#ifdef CONFIG_X86_64
			if (md->type != EFI_BOOT_SERVICES_CODE &&
			    md->type != EFI_BOOT_SERVICES_DATA)
#endif
				continue;
		}

		size = md->num_pages << EFI_PAGE_SHIFT;
		end = md->phys_addr + size;

		start_pfn = PFN_DOWN(md->phys_addr);
		end_pfn = PFN_UP(end);
		if (pfn_range_is_mapped(start_pfn, end_pfn)) {
			va = __va(md->phys_addr);

			if (!(md->attribute & EFI_MEMORY_WB))
				efi_memory_uc((u64)(unsigned long)va, size);
		} else
			va = efi_ioremap(md->phys_addr, size,
					 md->type, md->attribute);

		md->virt_addr = (u64) (unsigned long) va;

		if (!va) {
			pr_err("ioremap of 0x%llX failed!\n",
			       (unsigned long long)md->phys_addr);
			continue;
		}

		systab = (u64) (unsigned long) efi_phys.systab;
		if (md->phys_addr <= systab && systab < end) {
			systab += md->virt_addr - md->phys_addr;
			efi.systab = (efi_system_table_t *) (unsigned long) systab;
		}
		new_memmap = krealloc(new_memmap,
				      (count + 1) * memmap.desc_size,
				      GFP_KERNEL);
		memcpy(new_memmap + (count * memmap.desc_size), md,
		       memmap.desc_size);
		count++;
	}

	BUG_ON(!efi.systab);

	status = phys_efi_set_virtual_address_map(
		memmap.desc_size * count,
		memmap.desc_size,
		memmap.desc_version,
		(efi_memory_desc_t *)__pa(new_memmap));

	if (status != EFI_SUCCESS) {
		pr_alert("Unable to switch EFI into virtual mode "
			 "(status=%lx)!\n", status);
		panic("EFI call to SetVirtualAddressMap() failed!");
	}

	efi.runtime_version = efi_systab.hdr.revision;
	efi.get_time = virt_efi_get_time;
	efi.set_time = virt_efi_set_time;
	efi.get_wakeup_time = virt_efi_get_wakeup_time;
	efi.set_wakeup_time = virt_efi_set_wakeup_time;
	efi.get_variable = virt_efi_get_variable;
	efi.get_next_variable = virt_efi_get_next_variable;
	efi.set_variable = virt_efi_set_variable;
	efi.get_next_high_mono_count = virt_efi_get_next_high_mono_count;
	efi.reset_system = virt_efi_reset_system;
	efi.set_virtual_address_map = NULL;
	efi.query_variable_info = virt_efi_query_variable_info;
	efi.update_capsule = virt_efi_update_capsule;
	efi.query_capsule_caps = virt_efi_query_capsule_caps;
	if (__supported_pte_mask & _PAGE_NX)
		runtime_code_page_mkexec();

	kfree(new_memmap);

	efi.set_variable(efi_dummy_name, &EFI_DUMMY_GUID,
			 EFI_VARIABLE_NON_VOLATILE |
			 EFI_VARIABLE_BOOTSERVICE_ACCESS |
			 EFI_VARIABLE_RUNTIME_ACCESS,
			 0, NULL);
}

u32 efi_mem_type(unsigned long phys_addr)
{
	efi_memory_desc_t *md;
	void *p;

	if (!efi_enabled(EFI_MEMMAP))
		return 0;

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		md = p;
		if ((md->phys_addr <= phys_addr) &&
		    (phys_addr < (md->phys_addr +
				  (md->num_pages << EFI_PAGE_SHIFT))))
			return md->type;
	}
	return 0;
}

u64 efi_mem_attributes(unsigned long phys_addr)
{
	efi_memory_desc_t *md;
	void *p;

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		md = p;
		if ((md->phys_addr <= phys_addr) &&
		    (phys_addr < (md->phys_addr +
				  (md->num_pages << EFI_PAGE_SHIFT))))
			return md->attribute;
	}
	return 0;
}

efi_status_t efi_query_variable_store(u32 attributes, unsigned long size)
{
	efi_status_t status;
	u64 storage_size, remaining_size, max_size;

	if (!(attributes & EFI_VARIABLE_NON_VOLATILE))
		return 0;

	status = efi.query_variable_info(attributes, &storage_size,
					 &remaining_size, &max_size);
	if (status != EFI_SUCCESS)
		return status;

	if ((remaining_size - size < EFI_MIN_RESERVE) &&
		!efi_no_storage_paranoia) {

		unsigned long dummy_size = remaining_size + 1024;
		void *dummy = kzalloc(dummy_size, GFP_ATOMIC);

		if (!dummy)
			return EFI_OUT_OF_RESOURCES;

		status = efi.set_variable(efi_dummy_name, &EFI_DUMMY_GUID,
					  EFI_VARIABLE_NON_VOLATILE |
					  EFI_VARIABLE_BOOTSERVICE_ACCESS |
					  EFI_VARIABLE_RUNTIME_ACCESS,
					  dummy_size, dummy);

		if (status == EFI_SUCCESS) {
			 
			efi.set_variable(efi_dummy_name, &EFI_DUMMY_GUID,
					 EFI_VARIABLE_NON_VOLATILE |
					 EFI_VARIABLE_BOOTSERVICE_ACCESS |
					 EFI_VARIABLE_RUNTIME_ACCESS,
					 0, dummy);
		}

		kfree(dummy);

		status = efi.query_variable_info(attributes, &storage_size,
						 &remaining_size, &max_size);

		if (status != EFI_SUCCESS)
			return status;

		if (remaining_size - size < EFI_MIN_RESERVE)
			return EFI_OUT_OF_RESOURCES;
	}

	return EFI_SUCCESS;
}
EXPORT_SYMBOL_GPL(efi_query_variable_store);
