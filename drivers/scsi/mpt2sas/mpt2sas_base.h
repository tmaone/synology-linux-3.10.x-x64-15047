#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef MPT2SAS_BASE_H_INCLUDED
#define MPT2SAS_BASE_H_INCLUDED

#include "mpi/mpi2_type.h"
#include "mpi/mpi2.h"
#include "mpi/mpi2_ioc.h"
#include "mpi/mpi2_cnfg.h"
#include "mpi/mpi2_init.h"
#include "mpi/mpi2_raid.h"
#include "mpi/mpi2_tool.h"
#include "mpi/mpi2_sas.h"

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_transport_sas.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_eh.h>

#include "mpt2sas_debug.h"

#define MPT2SAS_DRIVER_NAME		"mpt2sas"
#define MPT2SAS_AUTHOR	"LSI Corporation <DL-MPTFusionLinux@lsi.com>"
#define MPT2SAS_DESCRIPTION	"LSI MPT Fusion SAS 2.0 Device Driver"
#define MPT2SAS_DRIVER_VERSION		"14.100.00.00"
#define MPT2SAS_MAJOR_VERSION		14
#define MPT2SAS_MINOR_VERSION		100
#define MPT2SAS_BUILD_VERSION		00
#define MPT2SAS_RELEASE_VERSION		00

#ifdef CONFIG_SCSI_MPT2SAS_MAX_SGE
#if     CONFIG_SCSI_MPT2SAS_MAX_SGE  < 16
#define MPT2SAS_SG_DEPTH       16
#elif CONFIG_SCSI_MPT2SAS_MAX_SGE  > 128
#define MPT2SAS_SG_DEPTH       128
#else
#define MPT2SAS_SG_DEPTH       CONFIG_SCSI_MPT2SAS_MAX_SGE
#endif
#else
#define MPT2SAS_SG_DEPTH       128  
#endif

#define MPT2SAS_SATA_QUEUE_DEPTH	32
#define MPT2SAS_SAS_QUEUE_DEPTH		254
#define MPT2SAS_RAID_QUEUE_DEPTH	128

#define MPT_NAME_LENGTH			32	 
#define MPT_STRING_LENGTH		64

#define MPT_MAX_CALLBACKS		16

#define	 CAN_SLEEP			1
#define  NO_SLEEP			0

#define INTERNAL_CMDS_COUNT		10	 

#define MPI2_HIM_MASK			0xFFFFFFFF  

#define MPT2SAS_INVALID_DEVICE_HANDLE	0xFFFF

#define MPT2_IOC_PRE_RESET		1  
#define MPT2_IOC_AFTER_RESET		2  
#define MPT2_IOC_DONE_RESET		3  

#define MPT2SAS_FMT			"%s: "
#define MPT2SAS_INFO_FMT		KERN_INFO MPT2SAS_FMT
#define MPT2SAS_NOTE_FMT		KERN_NOTICE MPT2SAS_FMT
#define MPT2SAS_WARN_FMT		KERN_WARNING MPT2SAS_FMT
#define MPT2SAS_ERR_FMT			KERN_ERR MPT2SAS_FMT

#define MPT2SAS_DELL_BRANDING_SIZE                 32

#define MPT2SAS_DELL_6GBPS_SAS_HBA_BRANDING        "Dell 6Gbps SAS HBA"
#define MPT2SAS_DELL_PERC_H200_ADAPTER_BRANDING    "Dell PERC H200 Adapter"
#define MPT2SAS_DELL_PERC_H200_INTEGRATED_BRANDING "Dell PERC H200 Integrated"
#define MPT2SAS_DELL_PERC_H200_MODULAR_BRANDING    "Dell PERC H200 Modular"
#define MPT2SAS_DELL_PERC_H200_EMBEDDED_BRANDING   "Dell PERC H200 Embedded"
#define MPT2SAS_DELL_PERC_H200_BRANDING            "Dell PERC H200"
#define MPT2SAS_DELL_6GBPS_SAS_BRANDING            "Dell 6Gbps SAS"

#define MPT2SAS_DELL_6GBPS_SAS_HBA_SSDID           0x1F1C
#define MPT2SAS_DELL_PERC_H200_ADAPTER_SSDID       0x1F1D
#define MPT2SAS_DELL_PERC_H200_INTEGRATED_SSDID    0x1F1E
#define MPT2SAS_DELL_PERC_H200_MODULAR_SSDID       0x1F1F
#define MPT2SAS_DELL_PERC_H200_EMBEDDED_SSDID      0x1F20
#define MPT2SAS_DELL_PERC_H200_SSDID               0x1F21
#define MPT2SAS_DELL_6GBPS_SAS_SSDID               0x1F22

#define MPT2SAS_INTEL_RMS25JB080_BRANDING    \
				"Intel(R) Integrated RAID Module RMS25JB080"
#define MPT2SAS_INTEL_RMS25JB040_BRANDING    \
				"Intel(R) Integrated RAID Module RMS25JB040"
#define MPT2SAS_INTEL_RMS25KB080_BRANDING    \
				"Intel(R) Integrated RAID Module RMS25KB080"
#define MPT2SAS_INTEL_RMS25KB040_BRANDING    \
				"Intel(R) Integrated RAID Module RMS25KB040"
#define MPT2SAS_INTEL_RMS25LB040_BRANDING	\
				"Intel(R) Integrated RAID Module RMS25LB040"
#define MPT2SAS_INTEL_RMS25LB080_BRANDING	\
				"Intel(R) Integrated RAID Module RMS25LB080"
#define MPT2SAS_INTEL_RMS2LL080_BRANDING	\
				"Intel Integrated RAID Module RMS2LL080"
#define MPT2SAS_INTEL_RMS2LL040_BRANDING	\
				"Intel Integrated RAID Module RMS2LL040"
#define MPT2SAS_INTEL_RS25GB008_BRANDING       \
				"Intel(R) RAID Controller RS25GB008"
#define MPT2SAS_INTEL_SSD910_BRANDING          \
				"Intel(R) SSD 910 Series"
 
#define MPT2SAS_INTEL_RMS25JB080_SSDID         0x3516
#define MPT2SAS_INTEL_RMS25JB040_SSDID         0x3517
#define MPT2SAS_INTEL_RMS25KB080_SSDID         0x3518
#define MPT2SAS_INTEL_RMS25KB040_SSDID         0x3519
#define MPT2SAS_INTEL_RMS25LB040_SSDID         0x351A
#define MPT2SAS_INTEL_RMS25LB080_SSDID         0x351B
#define MPT2SAS_INTEL_RMS2LL080_SSDID          0x350E
#define MPT2SAS_INTEL_RMS2LL040_SSDID          0x350F
#define MPT2SAS_INTEL_RS25GB008_SSDID          0x3000
#define MPT2SAS_INTEL_SSD910_SSDID             0x3700

#define MPT2SAS_HP_3PAR_SSVID                0x1590
#define MPT2SAS_HP_2_4_INTERNAL_BRANDING        "HP H220 Host Bus Adapter"
#define MPT2SAS_HP_2_4_EXTERNAL_BRANDING        "HP H221 Host Bus Adapter"
#define MPT2SAS_HP_1_4_INTERNAL_1_4_EXTERNAL_BRANDING "HP H222 Host Bus Adapter"
#define MPT2SAS_HP_EMBEDDED_2_4_INTERNAL_BRANDING    "HP H220i Host Bus Adapter"
#define MPT2SAS_HP_DAUGHTER_2_4_INTERNAL_BRANDING    "HP H210i Host Bus Adapter"

#define MPT2SAS_HP_2_4_INTERNAL_SSDID            0x0041
#define MPT2SAS_HP_2_4_EXTERNAL_SSDID            0x0042
#define MPT2SAS_HP_1_4_INTERNAL_1_4_EXTERNAL_SSDID    0x0043
#define MPT2SAS_HP_EMBEDDED_2_4_INTERNAL_SSDID        0x0044
#define MPT2SAS_HP_DAUGHTER_2_4_INTERNAL_SSDID        0x0046

#define MPT2_WARPDRIVE_LOGENTRY		(0x8002)
#define MPT2_WARPDRIVE_LC_SSDT		(0x41)
#define MPT2_WARPDRIVE_LC_SSDLW		(0x43)
#define MPT2_WARPDRIVE_LC_SSDLF		(0x44)
#define MPT2_WARPDRIVE_LC_BRMF		(0x4D)

#define MPT_TARGET_FLAGS_RAID_COMPONENT	0x01
#define MPT_TARGET_FLAGS_VOLUME		0x02
#define MPT_TARGET_FLAGS_DELETED	0x04

struct MPT2SAS_TARGET {
	struct scsi_target *starget;
	u64	sas_address;
	struct _raid_device *raid_device;
	u16	handle;
	int	num_luns;
	u32	flags;
	u8	deleted;
	u8	tm_busy;
};

#define MPT_DEVICE_FLAGS_INIT		0x01
#define MPT_DEVICE_TLR_ON		0x02

#define MFG10_OEM_ID_INVALID                   (0x00000000)
#define MFG10_OEM_ID_DELL                      (0x00000001)
#define MFG10_OEM_ID_FSC                       (0x00000002)
#define MFG10_OEM_ID_SUN                       (0x00000003)
#define MFG10_OEM_ID_IBM                       (0x00000004)

#define MFG10_GF0_OCE_DISABLED                 (0x00000001)
#define MFG10_GF0_R1E_DRIVE_COUNT              (0x00000002)
#define MFG10_GF0_R10_DISPLAY                  (0x00000004)
#define MFG10_GF0_SSD_DATA_SCRUB_DISABLE       (0x00000008)
#define MFG10_GF0_SINGLE_DRIVE_R0              (0x00000010)

typedef struct _MPI2_CONFIG_PAGE_MAN_10 {
    MPI2_CONFIG_PAGE_HEADER Header;                                  
    U8                      OEMIdentifier;                           
    U8                      Reserved1;                               
    U16                     Reserved2;                               
    U32                     Reserved3;                               
    U32                     GenericFlags0;                           
    U32                     GenericFlags1;                           
    U32                     Reserved4;                               
    U32                     OEMSpecificFlags0;                       
    U32                     OEMSpecificFlags1;                       
    U32                     Reserved5[18];                           
} MPI2_CONFIG_PAGE_MAN_10,
  MPI2_POINTER PTR_MPI2_CONFIG_PAGE_MAN_10,
  Mpi2ManufacturingPage10_t, MPI2_POINTER pMpi2ManufacturingPage10_t;

#define MFG_PAGE10_HIDE_SSDS_MASK	(0x00000003)
#define MFG_PAGE10_HIDE_ALL_DISKS	(0x00)
#define MFG_PAGE10_EXPOSE_ALL_DISKS	(0x01)
#define MFG_PAGE10_HIDE_IF_VOL_PRESENT	(0x02)

struct MPT2SAS_DEVICE {
	struct MPT2SAS_TARGET *sas_target;
	unsigned int	lun;
	u32	flags;
	u8	configured_lun;
	u8	block;
	u8	tlr_snoop_check;
};

#define MPT2_CMD_NOT_USED	0x8000	 
#define MPT2_CMD_COMPLETE	0x0001	 
#define MPT2_CMD_PENDING	0x0002	 
#define MPT2_CMD_REPLY_VALID	0x0004	 
#define MPT2_CMD_RESET		0x0008	 

struct _internal_cmd {
	struct mutex mutex;
	struct completion done;
	void 	*reply;
	void	*sense;
	u16	status;
	u16	smid;
};

struct _sas_device {
	struct list_head list;
	struct scsi_target *starget;
	u64	sas_address;
	u64	device_name;
	u16	handle;
	u64	sas_address_parent;
	u16	enclosure_handle;
	u64	enclosure_logical_id;
	u16	volume_handle;
	u64	volume_wwid;
	u32	device_info;
	int	id;
	int	channel;
	u16	slot;
	u8	phy;
	u8	responding;
};

#define MPT_MAX_WARPDRIVE_PDS		8
struct _raid_device {
	struct list_head list;
	struct scsi_target *starget;
	struct scsi_device *sdev;
	u64	wwid;
	u16	handle;
	u16	block_sz;
	int	id;
	int	channel;
	u8	volume_type;
	u8	num_pds;
	u8	responding;
	u8	percent_complete;
	u8	direct_io_enabled;
	u8	stripe_exponent;
	u8	block_exponent;
	u64	max_lba;
	u32	stripe_sz;
	u32	device_info;
	u16	pd_handle[MPT_MAX_WARPDRIVE_PDS];
};

struct _boot_device {
	u8 is_raid;
	void *device;
};

struct _sas_port {
	struct list_head port_list;
	u8	num_phys;
	struct sas_identify remote_identify;
	struct sas_rphy *rphy;
	struct sas_port *port;
	struct list_head phy_list;
};

struct _sas_phy {
	struct list_head port_siblings;
	struct sas_identify identify;
	struct sas_identify remote_identify;
	struct sas_phy *phy;
	u8	phy_id;
	u16	handle;
	u16	attached_handle;
	u8	phy_belongs_to_port;
};

struct _sas_node {
	struct list_head list;
	struct device *parent_dev;
	u8	num_phys;
	u64	sas_address;
	u16	handle;
	u64	sas_address_parent;
	u16	enclosure_handle;
	u64	enclosure_logical_id;
	u8	responding;
	struct	_sas_phy *phy;
	struct list_head sas_port_list;
};

enum reset_type {
	FORCE_BIG_HAMMER,
	SOFT_RESET,
};

struct chain_tracker {
	void *chain_buffer;
	dma_addr_t chain_buffer_dma;
	struct list_head tracker_list;
};

struct scsiio_tracker {
	u16	smid;
	struct scsi_cmnd *scmd;
	u8	cb_idx;
	u8	direct_io;
	struct list_head chain_list;
	struct list_head tracker_list;
};

struct request_tracker {
	u16	smid;
	u8	cb_idx;
	struct list_head tracker_list;
};

struct _tr_list {
	struct list_head list;
	u16	handle;
	u16	state;
};

typedef void (*MPT_ADD_SGE)(void *paddr, u32 flags_length, dma_addr_t dma_addr);

struct adapter_reply_queue {
	struct MPT2SAS_ADAPTER	*ioc;
	u8			msix_index;
	unsigned int		vector;
	u32			reply_post_host_index;
	Mpi2ReplyDescriptorsUnion_t *reply_post_free;
	char			name[MPT_NAME_LENGTH];
	atomic_t		busy;
	struct list_head	list;
};

union mpi2_version_union {
	MPI2_VERSION_STRUCT		Struct;
	u32				Word;
};

struct mpt2sas_facts {
	u16			MsgVersion;
	u16			HeaderVersion;
	u8			IOCNumber;
	u8			VP_ID;
	u8			VF_ID;
	u16			IOCExceptions;
	u16			IOCStatus;
	u32			IOCLogInfo;
	u8			MaxChainDepth;
	u8			WhoInit;
	u8			NumberOfPorts;
	u8			MaxMSIxVectors;
	u16			RequestCredit;
	u16			ProductID;
	u32			IOCCapabilities;
	union mpi2_version_union	FWVersion;
	u16			IOCRequestFrameSize;
	u16			Reserved3;
	u16			MaxInitiators;
	u16			MaxTargets;
	u16			MaxSasExpanders;
	u16			MaxEnclosures;
	u16			ProtocolFlags;
	u16			HighPriorityCredit;
	u16			MaxReplyDescriptorPostQueueDepth;
	u8			ReplyFrameSize;
	u8			MaxVolumes;
	u16			MaxDevHandle;
	u16			MaxPersistentEntries;
	u16			MinDevHandle;
};

struct mpt2sas_port_facts {
	u8			PortNumber;
	u8			VP_ID;
	u8			VF_ID;
	u8			PortType;
	u16			MaxPostedCmdBuffers;
};

enum mutex_type {
	TM_MUTEX_OFF = 0,
	TM_MUTEX_ON = 1,
};

typedef void (*MPT2SAS_FLUSH_RUNNING_CMDS)(struct MPT2SAS_ADAPTER *ioc);
 
struct MPT2SAS_ADAPTER {
	struct list_head list;
	struct Scsi_Host *shost;
	u8		id;
	int		cpu_count;
	char		name[MPT_NAME_LENGTH];
	char		tmp_string[MPT_STRING_LENGTH];
	struct pci_dev	*pdev;
	Mpi2SystemInterfaceRegs_t __iomem *chip;
	resource_size_t	chip_phys;
	int		logging_level;
	int		fwfault_debug;
	u8		ir_firmware;
	int		bars;
	u8		mask_interrupts;

	char		fault_reset_work_q_name[20];
	struct workqueue_struct *fault_reset_work_q;
	struct delayed_work fault_reset_work;

	char		firmware_event_name[20];
	struct workqueue_struct	*firmware_event_thread;
	spinlock_t	fw_event_lock;
	struct list_head fw_event_list;

	int		aen_event_read_flag;
	u8		broadcast_aen_busy;
	u16		broadcast_aen_pending;
	u8		shost_recovery;

	struct mutex	reset_in_progress_mutex;
	spinlock_t 	ioc_reset_in_progress_lock;
	u8		ioc_link_reset_in_progress;
	u8		ioc_reset_in_progress_status;

	u8		ignore_loginfos;
	u8		remove_host;
	u8		pci_error_recovery;
	u8		wait_for_discovery_to_complete;
	struct completion	port_enable_done;
	u8		is_driver_loading;
	u8		port_enable_failed;

	u8		start_scan;
	u16		start_scan_failed;

	u8		msix_enable;
	u16		msix_vector_count;
	u8		*cpu_msix_table;
	resource_size_t	**reply_post_host_index;
	u16		cpu_msix_table_sz;
	u32		ioc_reset_count;
	MPT2SAS_FLUSH_RUNNING_CMDS schedule_dead_ioc_flush_running_cmds;
	u32             non_operational_loop;

	u8		scsi_io_cb_idx;
	u8		tm_cb_idx;
	u8		transport_cb_idx;
	u8		scsih_cb_idx;
	u8		ctl_cb_idx;
	u8		base_cb_idx;
	u8		port_enable_cb_idx;
	u8		config_cb_idx;
	u8		tm_tr_cb_idx;
	u8		tm_tr_volume_cb_idx;
	u8		tm_sas_control_cb_idx;
	struct _internal_cmd base_cmds;
	struct _internal_cmd port_enable_cmds;
	struct _internal_cmd transport_cmds;
	struct _internal_cmd scsih_cmds;
	struct _internal_cmd tm_cmds;
	struct _internal_cmd ctl_cmds;
	struct _internal_cmd config_cmds;

	MPT_ADD_SGE	base_add_sg_single;

	u32		event_type[MPI2_EVENT_NOTIFY_EVENTMASK_WORDS];
	u32		event_context;
	void		*event_log;
	u32		event_masks[MPI2_EVENT_NOTIFY_EVENTMASK_WORDS];

	struct mpt2sas_facts facts;
	struct mpt2sas_port_facts *pfacts;
	Mpi2ManufacturingPage0_t manu_pg0;
	Mpi2BiosPage2_t	bios_pg2;
	Mpi2BiosPage3_t	bios_pg3;
	Mpi2IOCPage8_t ioc_pg8;
	Mpi2IOUnitPage0_t iounit_pg0;
	Mpi2IOUnitPage1_t iounit_pg1;

	struct _boot_device req_boot_device;
	struct _boot_device req_alt_boot_device;
	struct _boot_device current_boot_device;

	struct _sas_node sas_hba;
	struct list_head sas_expander_list;
	spinlock_t	sas_node_lock;
	struct list_head sas_device_list;
	struct list_head sas_device_init_list;
	spinlock_t	sas_device_lock;
	struct list_head raid_device_list;
	spinlock_t	raid_device_lock;
	u8		io_missing_delay;
	u16		device_missing_delay;
	int		sas_id;
	void		*blocking_handles;
	void		*pd_handles;
	u16		pd_handles_sz;

	u16		config_page_sz;
	void 		*config_page;
	dma_addr_t	config_page_dma;

	u16		hba_queue_depth;
	u16		sge_size;
	u16 		scsiio_depth;
	u16		request_sz;
	u8		*request;
	dma_addr_t	request_dma;
	u32		request_dma_sz;
	struct scsiio_tracker *scsi_lookup;
	ulong		scsi_lookup_pages;
	spinlock_t 	scsi_lookup_lock;
	struct list_head free_list;
	int		pending_io_count;
	wait_queue_head_t reset_wq;

	struct chain_tracker *chain_lookup;
	struct list_head free_chain_list;
	struct dma_pool *chain_dma_pool;
	ulong		chain_pages;
	u16 		max_sges_in_main_message;
	u16		max_sges_in_chain_message;
	u16		chains_needed_per_io;
	u16		chain_offset_value_for_main_message;
	u32		chain_depth;

	u16		hi_priority_smid;
	u8		*hi_priority;
	dma_addr_t	hi_priority_dma;
	u16		hi_priority_depth;
	struct request_tracker *hpr_lookup;
	struct list_head hpr_free_list;

	u16		internal_smid;
	u8		*internal;
	dma_addr_t	internal_dma;
	u16		internal_depth;
	struct request_tracker *internal_lookup;
	struct list_head internal_free_list;

	u8		*sense;
	dma_addr_t	sense_dma;
	struct dma_pool *sense_dma_pool;

	u16		reply_sz;
	u8		*reply;
	dma_addr_t	reply_dma;
	u32		reply_dma_max_address;
	u32		reply_dma_min_address;
	struct dma_pool *reply_dma_pool;

	u16 		reply_free_queue_depth;
	__le32		*reply_free;
	dma_addr_t	reply_free_dma;
	struct dma_pool *reply_free_dma_pool;
	u32		reply_free_host_index;

	u16 		reply_post_queue_depth;
	Mpi2ReplyDescriptorsUnion_t *reply_post_free;
	dma_addr_t	reply_post_free_dma;
	struct dma_pool *reply_post_free_dma_pool;
	u8		reply_queue_count;
	struct list_head reply_queue_list;

	struct list_head delayed_tr_list;
	struct list_head delayed_tr_volume_list;

	u8		*diag_buffer[MPI2_DIAG_BUF_TYPE_COUNT];
	u32		diag_buffer_sz[MPI2_DIAG_BUF_TYPE_COUNT];
	dma_addr_t	diag_buffer_dma[MPI2_DIAG_BUF_TYPE_COUNT];
	u8		diag_buffer_status[MPI2_DIAG_BUF_TYPE_COUNT];
	u32		unique_id[MPI2_DIAG_BUF_TYPE_COUNT];
	Mpi2ManufacturingPage10_t manu_pg10;
	u32		product_specific[MPI2_DIAG_BUF_TYPE_COUNT][23];
	u32		diagnostic_flags[MPI2_DIAG_BUF_TYPE_COUNT];
	u32		ring_buffer_offset;
	u32		ring_buffer_sz;
	u8		is_warpdrive;
	u8		hide_ir_msg;
	u8		mfg_pg10_hide_flag;
	u8		hide_drives;

#ifdef MY_DEF_HERE
	u8		shutdown;
#endif  
};

typedef u8 (*MPT_CALLBACK)(struct MPT2SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
    u32 reply);

extern struct list_head mpt2sas_ioc_list;
void mpt2sas_base_start_watchdog(struct MPT2SAS_ADAPTER *ioc);
void mpt2sas_base_stop_watchdog(struct MPT2SAS_ADAPTER *ioc);

int mpt2sas_base_attach(struct MPT2SAS_ADAPTER *ioc);
void mpt2sas_base_detach(struct MPT2SAS_ADAPTER *ioc);
int mpt2sas_base_map_resources(struct MPT2SAS_ADAPTER *ioc);
void mpt2sas_base_free_resources(struct MPT2SAS_ADAPTER *ioc);
int mpt2sas_base_hard_reset_handler(struct MPT2SAS_ADAPTER *ioc, int sleep_flag,
    enum reset_type type);

void *mpt2sas_base_get_msg_frame(struct MPT2SAS_ADAPTER *ioc, u16 smid);
void *mpt2sas_base_get_sense_buffer(struct MPT2SAS_ADAPTER *ioc, u16 smid);
void mpt2sas_base_build_zero_len_sge(struct MPT2SAS_ADAPTER *ioc, void *paddr);
__le32 mpt2sas_base_get_sense_buffer_dma(struct MPT2SAS_ADAPTER *ioc,
    u16 smid);
void mpt2sas_base_flush_reply_queues(struct MPT2SAS_ADAPTER *ioc);

u16 mpt2sas_base_get_smid_hpr(struct MPT2SAS_ADAPTER *ioc, u8 cb_idx);
u16 mpt2sas_base_get_smid_scsiio(struct MPT2SAS_ADAPTER *ioc, u8 cb_idx,
    struct scsi_cmnd *scmd);

u16 mpt2sas_base_get_smid(struct MPT2SAS_ADAPTER *ioc, u8 cb_idx);
void mpt2sas_base_free_smid(struct MPT2SAS_ADAPTER *ioc, u16 smid);
void mpt2sas_base_put_smid_scsi_io(struct MPT2SAS_ADAPTER *ioc, u16 smid,
    u16 handle);
void mpt2sas_base_put_smid_hi_priority(struct MPT2SAS_ADAPTER *ioc, u16 smid);
void mpt2sas_base_put_smid_target_assist(struct MPT2SAS_ADAPTER *ioc, u16 smid,
    u16 io_index);
void mpt2sas_base_put_smid_default(struct MPT2SAS_ADAPTER *ioc, u16 smid);
void mpt2sas_base_initialize_callback_handler(void);
u8 mpt2sas_base_register_callback_handler(MPT_CALLBACK cb_func);
void mpt2sas_base_release_callback_handler(u8 cb_idx);

u8 mpt2sas_base_done(struct MPT2SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
    u32 reply);
u8 mpt2sas_port_enable_done(struct MPT2SAS_ADAPTER *ioc, u16 smid,
	u8 msix_index,	u32 reply);
void *mpt2sas_base_get_reply_virt_addr(struct MPT2SAS_ADAPTER *ioc, u32 phys_addr);

u32 mpt2sas_base_get_iocstate(struct MPT2SAS_ADAPTER *ioc, int cooked);

void mpt2sas_base_fault_info(struct MPT2SAS_ADAPTER *ioc , u16 fault_code);
int mpt2sas_base_sas_iounit_control(struct MPT2SAS_ADAPTER *ioc,
    Mpi2SasIoUnitControlReply_t *mpi_reply, Mpi2SasIoUnitControlRequest_t
    *mpi_request);
int mpt2sas_base_scsi_enclosure_processor(struct MPT2SAS_ADAPTER *ioc,
    Mpi2SepReply_t *mpi_reply, Mpi2SepRequest_t *mpi_request);
void mpt2sas_base_validate_event_type(struct MPT2SAS_ADAPTER *ioc, u32 *event_type);

void mpt2sas_halt_firmware(struct MPT2SAS_ADAPTER *ioc);

void mpt2sas_base_update_missing_delay(struct MPT2SAS_ADAPTER *ioc,
	u16 device_missing_delay, u8 io_missing_delay);

int mpt2sas_port_enable(struct MPT2SAS_ADAPTER *ioc);

u8 mpt2sas_scsih_event_callback(struct MPT2SAS_ADAPTER *ioc, u8 msix_index,
    u32 reply);
int mpt2sas_scsih_issue_tm(struct MPT2SAS_ADAPTER *ioc, u16 handle,
	uint channel, uint id, uint lun, u8 type, u16 smid_task,
	ulong timeout, unsigned long serial_number, enum mutex_type m_type);
void mpt2sas_scsih_set_tm_flag(struct MPT2SAS_ADAPTER *ioc, u16 handle);
void mpt2sas_scsih_clear_tm_flag(struct MPT2SAS_ADAPTER *ioc, u16 handle);
void mpt2sas_expander_remove(struct MPT2SAS_ADAPTER *ioc, u64 sas_address);
void mpt2sas_device_remove_by_sas_address(struct MPT2SAS_ADAPTER *ioc,
		u64 sas_address);
struct _sas_node *mpt2sas_scsih_expander_find_by_handle(struct MPT2SAS_ADAPTER *ioc,
    u16 handle);
struct _sas_node *mpt2sas_scsih_expander_find_by_sas_address(struct MPT2SAS_ADAPTER
    *ioc, u64 sas_address);
struct _sas_device *mpt2sas_scsih_sas_device_find_by_sas_address(
    struct MPT2SAS_ADAPTER *ioc, u64 sas_address);

void mpt2sas_port_enable_complete(struct MPT2SAS_ADAPTER *ioc);

void mpt2sas_scsih_reset_handler(struct MPT2SAS_ADAPTER *ioc, int reset_phase);

u8 mpt2sas_config_done(struct MPT2SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
    u32 reply);
int mpt2sas_config_get_number_hba_phys(struct MPT2SAS_ADAPTER *ioc, u8 *num_phys);
int mpt2sas_config_get_manufacturing_pg0(struct MPT2SAS_ADAPTER *ioc,
    Mpi2ConfigReply_t *mpi_reply, Mpi2ManufacturingPage0_t *config_page);
int mpt2sas_config_get_manufacturing_pg10(struct MPT2SAS_ADAPTER *ioc,
    Mpi2ConfigReply_t *mpi_reply, Mpi2ManufacturingPage10_t *config_page);
int mpt2sas_config_get_bios_pg2(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2BiosPage2_t *config_page);
int mpt2sas_config_get_bios_pg3(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2BiosPage3_t *config_page);
int mpt2sas_config_get_iounit_pg0(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2IOUnitPage0_t *config_page);
int mpt2sas_config_get_sas_device_pg0(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2SasDevicePage0_t *config_page, u32 form, u32 handle);
int mpt2sas_config_get_sas_device_pg1(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2SasDevicePage1_t *config_page, u32 form, u32 handle);
int mpt2sas_config_get_sas_iounit_pg0(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2SasIOUnitPage0_t *config_page, u16 sz);
int mpt2sas_config_get_iounit_pg1(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2IOUnitPage1_t *config_page);
int mpt2sas_config_set_iounit_pg1(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2IOUnitPage1_t *config_page);
int mpt2sas_config_get_iounit_pg3(struct MPT2SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2IOUnitPage3_t *config_page, u16 sz);
int mpt2sas_config_get_sas_iounit_pg1(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2SasIOUnitPage1_t *config_page, u16 sz);
int mpt2sas_config_set_sas_iounit_pg1(struct MPT2SAS_ADAPTER *ioc,
    Mpi2ConfigReply_t *mpi_reply, Mpi2SasIOUnitPage1_t *config_page, u16 sz);
int mpt2sas_config_get_ioc_pg8(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2IOCPage8_t *config_page);
int mpt2sas_config_get_expander_pg0(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2ExpanderPage0_t *config_page, u32 form, u32 handle);
int mpt2sas_config_get_expander_pg1(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2ExpanderPage1_t *config_page, u32 phy_number, u16 handle);
int mpt2sas_config_get_enclosure_pg0(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2SasEnclosurePage0_t *config_page, u32 form, u32 handle);
int mpt2sas_config_get_phy_pg0(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2SasPhyPage0_t *config_page, u32 phy_number);
int mpt2sas_config_get_phy_pg1(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2SasPhyPage1_t *config_page, u32 phy_number);
int mpt2sas_config_get_raid_volume_pg1(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2RaidVolPage1_t *config_page, u32 form, u32 handle);
int mpt2sas_config_get_number_pds(struct MPT2SAS_ADAPTER *ioc, u16 handle, u8 *num_pds);
int mpt2sas_config_get_raid_volume_pg0(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2RaidVolPage0_t *config_page, u32 form, u32 handle, u16 sz);
int mpt2sas_config_get_phys_disk_pg0(struct MPT2SAS_ADAPTER *ioc, Mpi2ConfigReply_t
    *mpi_reply, Mpi2RaidPhysDiskPage0_t *config_page, u32 form,
    u32 form_specific);
int mpt2sas_config_get_volume_handle(struct MPT2SAS_ADAPTER *ioc, u16 pd_handle,
    u16 *volume_handle);
int mpt2sas_config_get_volume_wwid(struct MPT2SAS_ADAPTER *ioc, u16 volume_handle,
    u64 *wwid);
 
extern struct device_attribute *mpt2sas_host_attrs[];
extern struct device_attribute *mpt2sas_dev_attrs[];
void mpt2sas_ctl_init(void);
void mpt2sas_ctl_exit(void);
u8 mpt2sas_ctl_done(struct MPT2SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
    u32 reply);
void mpt2sas_ctl_reset_handler(struct MPT2SAS_ADAPTER *ioc, int reset_phase);
u8 mpt2sas_ctl_event_callback(struct MPT2SAS_ADAPTER *ioc, u8 msix_index,
    u32 reply);
void mpt2sas_ctl_add_to_event_log(struct MPT2SAS_ADAPTER *ioc,
    Mpi2EventNotificationReply_t *mpi_reply);

void mpt2sas_enable_diag_buffer(struct MPT2SAS_ADAPTER *ioc,
	u8 bits_to_regsiter);

u8 mpt2sas_transport_done(struct MPT2SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
    u32 reply);
struct _sas_port *mpt2sas_transport_port_add(struct MPT2SAS_ADAPTER *ioc,
     u16 handle, u64 sas_address);
void mpt2sas_transport_port_remove(struct MPT2SAS_ADAPTER *ioc, u64 sas_address,
     u64 sas_address_parent);
int mpt2sas_transport_add_host_phy(struct MPT2SAS_ADAPTER *ioc, struct _sas_phy
    *mpt2sas_phy, Mpi2SasPhyPage0_t phy_pg0, struct device *parent_dev);
int mpt2sas_transport_add_expander_phy(struct MPT2SAS_ADAPTER *ioc, struct _sas_phy
    *mpt2sas_phy, Mpi2ExpanderPage1_t expander_pg1, struct device *parent_dev);
void mpt2sas_transport_update_links(struct MPT2SAS_ADAPTER *ioc,
     u64 sas_address, u16 handle, u8 phy_number, u8 link_rate);
extern struct sas_function_template mpt2sas_transport_functions;
extern struct scsi_transport_template *mpt2sas_transport_template;
extern int scsi_internal_device_block(struct scsi_device *sdev);
extern u8 mpt2sas_stm_zero_smid_handler(struct MPT2SAS_ADAPTER *ioc,
    u8 msix_index, u32 reply);
extern int scsi_internal_device_unblock(struct scsi_device *sdev,
					enum scsi_device_state new_state);

#endif  
