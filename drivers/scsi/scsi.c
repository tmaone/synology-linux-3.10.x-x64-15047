#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/unistd.h>
#include <linux/spinlock.h>
#include <linux/kmod.h>
#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/mutex.h>
#include <linux/async.h>
#include <asm/unaligned.h>
#ifdef MY_ABC_HERE
#include <linux/ata.h>
#endif  

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>

#include "scsi_priv.h"
#include "scsi_logging.h"

#define CREATE_TRACE_POINTS
#include <trace/events/scsi.h>

static void scsi_done(struct scsi_cmnd *cmd);

#define MIN_RESET_DELAY (2*HZ)

#define MIN_RESET_PERIOD (15*HZ)

#ifdef MY_ABC_HERE
#include <linux/synolib.h>
extern int syno_hibernation_log_level;
#endif  

unsigned int scsi_logging_level;
#if defined(CONFIG_SCSI_LOGGING)
EXPORT_SYMBOL(scsi_logging_level);
#endif

ASYNC_DOMAIN(scsi_sd_probe_domain);
EXPORT_SYMBOL(scsi_sd_probe_domain);

static const char *const scsi_device_types[] = {
	"Direct-Access    ",
	"Sequential-Access",
	"Printer          ",
	"Processor        ",
	"WORM             ",
	"CD-ROM           ",
	"Scanner          ",
	"Optical Device   ",
	"Medium Changer   ",
	"Communications   ",
	"ASC IT8          ",
	"ASC IT8          ",
	"RAID             ",
	"Enclosure        ",
	"Direct-Access-RBC",
	"Optical card     ",
	"Bridge controller",
	"Object storage   ",
	"Automation/Drive ",
};

const char * scsi_device_type(unsigned type)
{
	if (type == 0x1e)
		return "Well-known LUN   ";
	if (type == 0x1f)
		return "No Device        ";
	if (type >= ARRAY_SIZE(scsi_device_types))
		return "Unknown          ";
	return scsi_device_types[type];
}

EXPORT_SYMBOL(scsi_device_type);

struct scsi_host_cmd_pool {
	struct kmem_cache	*cmd_slab;
	struct kmem_cache	*sense_slab;
	unsigned int		users;
	char			*cmd_name;
	char			*sense_name;
	unsigned int		slab_flags;
	gfp_t			gfp_mask;
};

static struct scsi_host_cmd_pool scsi_cmd_pool = {
	.cmd_name	= "scsi_cmd_cache",
	.sense_name	= "scsi_sense_cache",
	.slab_flags	= SLAB_HWCACHE_ALIGN,
};

static struct scsi_host_cmd_pool scsi_cmd_dma_pool = {
	.cmd_name	= "scsi_cmd_cache(DMA)",
	.sense_name	= "scsi_sense_cache(DMA)",
	.slab_flags	= SLAB_HWCACHE_ALIGN|SLAB_CACHE_DMA,
	.gfp_mask	= __GFP_DMA,
};

static DEFINE_MUTEX(host_cmd_pool_mutex);

static struct scsi_cmnd *
scsi_pool_alloc_command(struct scsi_host_cmd_pool *pool, gfp_t gfp_mask)
{
	struct scsi_cmnd *cmd;

	cmd = kmem_cache_zalloc(pool->cmd_slab, gfp_mask | pool->gfp_mask);
	if (!cmd)
		return NULL;

	cmd->sense_buffer = kmem_cache_alloc(pool->sense_slab,
					     gfp_mask | pool->gfp_mask);
	if (!cmd->sense_buffer) {
		kmem_cache_free(pool->cmd_slab, cmd);
		return NULL;
	}

	return cmd;
}

static void
scsi_pool_free_command(struct scsi_host_cmd_pool *pool,
			 struct scsi_cmnd *cmd)
{
	if (cmd->prot_sdb)
		kmem_cache_free(scsi_sdb_cache, cmd->prot_sdb);

	kmem_cache_free(pool->sense_slab, cmd->sense_buffer);
	kmem_cache_free(pool->cmd_slab, cmd);
}

static struct scsi_cmnd *
scsi_host_alloc_command(struct Scsi_Host *shost, gfp_t gfp_mask)
{
	struct scsi_cmnd *cmd;

	cmd = scsi_pool_alloc_command(shost->cmd_pool, gfp_mask);
	if (!cmd)
		return NULL;

	if (scsi_host_get_prot(shost) >= SHOST_DIX_TYPE0_PROTECTION) {
		cmd->prot_sdb = kmem_cache_zalloc(scsi_sdb_cache, gfp_mask);

		if (!cmd->prot_sdb) {
			scsi_pool_free_command(shost->cmd_pool, cmd);
			return NULL;
		}
	}

	return cmd;
}

struct scsi_cmnd *__scsi_get_command(struct Scsi_Host *shost, gfp_t gfp_mask)
{
	struct scsi_cmnd *cmd = scsi_host_alloc_command(shost, gfp_mask);

	if (unlikely(!cmd)) {
		unsigned long flags;

		spin_lock_irqsave(&shost->free_list_lock, flags);
		if (likely(!list_empty(&shost->free_list))) {
			cmd = list_entry(shost->free_list.next,
					 struct scsi_cmnd, list);
			list_del_init(&cmd->list);
		}
		spin_unlock_irqrestore(&shost->free_list_lock, flags);

		if (cmd) {
			void *buf, *prot;

			buf = cmd->sense_buffer;
			prot = cmd->prot_sdb;

			memset(cmd, 0, sizeof(*cmd));

			cmd->sense_buffer = buf;
			cmd->prot_sdb = prot;
		}
	}

	return cmd;
}
EXPORT_SYMBOL_GPL(__scsi_get_command);

struct scsi_cmnd *scsi_get_command(struct scsi_device *dev, gfp_t gfp_mask)
{
	struct scsi_cmnd *cmd;

	if (!get_device(&dev->sdev_gendev))
		return NULL;

	cmd = __scsi_get_command(dev->host, gfp_mask);

	if (likely(cmd != NULL)) {
		unsigned long flags;

		cmd->device = dev;
		INIT_LIST_HEAD(&cmd->list);
		spin_lock_irqsave(&dev->list_lock, flags);
		list_add_tail(&cmd->list, &dev->cmd_list);
		spin_unlock_irqrestore(&dev->list_lock, flags);
		cmd->jiffies_at_alloc = jiffies;
	} else
		put_device(&dev->sdev_gendev);

	return cmd;
}
EXPORT_SYMBOL(scsi_get_command);

void __scsi_put_command(struct Scsi_Host *shost, struct scsi_cmnd *cmd,
			struct device *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&shost->free_list_lock, flags);
	if (unlikely(list_empty(&shost->free_list))) {
		list_add(&cmd->list, &shost->free_list);
		cmd = NULL;
	}
	spin_unlock_irqrestore(&shost->free_list_lock, flags);

	if (likely(cmd != NULL))
		scsi_pool_free_command(shost->cmd_pool, cmd);

	put_device(dev);
}
EXPORT_SYMBOL(__scsi_put_command);

void scsi_put_command(struct scsi_cmnd *cmd)
{
	struct scsi_device *sdev = cmd->device;
	unsigned long flags;

	spin_lock_irqsave(&cmd->device->list_lock, flags);
	BUG_ON(list_empty(&cmd->list));
	list_del_init(&cmd->list);
	spin_unlock_irqrestore(&cmd->device->list_lock, flags);

	__scsi_put_command(cmd->device->host, cmd, &sdev->sdev_gendev);
}
EXPORT_SYMBOL(scsi_put_command);

static struct scsi_host_cmd_pool *scsi_get_host_cmd_pool(gfp_t gfp_mask)
{
	struct scsi_host_cmd_pool *retval = NULL, *pool;
	 
	mutex_lock(&host_cmd_pool_mutex);
	pool = (gfp_mask & __GFP_DMA) ? &scsi_cmd_dma_pool :
		&scsi_cmd_pool;
	if (!pool->users) {
		pool->cmd_slab = kmem_cache_create(pool->cmd_name,
						   sizeof(struct scsi_cmnd), 0,
						   pool->slab_flags, NULL);
		if (!pool->cmd_slab)
			goto fail;

		pool->sense_slab = kmem_cache_create(pool->sense_name,
						     SCSI_SENSE_BUFFERSIZE, 0,
						     pool->slab_flags, NULL);
		if (!pool->sense_slab) {
			kmem_cache_destroy(pool->cmd_slab);
			goto fail;
		}
	}

	pool->users++;
	retval = pool;
 fail:
	mutex_unlock(&host_cmd_pool_mutex);
	return retval;
}

static void scsi_put_host_cmd_pool(gfp_t gfp_mask)
{
	struct scsi_host_cmd_pool *pool;

	mutex_lock(&host_cmd_pool_mutex);
	pool = (gfp_mask & __GFP_DMA) ? &scsi_cmd_dma_pool :
		&scsi_cmd_pool;
	 
	BUG_ON(pool->users == 0);

	if (!--pool->users) {
		kmem_cache_destroy(pool->cmd_slab);
		kmem_cache_destroy(pool->sense_slab);
	}
	mutex_unlock(&host_cmd_pool_mutex);
}

struct scsi_cmnd *scsi_allocate_command(gfp_t gfp_mask)
{
	struct scsi_host_cmd_pool *pool = scsi_get_host_cmd_pool(gfp_mask);

	if (!pool)
		return NULL;

	return scsi_pool_alloc_command(pool, gfp_mask);
}
EXPORT_SYMBOL(scsi_allocate_command);

void scsi_free_command(gfp_t gfp_mask, struct scsi_cmnd *cmd)
{
	struct scsi_host_cmd_pool *pool = scsi_get_host_cmd_pool(gfp_mask);

	BUG_ON(!pool);

	scsi_pool_free_command(pool, cmd);
	 
	scsi_put_host_cmd_pool(gfp_mask);
	scsi_put_host_cmd_pool(gfp_mask);
}
EXPORT_SYMBOL(scsi_free_command);

int scsi_setup_command_freelist(struct Scsi_Host *shost)
{
	struct scsi_cmnd *cmd;
	const gfp_t gfp_mask = shost->unchecked_isa_dma ? GFP_DMA : GFP_KERNEL;

	spin_lock_init(&shost->free_list_lock);
	INIT_LIST_HEAD(&shost->free_list);

	shost->cmd_pool = scsi_get_host_cmd_pool(gfp_mask);

	if (!shost->cmd_pool)
		return -ENOMEM;

	cmd = scsi_host_alloc_command(shost, gfp_mask);
	if (!cmd) {
		scsi_put_host_cmd_pool(gfp_mask);
		shost->cmd_pool = NULL;
		return -ENOMEM;
	}
	list_add(&cmd->list, &shost->free_list);
	return 0;
}

void scsi_destroy_command_freelist(struct Scsi_Host *shost)
{
	 
	if (!shost->cmd_pool)
		return;

	while (!list_empty(&shost->free_list)) {
		struct scsi_cmnd *cmd;

		cmd = list_entry(shost->free_list.next, struct scsi_cmnd, list);
		list_del_init(&cmd->list);
		scsi_pool_free_command(shost->cmd_pool, cmd);
	}
	shost->cmd_pool = NULL;
	scsi_put_host_cmd_pool(shost->unchecked_isa_dma ? GFP_DMA : GFP_KERNEL);
}

#ifdef CONFIG_SCSI_LOGGING
void scsi_log_send(struct scsi_cmnd *cmd)
{
	unsigned int level;

	if (unlikely(scsi_logging_level)) {
		level = SCSI_LOG_LEVEL(SCSI_LOG_MLQUEUE_SHIFT,
				       SCSI_LOG_MLQUEUE_BITS);
		if (level > 1) {
			scmd_printk(KERN_INFO, cmd, "Send: ");
			if (level > 2)
				printk("0x%p ", cmd);
			printk("\n");
			scsi_print_command(cmd);
			if (level > 3) {
				printk(KERN_INFO "buffer = 0x%p, bufflen = %d,"
				       " queuecommand 0x%p\n",
					scsi_sglist(cmd), scsi_bufflen(cmd),
					cmd->device->host->hostt->queuecommand);

			}
		}
	}
}

void scsi_log_completion(struct scsi_cmnd *cmd, int disposition)
{
	unsigned int level;

	if (unlikely(scsi_logging_level)) {
		level = SCSI_LOG_LEVEL(SCSI_LOG_MLCOMPLETE_SHIFT,
				       SCSI_LOG_MLCOMPLETE_BITS);
		if (((level > 0) && (cmd->result || disposition != SUCCESS)) ||
		    (level > 1)) {
			scmd_printk(KERN_INFO, cmd, "Done: ");
			if (level > 2)
				printk("0x%p ", cmd);
			 
			switch (disposition) {
			case SUCCESS:
				printk("SUCCESS\n");
				break;
			case NEEDS_RETRY:
				printk("RETRY\n");
				break;
			case ADD_TO_MLQUEUE:
				printk("MLQUEUE\n");
				break;
			case FAILED:
				printk("FAILED\n");
				break;
			case TIMEOUT_ERROR:
				 
				printk("TIMEOUT\n");
				break;
			default:
				printk("UNKNOWN\n");
			}
			scsi_print_result(cmd);
			scsi_print_command(cmd);
			if (status_byte(cmd->result) & CHECK_CONDITION)
				scsi_print_sense("", cmd);
			if (level > 3)
				scmd_printk(KERN_INFO, cmd,
					    "scsi host busy %d failed %d\n",
					    cmd->device->host->host_busy,
					    cmd->device->host->host_failed);
		}
	}
}
#endif

void scsi_cmd_get_serial(struct Scsi_Host *host, struct scsi_cmnd *cmd)
{
	cmd->serial_number = host->cmd_serial_number++;
	if (cmd->serial_number == 0) 
		cmd->serial_number = host->cmd_serial_number++;
}
EXPORT_SYMBOL(scsi_cmd_get_serial);

#if defined(MY_ABC_HERE) && defined(MY_ABC_HERE)
 
void syno_disk_hiternation_cmd_printk(struct scsi_device *sdp, struct scsi_cmnd *cmd)
{
	 
	if (SYNO_PORT_TYPE_SATA == sdp->host->hostt->syno_port_type ||
		SYNO_PORT_TYPE_SAS  == sdp->host->hostt->syno_port_type) {
		 
		syno_do_hibernation_scsi_log(sdp->syno_disk_name);
	} else if (SYNO_PORT_TYPE_USB == sdp->host->hostt->syno_port_type) {
		char szBuf[128];
		struct mm_struct *mm;
		int len;
		if (current) {
			mm = current->mm;
			if (mm) {
				len = mm->arg_end - mm->arg_start;
				memset(szBuf, 0, sizeof(szBuf));
				memcpy(szBuf, (unsigned char *)mm->arg_start, len);
				printk(KERN_WARNING"%s[%d]:%s(), %s: spin up by pid=%d, name=%s\n",
					   __FILE__, __LINE__, __FUNCTION__,
					   sdp->syno_disk_name, current->pid, szBuf);
			} else {
				printk(KERN_WARNING"%s[%d]:%s(), %s: spin up by pid = %d, current->mm = NULL\n",
					   __FILE__, __LINE__, __FUNCTION__,
					   sdp->syno_disk_name, current->pid);
			}
		} else {
			printk(KERN_WARNING"%s[%d]:%s(), current = NULL\n",
				   __FILE__, __LINE__, __FUNCTION__);
		}
	}
}
#endif  

int scsi_dispatch_cmd(struct scsi_cmnd *cmd)
{
	struct Scsi_Host *host = cmd->device->host;
	unsigned long timeout;
	int rtn = 0;

	atomic_inc(&cmd->device->iorequest_cnt);

	if (unlikely(cmd->device->sdev_state == SDEV_DEL)) {
		 
		cmd->result = DID_NO_CONNECT << 16;
		scsi_done(cmd);
		 
		goto out;
	}

	if (unlikely(scsi_device_blocked(cmd->device))) {
		 
		scsi_queue_insert(cmd, SCSI_MLQUEUE_DEVICE_BUSY);

		SCSI_LOG_MLQUEUE(3, printk("queuecommand : device blocked \n"));

		goto out;
	}

	if (cmd->device->scsi_level <= SCSI_2 &&
	    cmd->device->scsi_level != SCSI_UNKNOWN) {
		cmd->cmnd[1] = (cmd->cmnd[1] & 0x1f) |
			       (cmd->device->lun << 5 & 0xe0);
	}

	timeout = host->last_reset + MIN_RESET_DELAY;

	if (host->resetting && time_before(jiffies, timeout)) {
		int ticks_remaining = timeout - jiffies;
		 
		while (--ticks_remaining >= 0)
			mdelay(1 + 999 / HZ);
		host->resetting = 0;
	}

	scsi_log_send(cmd);

	if (cmd->cmd_len > cmd->device->host->max_cmd_len) {
		SCSI_LOG_MLQUEUE(3,
			printk("queuecommand : command too long. "
			       "cdb_size=%d host->max_cmd_len=%d\n",
			       cmd->cmd_len, cmd->device->host->max_cmd_len));
		cmd->result = (DID_ABORT << 16);

		scsi_done(cmd);
		goto out;
	}

#ifdef CONFIG_SYNO_SAS_SPINUP_DELAY_DEBUG
	 
	if (0x1b == cmd->cmnd[0]) {
	    sdev_printk(KERN_ERR, cmd->device,
		    "START_STOP run  - tag %02x %s - %02x %02x %02x %02x %02x %02x\n",
			cmd->tag, (cmd->cmnd[4]&0x01)?"START":"STOP ",
		    cmd->cmnd[0], cmd->cmnd[1], cmd->cmnd[2], 
		    cmd->cmnd[3], cmd->cmnd[4], cmd->cmnd[5]);
	}
#endif  
#ifdef MY_ABC_HERE
	 
	if (cmd->device->spindown &&
	 
		!(ATA_16 == cmd->cmnd[0] && (ATA_CMD_PMP_WRITE == cmd->cmnd[14] ||ATA_CMD_PMP_READ == cmd->cmnd[14])) &&
		TEST_UNIT_READY != cmd->cmnd[0]) {
#ifdef MY_ABC_HERE
		if(syno_hibernation_log_level > 0) {
			syno_disk_hiternation_cmd_printk(cmd->device, cmd);
		}
#endif  
		if (0 == cmd->device->do_standby_syncing) {
			cmd->device->idle = jiffies;
		}
		cmd->device->spindown = 0;
	}

	if(0x0C == cmd->cmnd[0]) {
		struct scatterlist *sg;
		unsigned char* pBuffer;

		if( cmd->sdb.table.nents ) {
			sg = (struct scatterlist *)cmd->sdb.table.sgl;
			pBuffer = kmap_atomic(sg_page(sg)) + sg->offset;
		} else {
			pBuffer = (char *)cmd->sdb.table.sgl;
		}

		if( 0xE0 == pBuffer[0] ) {
			cmd->device->spindown = 1;
		}

		if( cmd->sdb.table.nents ) {
			kunmap_atomic(pBuffer - sg->offset);
		}
	} else if(ATA_16 == cmd->cmnd[0]) {
		 
		if (0xE0 == cmd->cmnd[14]) {
			cmd->device->spindown = 1;
		}
	} else if(START_STOP == cmd->cmnd[0]) {
		if (0x01 == cmd->cmnd[4]) {
			 
#ifdef MY_ABC_HERE
			if(syno_hibernation_log_level > 0) {
				syno_disk_hiternation_cmd_printk(cmd->device, cmd);
			}
#endif  
			if (0 == cmd->device->do_standby_syncing) {
				cmd->device->idle = jiffies;
			}
		}
	} else if(LOG_SENSE != cmd->cmnd[0] &&
			TEST_UNIT_READY != cmd->cmnd[0] &&
			SYNCHRONIZE_CACHE != cmd->cmnd[0]) {

#ifdef MY_ABC_HERE
			if(syno_hibernation_log_level > 1) {  
				syno_disk_hiternation_cmd_printk(cmd->device, cmd);
			}
#endif  

		if (0 == cmd->device->do_standby_syncing) {
			cmd->device->idle = jiffies;
		}
	}
#endif  

	if (unlikely(host->shost_state == SHOST_DEL)) {
		cmd->result = (DID_NO_CONNECT << 16);
		scsi_done(cmd);
	} else {
		trace_scsi_dispatch_cmd_start(cmd);
		cmd->scsi_done = scsi_done;
		rtn = host->hostt->queuecommand(host, cmd);
	}

	if (rtn) {
		trace_scsi_dispatch_cmd_error(cmd, rtn);
		if (rtn != SCSI_MLQUEUE_DEVICE_BUSY &&
		    rtn != SCSI_MLQUEUE_TARGET_BUSY)
			rtn = SCSI_MLQUEUE_HOST_BUSY;

		scsi_queue_insert(cmd, rtn);

		SCSI_LOG_MLQUEUE(3,
		    printk("queuecommand : request rejected\n"));
	}

 out:
	SCSI_LOG_MLQUEUE(3, printk("leaving scsi_dispatch_cmnd()\n"));
	return rtn;
}

static void scsi_done(struct scsi_cmnd *cmd)
{
	trace_scsi_dispatch_cmd_done(cmd);
	blk_complete_request(cmd->request);
}

void scsi_finish_command(struct scsi_cmnd *cmd)
{
	struct scsi_device *sdev = cmd->device;
	struct scsi_target *starget = scsi_target(sdev);
	struct Scsi_Host *shost = sdev->host;
	struct scsi_driver *drv;
	unsigned int good_bytes;

	scsi_device_unbusy(sdev);

        shost->host_blocked = 0;
	starget->target_blocked = 0;
        sdev->device_blocked = 0;

	if (SCSI_SENSE_VALID(cmd))
		cmd->result |= (DRIVER_SENSE << 24);

	SCSI_LOG_MLCOMPLETE(4, sdev_printk(KERN_INFO, sdev,
				"Notifying upper driver of completion "
				"(result %x)\n", cmd->result));

	good_bytes = scsi_bufflen(cmd);
        if (cmd->request->cmd_type != REQ_TYPE_BLOCK_PC) {
		int old_good_bytes = good_bytes;
		drv = scsi_cmd_to_driver(cmd);
		if (drv->done)
			good_bytes = drv->done(cmd);
		 
		if (good_bytes == old_good_bytes)
			good_bytes -= scsi_get_resid(cmd);
	}
	scsi_io_completion(cmd, good_bytes);
}
EXPORT_SYMBOL(scsi_finish_command);

void scsi_adjust_queue_depth(struct scsi_device *sdev, int tagged, int tags)
{
	unsigned long flags;

	if (tags <= 0)
		return;

	spin_lock_irqsave(sdev->request_queue->queue_lock, flags);

	if (!sdev->host->bqt) {
		if (blk_queue_tagged(sdev->request_queue) &&
		    blk_queue_resize_tags(sdev->request_queue, tags) != 0)
			goto out;
	}

	sdev->queue_depth = tags;
	switch (tagged) {
		case MSG_ORDERED_TAG:
			sdev->ordered_tags = 1;
			sdev->simple_tags = 1;
			break;
		case MSG_SIMPLE_TAG:
			sdev->ordered_tags = 0;
			sdev->simple_tags = 1;
			break;
		default:
			sdev_printk(KERN_WARNING, sdev,
				    "scsi_adjust_queue_depth, bad queue type, "
				    "disabled\n");
		case 0:
			sdev->ordered_tags = sdev->simple_tags = 0;
			sdev->queue_depth = tags;
			break;
	}
 out:
	spin_unlock_irqrestore(sdev->request_queue->queue_lock, flags);
}
EXPORT_SYMBOL(scsi_adjust_queue_depth);

int scsi_track_queue_full(struct scsi_device *sdev, int depth)
{

	if ((jiffies >> 4) == (sdev->last_queue_full_time >> 4))
		return 0;

	sdev->last_queue_full_time = jiffies;
	if (sdev->last_queue_full_depth != depth) {
		sdev->last_queue_full_count = 1;
		sdev->last_queue_full_depth = depth;
	} else {
		sdev->last_queue_full_count++;
	}

	if (sdev->last_queue_full_count <= 10)
		return 0;
	if (sdev->last_queue_full_depth < 8) {
		 
		scsi_adjust_queue_depth(sdev, 0, sdev->host->cmd_per_lun);
		return -1;
	}
	
	if (sdev->ordered_tags)
		scsi_adjust_queue_depth(sdev, MSG_ORDERED_TAG, depth);
	else
		scsi_adjust_queue_depth(sdev, MSG_SIMPLE_TAG, depth);
	return depth;
}
EXPORT_SYMBOL(scsi_track_queue_full);

static int scsi_vpd_inquiry(struct scsi_device *sdev, unsigned char *buffer,
							u8 page, unsigned len)
{
	int result;
	unsigned char cmd[16];

	cmd[0] = INQUIRY;
	cmd[1] = 1;		 
	cmd[2] = page;
	cmd[3] = len >> 8;
	cmd[4] = len & 0xff;
	cmd[5] = 0;		 

	result = scsi_execute_req(sdev, cmd, DMA_FROM_DEVICE, buffer,
				  len, NULL, 30 * HZ, 3, NULL);
	if (result)
		return result;

	if (buffer[1] != page)
		return -EIO;

	return 0;
}

int scsi_get_vpd_page(struct scsi_device *sdev, u8 page, unsigned char *buf,
		      int buf_len)
{
	int i, result;

	if (sdev->skip_vpd_pages)
		goto fail;

	result = scsi_vpd_inquiry(sdev, buf, 0, buf_len);
	if (result)
		goto fail;

	if (page == 0)
		return 0;

	for (i = 0; i < min((int)buf[3], buf_len - 4); i++)
		if (buf[i + 4] == page)
			goto found;

	if (i < buf[3] && i >= buf_len - 4)
		 
		goto found;
	 
	goto fail;

 found:
	result = scsi_vpd_inquiry(sdev, buf, page, buf_len);
	if (result)
		goto fail;

	return 0;

 fail:
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(scsi_get_vpd_page);

int scsi_report_opcode(struct scsi_device *sdev, unsigned char *buffer,
		       unsigned int len, unsigned char opcode)
{
	unsigned char cmd[16];
	struct scsi_sense_hdr sshdr;
	int result;

	if (sdev->no_report_opcodes || sdev->scsi_level < SCSI_SPC_3)
		return -EINVAL;

	memset(cmd, 0, 16);
	cmd[0] = MAINTENANCE_IN;
	cmd[1] = MI_REPORT_SUPPORTED_OPERATION_CODES;
	cmd[2] = 1;		 
	cmd[3] = opcode;
	put_unaligned_be32(len, &cmd[6]);
	memset(buffer, 0, len);

	result = scsi_execute_req(sdev, cmd, DMA_FROM_DEVICE, buffer, len,
				  &sshdr, 30 * HZ, 3, NULL);

	if (result && scsi_sense_valid(&sshdr) &&
	    sshdr.sense_key == ILLEGAL_REQUEST &&
	    (sshdr.asc == 0x20 || sshdr.asc == 0x24) && sshdr.ascq == 0x00)
		return -EINVAL;

	if ((buffer[1] & 3) == 3)  
		return 1;

	return 0;
}
EXPORT_SYMBOL(scsi_report_opcode);

int scsi_device_get(struct scsi_device *sdev)
{
	if (sdev->sdev_state == SDEV_DEL)
		return -ENXIO;
	if (!get_device(&sdev->sdev_gendev))
		return -ENXIO;
	 
	try_module_get(sdev->host->hostt->module);

	return 0;
}
EXPORT_SYMBOL(scsi_device_get);

void scsi_device_put(struct scsi_device *sdev)
{
#ifdef CONFIG_MODULE_UNLOAD
	struct module *module = sdev->host->hostt->module;

	if (module && module_refcount(module) != 0)
		module_put(module);
#endif
	put_device(&sdev->sdev_gendev);
}
EXPORT_SYMBOL(scsi_device_put);

struct scsi_device *__scsi_iterate_devices(struct Scsi_Host *shost,
					   struct scsi_device *prev)
{
	struct list_head *list = (prev ? &prev->siblings : &shost->__devices);
	struct scsi_device *next = NULL;
	unsigned long flags;

	spin_lock_irqsave(shost->host_lock, flags);
	while (list->next != &shost->__devices) {
		next = list_entry(list->next, struct scsi_device, siblings);
		 
		if (!scsi_device_get(next))
			break;
		next = NULL;
		list = list->next;
	}
	spin_unlock_irqrestore(shost->host_lock, flags);

	if (prev)
		scsi_device_put(prev);
	return next;
}
EXPORT_SYMBOL(__scsi_iterate_devices);

void starget_for_each_device(struct scsi_target *starget, void *data,
		     void (*fn)(struct scsi_device *, void *))
{
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	struct scsi_device *sdev;

	shost_for_each_device(sdev, shost) {
		if ((sdev->channel == starget->channel) &&
		    (sdev->id == starget->id))
			fn(sdev, data);
	}
}
EXPORT_SYMBOL(starget_for_each_device);

void __starget_for_each_device(struct scsi_target *starget, void *data,
			       void (*fn)(struct scsi_device *, void *))
{
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	struct scsi_device *sdev;

	__shost_for_each_device(sdev, shost) {
		if ((sdev->channel == starget->channel) &&
		    (sdev->id == starget->id))
			fn(sdev, data);
	}
}
EXPORT_SYMBOL(__starget_for_each_device);

struct scsi_device *__scsi_device_lookup_by_target(struct scsi_target *starget,
						   uint lun)
{
	struct scsi_device *sdev;

	list_for_each_entry(sdev, &starget->devices, same_target_siblings) {
		if (sdev->sdev_state == SDEV_DEL)
			continue;
		if (sdev->lun ==lun)
			return sdev;
	}

	return NULL;
}
EXPORT_SYMBOL(__scsi_device_lookup_by_target);

struct scsi_device *scsi_device_lookup_by_target(struct scsi_target *starget,
						 uint lun)
{
	struct scsi_device *sdev;
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	unsigned long flags;

	spin_lock_irqsave(shost->host_lock, flags);
	sdev = __scsi_device_lookup_by_target(starget, lun);
	if (sdev && scsi_device_get(sdev))
		sdev = NULL;
	spin_unlock_irqrestore(shost->host_lock, flags);

	return sdev;
}
EXPORT_SYMBOL(scsi_device_lookup_by_target);

struct scsi_device *__scsi_device_lookup(struct Scsi_Host *shost,
		uint channel, uint id, uint lun)
{
	struct scsi_device *sdev;

	list_for_each_entry(sdev, &shost->__devices, siblings) {
		if (sdev->channel == channel && sdev->id == id &&
				sdev->lun ==lun)
			return sdev;
	}

	return NULL;
}
EXPORT_SYMBOL(__scsi_device_lookup);

struct scsi_device *scsi_device_lookup(struct Scsi_Host *shost,
		uint channel, uint id, uint lun)
{
	struct scsi_device *sdev;
	unsigned long flags;

	spin_lock_irqsave(shost->host_lock, flags);
	sdev = __scsi_device_lookup(shost, channel, id, lun);
	if (sdev && scsi_device_get(sdev))
		sdev = NULL;
	spin_unlock_irqrestore(shost->host_lock, flags);

	return sdev;
}
EXPORT_SYMBOL(scsi_device_lookup);

MODULE_DESCRIPTION("SCSI core");
MODULE_LICENSE("GPL");

module_param(scsi_logging_level, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(scsi_logging_level, "a bit mask of logging levels");

static int __init init_scsi(void)
{
	int error;

	error = scsi_init_queue();
	if (error)
		return error;
	error = scsi_init_procfs();
	if (error)
		goto cleanup_queue;
	error = scsi_init_devinfo();
	if (error)
		goto cleanup_procfs;
	error = scsi_init_hosts();
	if (error)
		goto cleanup_devlist;
	error = scsi_init_sysctl();
	if (error)
		goto cleanup_hosts;
	error = scsi_sysfs_register();
	if (error)
		goto cleanup_sysctl;

	scsi_netlink_init();

	printk(KERN_NOTICE "SCSI subsystem initialized\n");
	return 0;

cleanup_sysctl:
	scsi_exit_sysctl();
cleanup_hosts:
	scsi_exit_hosts();
cleanup_devlist:
	scsi_exit_devinfo();
cleanup_procfs:
	scsi_exit_procfs();
cleanup_queue:
	scsi_exit_queue();
	printk(KERN_ERR "SCSI subsystem failed to initialize, error = %d\n",
	       -error);
	return error;
}

static void __exit exit_scsi(void)
{
	scsi_netlink_exit();
	scsi_sysfs_unregister();
	scsi_exit_sysctl();
	scsi_exit_hosts();
	scsi_exit_devinfo();
	scsi_exit_procfs();
	scsi_exit_queue();
	async_unregister_domain(&scsi_sd_probe_domain);
}

subsys_initcall(init_scsi);
module_exit(exit_scsi);
