 
#include <linux/blkdev.h>
#include <linux/ratelimit.h>
#include "ctree.h"
#include "volumes.h"
#include "disk-io.h"
#include "ordered-data.h"
#include "transaction.h"
#include "backref.h"
#include "extent_io.h"
#include "dev-replace.h"
#include "check-integrity.h"
#include "rcu-string.h"
#include "raid56.h"

struct scrub_block;
struct scrub_ctx;

#define SCRUB_PAGES_PER_RD_BIO	32	 
#define SCRUB_PAGES_PER_WR_BIO	32	 
#define SCRUB_BIOS_PER_SCTX	64	 

#define SCRUB_MAX_PAGES_PER_BLOCK	16	 

struct scrub_page {
	struct scrub_block	*sblock;
	struct page		*page;
	struct btrfs_device	*dev;
	u64			flags;   
	u64			generation;
	u64			logical;
	u64			physical;
	u64			physical_for_dev_replace;
	atomic_t		ref_count;
	struct {
		unsigned int	mirror_num:8;
		unsigned int	have_csum:1;
		unsigned int	io_error:1;
	};
	u8			csum[BTRFS_CSUM_SIZE];
};

struct scrub_bio {
	int			index;
	struct scrub_ctx	*sctx;
	struct btrfs_device	*dev;
	struct bio		*bio;
	int			err;
	u64			logical;
	u64			physical;
#if SCRUB_PAGES_PER_WR_BIO >= SCRUB_PAGES_PER_RD_BIO
	struct scrub_page	*pagev[SCRUB_PAGES_PER_WR_BIO];
#else
	struct scrub_page	*pagev[SCRUB_PAGES_PER_RD_BIO];
#endif
	int			page_count;
	int			next_free;
	struct btrfs_work	work;
};

struct scrub_block {
	struct scrub_page	*pagev[SCRUB_MAX_PAGES_PER_BLOCK];
	int			page_count;
	atomic_t		outstanding_pages;
	atomic_t		ref_count;  
	struct scrub_ctx	*sctx;
	struct {
		unsigned int	header_error:1;
		unsigned int	checksum_error:1;
		unsigned int	no_io_error_seen:1;
		unsigned int	generation_error:1;  
	};
};

struct scrub_wr_ctx {
	struct scrub_bio *wr_curr_bio;
	struct btrfs_device *tgtdev;
	int pages_per_wr_bio;  
	atomic_t flush_all_writes;
	struct mutex wr_lock;
};

struct scrub_ctx {
	struct scrub_bio	*bios[SCRUB_BIOS_PER_SCTX];
	struct btrfs_root	*dev_root;
	int			first_free;
	int			curr;
	atomic_t		bios_in_flight;
	atomic_t		workers_pending;
	spinlock_t		list_lock;
	wait_queue_head_t	list_wait;
	u16			csum_size;
	struct list_head	csum_list;
	atomic_t		cancel_req;
	int			readonly;
	int			pages_per_rd_bio;
	u32			sectorsize;
	u32			nodesize;
	u32			leafsize;

	int			is_dev_replace;
	struct scrub_wr_ctx	wr_ctx;

	struct btrfs_scrub_progress stat;
	spinlock_t		stat_lock;
};

struct scrub_fixup_nodatasum {
	struct scrub_ctx	*sctx;
	struct btrfs_device	*dev;
	u64			logical;
	struct btrfs_root	*root;
	struct btrfs_work	work;
	int			mirror_num;
};

struct scrub_nocow_inode {
	u64			inum;
	u64			offset;
	u64			root;
	struct list_head	list;
};

struct scrub_copy_nocow_ctx {
	struct scrub_ctx	*sctx;
	u64			logical;
	u64			len;
	int			mirror_num;
	u64			physical_for_dev_replace;
	struct list_head	inodes;
	struct btrfs_work	work;
};

struct scrub_warning {
	struct btrfs_path	*path;
	u64			extent_item_size;
	char			*scratch_buf;
	char			*msg_buf;
	const char		*errstr;
	sector_t		sector;
	u64			logical;
	struct btrfs_device	*dev;
	int			msg_bufsize;
	int			scratch_bufsize;
};

static void scrub_pending_bio_inc(struct scrub_ctx *sctx);
static void scrub_pending_bio_dec(struct scrub_ctx *sctx);
static void scrub_pending_trans_workers_inc(struct scrub_ctx *sctx);
static void scrub_pending_trans_workers_dec(struct scrub_ctx *sctx);
static int scrub_handle_errored_block(struct scrub_block *sblock_to_check);
static int scrub_setup_recheck_block(struct scrub_ctx *sctx,
				     struct btrfs_fs_info *fs_info,
				     struct scrub_block *original_sblock,
				     u64 length, u64 logical,
				     struct scrub_block *sblocks_for_recheck);
static void scrub_recheck_block(struct btrfs_fs_info *fs_info,
				struct scrub_block *sblock, int is_metadata,
				int have_csum, u8 *csum, u64 generation,
				u16 csum_size);
static void scrub_recheck_block_checksum(struct btrfs_fs_info *fs_info,
					 struct scrub_block *sblock,
					 int is_metadata, int have_csum,
					 const u8 *csum, u64 generation,
					 u16 csum_size);
static void scrub_complete_bio_end_io(struct bio *bio, int err);
static int scrub_repair_block_from_good_copy(struct scrub_block *sblock_bad,
					     struct scrub_block *sblock_good,
					     int force_write);
static int scrub_repair_page_from_good_copy(struct scrub_block *sblock_bad,
					    struct scrub_block *sblock_good,
					    int page_num, int force_write);
static void scrub_write_block_to_dev_replace(struct scrub_block *sblock);
static int scrub_write_page_to_dev_replace(struct scrub_block *sblock,
					   int page_num);
static int scrub_checksum_data(struct scrub_block *sblock);
static int scrub_checksum_tree_block(struct scrub_block *sblock);
static int scrub_checksum_super(struct scrub_block *sblock);
static void scrub_block_get(struct scrub_block *sblock);
static void scrub_block_put(struct scrub_block *sblock);
static void scrub_page_get(struct scrub_page *spage);
static void scrub_page_put(struct scrub_page *spage);
static int scrub_add_page_to_rd_bio(struct scrub_ctx *sctx,
				    struct scrub_page *spage);
static int scrub_pages(struct scrub_ctx *sctx, u64 logical, u64 len,
		       u64 physical, struct btrfs_device *dev, u64 flags,
		       u64 gen, int mirror_num, u8 *csum, int force,
		       u64 physical_for_dev_replace);
static void scrub_bio_end_io(struct bio *bio, int err);
static void scrub_bio_end_io_worker(struct btrfs_work *work);
static void scrub_block_complete(struct scrub_block *sblock);
static void scrub_remap_extent(struct btrfs_fs_info *fs_info,
			       u64 extent_logical, u64 extent_len,
			       u64 *extent_physical,
			       struct btrfs_device **extent_dev,
			       int *extent_mirror_num);
static int scrub_setup_wr_ctx(struct scrub_ctx *sctx,
			      struct scrub_wr_ctx *wr_ctx,
			      struct btrfs_fs_info *fs_info,
			      struct btrfs_device *dev,
			      int is_dev_replace);
static void scrub_free_wr_ctx(struct scrub_wr_ctx *wr_ctx);
static int scrub_add_page_to_wr_bio(struct scrub_ctx *sctx,
				    struct scrub_page *spage);
static void scrub_wr_submit(struct scrub_ctx *sctx);
static void scrub_wr_bio_end_io(struct bio *bio, int err);
static void scrub_wr_bio_end_io_worker(struct btrfs_work *work);
static int write_page_nocow(struct scrub_ctx *sctx,
			    u64 physical_for_dev_replace, struct page *page);
static int copy_nocow_pages_for_inode(u64 inum, u64 offset, u64 root,
				      struct scrub_copy_nocow_ctx *ctx);
static int copy_nocow_pages(struct scrub_ctx *sctx, u64 logical, u64 len,
			    int mirror_num, u64 physical_for_dev_replace);
static void copy_nocow_pages_worker(struct btrfs_work *work);
static void __scrub_blocked_if_needed(struct btrfs_fs_info *fs_info);
static void scrub_blocked_if_needed(struct btrfs_fs_info *fs_info);

static void scrub_pending_bio_inc(struct scrub_ctx *sctx)
{
	atomic_inc(&sctx->bios_in_flight);
}

static void scrub_pending_bio_dec(struct scrub_ctx *sctx)
{
	atomic_dec(&sctx->bios_in_flight);
	wake_up(&sctx->list_wait);
}

static void __scrub_blocked_if_needed(struct btrfs_fs_info *fs_info)
{
	while (atomic_read(&fs_info->scrub_pause_req)) {
		mutex_unlock(&fs_info->scrub_lock);
		wait_event(fs_info->scrub_pause_wait,
		   atomic_read(&fs_info->scrub_pause_req) == 0);
		mutex_lock(&fs_info->scrub_lock);
	}
}

static void scrub_blocked_if_needed(struct btrfs_fs_info *fs_info)
{
	atomic_inc(&fs_info->scrubs_paused);
	wake_up(&fs_info->scrub_pause_wait);

	mutex_lock(&fs_info->scrub_lock);
	__scrub_blocked_if_needed(fs_info);
	atomic_dec(&fs_info->scrubs_paused);
	mutex_unlock(&fs_info->scrub_lock);

	wake_up(&fs_info->scrub_pause_wait);
}

static void scrub_pending_trans_workers_inc(struct scrub_ctx *sctx)
{
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;

	mutex_lock(&fs_info->scrub_lock);
	atomic_inc(&fs_info->scrubs_running);
	atomic_inc(&fs_info->scrubs_paused);
	mutex_unlock(&fs_info->scrub_lock);

	wake_up(&fs_info->scrub_pause_wait);

	atomic_inc(&sctx->workers_pending);
}

static void scrub_pending_trans_workers_dec(struct scrub_ctx *sctx)
{
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;

	mutex_lock(&fs_info->scrub_lock);
	atomic_dec(&fs_info->scrubs_running);
	atomic_dec(&fs_info->scrubs_paused);
	mutex_unlock(&fs_info->scrub_lock);
	atomic_dec(&sctx->workers_pending);
	wake_up(&fs_info->scrub_pause_wait);
	wake_up(&sctx->list_wait);
}

static void scrub_free_csums(struct scrub_ctx *sctx)
{
	while (!list_empty(&sctx->csum_list)) {
		struct btrfs_ordered_sum *sum;
		sum = list_first_entry(&sctx->csum_list,
				       struct btrfs_ordered_sum, list);
		list_del(&sum->list);
		kfree(sum);
	}
}

static noinline_for_stack void scrub_free_ctx(struct scrub_ctx *sctx)
{
	int i;

	if (!sctx)
		return;

	scrub_free_wr_ctx(&sctx->wr_ctx);

	if (sctx->curr != -1) {
		struct scrub_bio *sbio = sctx->bios[sctx->curr];

		for (i = 0; i < sbio->page_count; i++) {
			WARN_ON(!sbio->pagev[i]->page);
			scrub_block_put(sbio->pagev[i]->sblock);
		}
		bio_put(sbio->bio);
	}

	for (i = 0; i < SCRUB_BIOS_PER_SCTX; ++i) {
		struct scrub_bio *sbio = sctx->bios[i];

		if (!sbio)
			break;
		kfree(sbio);
	}

	scrub_free_csums(sctx);
	kfree(sctx);
}

static noinline_for_stack
struct scrub_ctx *scrub_setup_ctx(struct btrfs_device *dev, int is_dev_replace)
{
	struct scrub_ctx *sctx;
	int		i;
	struct btrfs_fs_info *fs_info = dev->dev_root->fs_info;
	int pages_per_rd_bio;
	int ret;

	if (dev->bdev)
		pages_per_rd_bio = min_t(int, SCRUB_PAGES_PER_RD_BIO,
					 bio_get_nr_vecs(dev->bdev));
	else
		pages_per_rd_bio = SCRUB_PAGES_PER_RD_BIO;
	sctx = kzalloc(sizeof(*sctx), GFP_NOFS);
	if (!sctx)
		goto nomem;
	sctx->is_dev_replace = is_dev_replace;
	sctx->pages_per_rd_bio = pages_per_rd_bio;
	sctx->curr = -1;
	sctx->dev_root = dev->dev_root;
	for (i = 0; i < SCRUB_BIOS_PER_SCTX; ++i) {
		struct scrub_bio *sbio;

		sbio = kzalloc(sizeof(*sbio), GFP_NOFS);
		if (!sbio)
			goto nomem;
		sctx->bios[i] = sbio;

		sbio->index = i;
		sbio->sctx = sctx;
		sbio->page_count = 0;
		btrfs_init_work(&sbio->work, btrfs_scrub_helper,
				scrub_bio_end_io_worker, NULL, NULL);

		if (i != SCRUB_BIOS_PER_SCTX - 1)
			sctx->bios[i]->next_free = i + 1;
		else
			sctx->bios[i]->next_free = -1;
	}
	sctx->first_free = 0;
	sctx->nodesize = dev->dev_root->nodesize;
	sctx->leafsize = dev->dev_root->leafsize;
	sctx->sectorsize = dev->dev_root->sectorsize;
	atomic_set(&sctx->bios_in_flight, 0);
	atomic_set(&sctx->workers_pending, 0);
	atomic_set(&sctx->cancel_req, 0);
	sctx->csum_size = btrfs_super_csum_size(fs_info->super_copy);
	INIT_LIST_HEAD(&sctx->csum_list);

	spin_lock_init(&sctx->list_lock);
	spin_lock_init(&sctx->stat_lock);
	init_waitqueue_head(&sctx->list_wait);

	ret = scrub_setup_wr_ctx(sctx, &sctx->wr_ctx, fs_info,
				 fs_info->dev_replace.tgtdev, is_dev_replace);
	if (ret) {
		scrub_free_ctx(sctx);
		return ERR_PTR(ret);
	}
	return sctx;

nomem:
	scrub_free_ctx(sctx);
	return ERR_PTR(-ENOMEM);
}

static int scrub_print_warning_inode(u64 inum, u64 offset, u64 root,
				     void *warn_ctx)
{
	u64 isize;
	u32 nlink;
	int ret;
	int i;
	struct extent_buffer *eb;
	struct btrfs_inode_item *inode_item;
	struct scrub_warning *swarn = warn_ctx;
	struct btrfs_fs_info *fs_info = swarn->dev->dev_root->fs_info;
	struct inode_fs_paths *ipath = NULL;
	struct btrfs_root *local_root;
	struct btrfs_key root_key;

	root_key.objectid = root;
	root_key.type = BTRFS_ROOT_ITEM_KEY;
	root_key.offset = (u64)-1;
	local_root = btrfs_read_fs_root_no_name(fs_info, &root_key);
	if (IS_ERR(local_root)) {
		ret = PTR_ERR(local_root);
		goto err;
	}

	ret = inode_item_info(inum, 0, local_root, swarn->path);
	if (ret) {
		btrfs_release_path(swarn->path);
		goto err;
	}

	eb = swarn->path->nodes[0];
	inode_item = btrfs_item_ptr(eb, swarn->path->slots[0],
					struct btrfs_inode_item);
	isize = btrfs_inode_size(eb, inode_item);
	nlink = btrfs_inode_nlink(eb, inode_item);
	btrfs_release_path(swarn->path);

	ipath = init_ipath(4096, local_root, swarn->path);
	if (IS_ERR(ipath)) {
		ret = PTR_ERR(ipath);
		ipath = NULL;
		goto err;
	}
	ret = paths_from_inode(inum, ipath);

	if (ret < 0)
		goto err;

	for (i = 0; i < ipath->fspath->elem_cnt; ++i)
		printk_in_rcu(KERN_WARNING "BTRFS: %s at logical %llu on dev "
			"%s, sector %llu, root %llu, inode %llu, offset %llu, "
			"length %llu, links %u (path: %s)\n", swarn->errstr,
			swarn->logical, rcu_str_deref(swarn->dev->name),
			(unsigned long long)swarn->sector, root, inum, offset,
			min(isize - offset, (u64)PAGE_SIZE), nlink,
			(char *)(unsigned long)ipath->fspath->val[i]);
	free_ipath(ipath);
	return 0;

err:
	printk_in_rcu(KERN_WARNING "BTRFS: %s at logical %llu on dev "
		"%s, sector %llu, root %llu, inode %llu, offset %llu: path "
		"resolving failed with ret=%d\n", swarn->errstr,
		swarn->logical, rcu_str_deref(swarn->dev->name),
		(unsigned long long)swarn->sector, root, inum, offset, ret);

	free_ipath(ipath);
	return 0;
}

static void scrub_print_warning(const char *errstr, struct scrub_block *sblock)
{
	struct btrfs_device *dev;
	struct btrfs_fs_info *fs_info;
	struct btrfs_path *path;
	struct btrfs_key found_key;
	struct extent_buffer *eb;
	struct btrfs_extent_item *ei;
	struct scrub_warning swarn;
	unsigned long ptr = 0;
	u64 extent_item_pos;
	u64 flags = 0;
	u64 ref_root;
	u32 item_size;
	u8 ref_level;
	const int bufsize = 4096;
	int ret;

	WARN_ON(sblock->page_count < 1);
	dev = sblock->pagev[0]->dev;
	fs_info = sblock->sctx->dev_root->fs_info;

	path = btrfs_alloc_path();

	swarn.scratch_buf = kmalloc(bufsize, GFP_NOFS);
	swarn.msg_buf = kmalloc(bufsize, GFP_NOFS);
	swarn.sector = (sblock->pagev[0]->physical) >> 9;
	swarn.logical = sblock->pagev[0]->logical;
	swarn.errstr = errstr;
	swarn.dev = NULL;
	swarn.msg_bufsize = bufsize;
	swarn.scratch_bufsize = bufsize;

	if (!path || !swarn.scratch_buf || !swarn.msg_buf)
		goto out;

	ret = extent_from_logical(fs_info, swarn.logical, path, &found_key,
				  &flags);
	if (ret < 0)
		goto out;

	extent_item_pos = swarn.logical - found_key.objectid;
	swarn.extent_item_size = found_key.offset;

	eb = path->nodes[0];
	ei = btrfs_item_ptr(eb, path->slots[0], struct btrfs_extent_item);
	item_size = btrfs_item_size_nr(eb, path->slots[0]);

	if (flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
		do {
			ret = tree_backref_for_extent(&ptr, eb, &found_key, ei,
						      item_size, &ref_root,
						      &ref_level);
			printk_in_rcu(KERN_WARNING
				"BTRFS: %s at logical %llu on dev %s, "
				"sector %llu: metadata %s (level %d) in tree "
				"%llu\n", errstr, swarn.logical,
				rcu_str_deref(dev->name),
				(unsigned long long)swarn.sector,
				ref_level ? "node" : "leaf",
				ret < 0 ? -1 : ref_level,
				ret < 0 ? -1 : ref_root);
		} while (ret != 1);
		btrfs_release_path(path);
	} else {
		btrfs_release_path(path);
		swarn.path = path;
		swarn.dev = dev;
		iterate_extent_inodes(fs_info, found_key.objectid,
					extent_item_pos, 1,
					scrub_print_warning_inode, &swarn);
	}

out:
	btrfs_free_path(path);
	kfree(swarn.scratch_buf);
	kfree(swarn.msg_buf);
}

static int scrub_fixup_readpage(u64 inum, u64 offset, u64 root, void *fixup_ctx)
{
	struct page *page = NULL;
	unsigned long index;
	struct scrub_fixup_nodatasum *fixup = fixup_ctx;
	int ret;
	int corrected = 0;
	struct btrfs_key key;
	struct inode *inode = NULL;
	struct btrfs_fs_info *fs_info;
	u64 end = offset + PAGE_SIZE - 1;
	struct btrfs_root *local_root;
	int srcu_index;

	key.objectid = root;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;

	fs_info = fixup->root->fs_info;
	srcu_index = srcu_read_lock(&fs_info->subvol_srcu);

	local_root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(local_root)) {
		srcu_read_unlock(&fs_info->subvol_srcu, srcu_index);
		return PTR_ERR(local_root);
	}

	key.type = BTRFS_INODE_ITEM_KEY;
	key.objectid = inum;
	key.offset = 0;
	inode = btrfs_iget(fs_info->sb, &key, local_root, NULL);
	srcu_read_unlock(&fs_info->subvol_srcu, srcu_index);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	index = offset >> PAGE_CACHE_SHIFT;

	page = find_or_create_page(inode->i_mapping, index, GFP_NOFS);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	if (PageUptodate(page)) {
		if (PageDirty(page)) {
			 
			ret = -EIO;
			goto out;
		}
		fs_info = BTRFS_I(inode)->root->fs_info;
		ret = repair_io_failure(fs_info, offset, PAGE_SIZE,
					fixup->logical, page,
					fixup->mirror_num);
		unlock_page(page);
		corrected = !ret;
	} else {
		 
		ret = set_extent_bits(&BTRFS_I(inode)->io_tree, offset, end,
					EXTENT_DAMAGED, GFP_NOFS);
		if (ret) {
			 
			WARN_ON(ret > 0);
			if (ret > 0)
				ret = -EFAULT;
			goto out;
		}

		ret = extent_read_full_page(&BTRFS_I(inode)->io_tree, page,
						btrfs_get_extent,
						fixup->mirror_num);
		wait_on_page_locked(page);

		corrected = !test_range_bit(&BTRFS_I(inode)->io_tree, offset,
						end, EXTENT_DAMAGED, 0, NULL);
		if (!corrected)
			clear_extent_bits(&BTRFS_I(inode)->io_tree, offset, end,
						EXTENT_DAMAGED, GFP_NOFS);
	}

out:
	if (page)
		put_page(page);

	iput(inode);

	if (ret < 0)
		return ret;

	if (ret == 0 && corrected) {
		 
		return 1;
	}

	return -EIO;
}

static void scrub_fixup_nodatasum(struct btrfs_work *work)
{
	int ret;
	struct scrub_fixup_nodatasum *fixup;
	struct scrub_ctx *sctx;
	struct btrfs_trans_handle *trans = NULL;
	struct btrfs_path *path;
	int uncorrectable = 0;

	fixup = container_of(work, struct scrub_fixup_nodatasum, work);
	sctx = fixup->sctx;

	path = btrfs_alloc_path();
	if (!path) {
		spin_lock(&sctx->stat_lock);
		++sctx->stat.malloc_errors;
		spin_unlock(&sctx->stat_lock);
		uncorrectable = 1;
		goto out;
	}

	trans = btrfs_join_transaction(fixup->root);
	if (IS_ERR(trans)) {
		uncorrectable = 1;
		goto out;
	}

	ret = iterate_inodes_from_logical(fixup->logical, fixup->root->fs_info,
						path, scrub_fixup_readpage,
						fixup);
	if (ret < 0) {
		uncorrectable = 1;
		goto out;
	}
	WARN_ON(ret != 1);

	spin_lock(&sctx->stat_lock);
	++sctx->stat.corrected_errors;
	spin_unlock(&sctx->stat_lock);

out:
	if (trans && !IS_ERR(trans))
		btrfs_end_transaction(trans, fixup->root);
	if (uncorrectable) {
		spin_lock(&sctx->stat_lock);
		++sctx->stat.uncorrectable_errors;
		spin_unlock(&sctx->stat_lock);
		btrfs_dev_replace_stats_inc(
			&sctx->dev_root->fs_info->dev_replace.
			num_uncorrectable_read_errors);
		printk_ratelimited_in_rcu(KERN_ERR "BTRFS: "
		    "unable to fixup (nodatasum) error at logical %llu on dev %s\n",
			fixup->logical, rcu_str_deref(fixup->dev->name));
	}

	btrfs_free_path(path);
	kfree(fixup);

	scrub_pending_trans_workers_dec(sctx);
}

static int scrub_handle_errored_block(struct scrub_block *sblock_to_check)
{
	struct scrub_ctx *sctx = sblock_to_check->sctx;
	struct btrfs_device *dev;
	struct btrfs_fs_info *fs_info;
	u64 length;
	u64 logical;
	u64 generation;
	unsigned int failed_mirror_index;
	unsigned int is_metadata;
	unsigned int have_csum;
	u8 *csum;
	struct scrub_block *sblocks_for_recheck;  
	struct scrub_block *sblock_bad;
	int ret;
	int mirror_index;
	int page_num;
	int success;
	static DEFINE_RATELIMIT_STATE(_rs, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);

	BUG_ON(sblock_to_check->page_count < 1);
	fs_info = sctx->dev_root->fs_info;
	if (sblock_to_check->pagev[0]->flags & BTRFS_EXTENT_FLAG_SUPER) {
		 
		spin_lock(&sctx->stat_lock);
		++sctx->stat.super_errors;
		spin_unlock(&sctx->stat_lock);
		return 0;
	}
	length = sblock_to_check->page_count * PAGE_SIZE;
	logical = sblock_to_check->pagev[0]->logical;
	generation = sblock_to_check->pagev[0]->generation;
	BUG_ON(sblock_to_check->pagev[0]->mirror_num < 1);
	failed_mirror_index = sblock_to_check->pagev[0]->mirror_num - 1;
	is_metadata = !(sblock_to_check->pagev[0]->flags &
			BTRFS_EXTENT_FLAG_DATA);
	have_csum = sblock_to_check->pagev[0]->have_csum;
	csum = sblock_to_check->pagev[0]->csum;
	dev = sblock_to_check->pagev[0]->dev;

	if (sctx->is_dev_replace && !is_metadata && !have_csum) {
		sblocks_for_recheck = NULL;
		goto nodatasum_case;
	}

	sblocks_for_recheck = kzalloc(BTRFS_MAX_MIRRORS *
				     sizeof(*sblocks_for_recheck),
				     GFP_NOFS);
	if (!sblocks_for_recheck) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		sctx->stat.read_errors++;
		sctx->stat.uncorrectable_errors++;
		spin_unlock(&sctx->stat_lock);
		btrfs_dev_stat_inc_and_print(dev, BTRFS_DEV_STAT_READ_ERRS);
		goto out;
	}

	ret = scrub_setup_recheck_block(sctx, fs_info, sblock_to_check, length,
					logical, sblocks_for_recheck);
	if (ret) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.read_errors++;
		sctx->stat.uncorrectable_errors++;
		spin_unlock(&sctx->stat_lock);
		btrfs_dev_stat_inc_and_print(dev, BTRFS_DEV_STAT_READ_ERRS);
		goto out;
	}
	BUG_ON(failed_mirror_index >= BTRFS_MAX_MIRRORS);
	sblock_bad = sblocks_for_recheck + failed_mirror_index;

	scrub_recheck_block(fs_info, sblock_bad, is_metadata, have_csum,
			    csum, generation, sctx->csum_size);

	if (!sblock_bad->header_error && !sblock_bad->checksum_error &&
	    sblock_bad->no_io_error_seen) {
		 
		spin_lock(&sctx->stat_lock);
		sctx->stat.unverified_errors++;
		spin_unlock(&sctx->stat_lock);

		if (sctx->is_dev_replace)
			scrub_write_block_to_dev_replace(sblock_bad);
		goto out;
	}

	if (!sblock_bad->no_io_error_seen) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.read_errors++;
		spin_unlock(&sctx->stat_lock);
		if (__ratelimit(&_rs))
			scrub_print_warning("i/o error", sblock_to_check);
		btrfs_dev_stat_inc_and_print(dev, BTRFS_DEV_STAT_READ_ERRS);
	} else if (sblock_bad->checksum_error) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.csum_errors++;
		spin_unlock(&sctx->stat_lock);
		if (__ratelimit(&_rs))
			scrub_print_warning("checksum error", sblock_to_check);
		btrfs_dev_stat_inc_and_print(dev,
					     BTRFS_DEV_STAT_CORRUPTION_ERRS);
	} else if (sblock_bad->header_error) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.verify_errors++;
		spin_unlock(&sctx->stat_lock);
		if (__ratelimit(&_rs))
			scrub_print_warning("checksum/header error",
					    sblock_to_check);
		if (sblock_bad->generation_error)
			btrfs_dev_stat_inc_and_print(dev,
				BTRFS_DEV_STAT_GENERATION_ERRS);
		else
			btrfs_dev_stat_inc_and_print(dev,
				BTRFS_DEV_STAT_CORRUPTION_ERRS);
	}

	if (sctx->readonly) {
		ASSERT(!sctx->is_dev_replace);
		goto out;
	}

	if (!is_metadata && !have_csum) {
		struct scrub_fixup_nodatasum *fixup_nodatasum;

nodatasum_case:
		WARN_ON(sctx->is_dev_replace);

		fixup_nodatasum = kzalloc(sizeof(*fixup_nodatasum), GFP_NOFS);
		if (!fixup_nodatasum)
			goto did_not_correct_error;
		fixup_nodatasum->sctx = sctx;
		fixup_nodatasum->dev = dev;
		fixup_nodatasum->logical = logical;
		fixup_nodatasum->root = fs_info->extent_root;
		fixup_nodatasum->mirror_num = failed_mirror_index + 1;
		scrub_pending_trans_workers_inc(sctx);
		btrfs_init_work(&fixup_nodatasum->work, btrfs_scrub_helper,
				scrub_fixup_nodatasum, NULL, NULL);
		btrfs_queue_work(fs_info->scrub_workers,
				 &fixup_nodatasum->work);
		goto out;
	}

	for (mirror_index = 0;
	     mirror_index < BTRFS_MAX_MIRRORS &&
	     sblocks_for_recheck[mirror_index].page_count > 0;
	     mirror_index++) {
		struct scrub_block *sblock_other;

		if (mirror_index == failed_mirror_index)
			continue;
		sblock_other = sblocks_for_recheck + mirror_index;

		scrub_recheck_block(fs_info, sblock_other, is_metadata,
				    have_csum, csum, generation,
				    sctx->csum_size);

		if (!sblock_other->header_error &&
		    !sblock_other->checksum_error &&
		    sblock_other->no_io_error_seen) {
			if (sctx->is_dev_replace) {
				scrub_write_block_to_dev_replace(sblock_other);
			} else {
				int force_write = is_metadata || have_csum;

				ret = scrub_repair_block_from_good_copy(
						sblock_bad, sblock_other,
						force_write);
			}
			if (0 == ret)
				goto corrected_error;
		}
	}

	if (sctx->is_dev_replace) {
		success = 1;
		for (page_num = 0; page_num < sblock_bad->page_count;
		     page_num++) {
			int sub_success;

			sub_success = 0;
			for (mirror_index = 0;
			     mirror_index < BTRFS_MAX_MIRRORS &&
			     sblocks_for_recheck[mirror_index].page_count > 0;
			     mirror_index++) {
				struct scrub_block *sblock_other =
					sblocks_for_recheck + mirror_index;
				struct scrub_page *page_other =
					sblock_other->pagev[page_num];

				if (!page_other->io_error) {
					ret = scrub_write_page_to_dev_replace(
							sblock_other, page_num);
					if (ret == 0) {
						 
						sub_success = 1;
						break;
					} else {
						btrfs_dev_replace_stats_inc(
							&sctx->dev_root->
							fs_info->dev_replace.
							num_write_errors);
					}
				}
			}

			if (!sub_success) {
				 
				success = 0;
				ret = scrub_write_page_to_dev_replace(
						sblock_bad, page_num);
				if (ret)
					btrfs_dev_replace_stats_inc(
						&sctx->dev_root->fs_info->
						dev_replace.num_write_errors);
			}
		}

		goto out;
	}

	if (sblock_bad->no_io_error_seen)
		goto did_not_correct_error;

	success = 1;
	for (page_num = 0; page_num < sblock_bad->page_count; page_num++) {
		struct scrub_page *page_bad = sblock_bad->pagev[page_num];

		if (!page_bad->io_error)
			continue;

		for (mirror_index = 0;
		     mirror_index < BTRFS_MAX_MIRRORS &&
		     sblocks_for_recheck[mirror_index].page_count > 0;
		     mirror_index++) {
			struct scrub_block *sblock_other = sblocks_for_recheck +
							   mirror_index;
			struct scrub_page *page_other = sblock_other->pagev[
							page_num];

			if (!page_other->io_error) {
				ret = scrub_repair_page_from_good_copy(
					sblock_bad, sblock_other, page_num, 0);
				if (0 == ret) {
					page_bad->io_error = 0;
					break;  
				}
			}
		}

		if (page_bad->io_error) {
			 
			success = 0;
		}
	}

	if (success) {
		if (is_metadata || have_csum) {
			 
			scrub_recheck_block(fs_info, sblock_bad,
					    is_metadata, have_csum, csum,
					    generation, sctx->csum_size);
			if (!sblock_bad->header_error &&
			    !sblock_bad->checksum_error &&
			    sblock_bad->no_io_error_seen)
				goto corrected_error;
			else
				goto did_not_correct_error;
		} else {
corrected_error:
			spin_lock(&sctx->stat_lock);
			sctx->stat.corrected_errors++;
			spin_unlock(&sctx->stat_lock);
			printk_ratelimited_in_rcu(KERN_ERR
				"BTRFS: fixed up error at logical %llu on dev %s\n",
				logical, rcu_str_deref(dev->name));
		}
	} else {
did_not_correct_error:
		spin_lock(&sctx->stat_lock);
		sctx->stat.uncorrectable_errors++;
		spin_unlock(&sctx->stat_lock);
		printk_ratelimited_in_rcu(KERN_ERR
			"BTRFS: unable to fixup (regular) error at logical %llu on dev %s\n",
			logical, rcu_str_deref(dev->name));
	}

out:
	if (sblocks_for_recheck) {
		for (mirror_index = 0; mirror_index < BTRFS_MAX_MIRRORS;
		     mirror_index++) {
			struct scrub_block *sblock = sblocks_for_recheck +
						     mirror_index;
			int page_index;

			for (page_index = 0; page_index < sblock->page_count;
			     page_index++) {
				sblock->pagev[page_index]->sblock = NULL;
				scrub_page_put(sblock->pagev[page_index]);
			}
		}
		kfree(sblocks_for_recheck);
	}

	return 0;
}

static int scrub_setup_recheck_block(struct scrub_ctx *sctx,
				     struct btrfs_fs_info *fs_info,
				     struct scrub_block *original_sblock,
				     u64 length, u64 logical,
				     struct scrub_block *sblocks_for_recheck)
{
	int page_index;
	int mirror_index;
	int ret;

	page_index = 0;
	while (length > 0) {
		u64 sublen = min_t(u64, length, PAGE_SIZE);
		u64 mapped_length = sublen;
		struct btrfs_bio *bbio = NULL;

		ret = btrfs_map_block(fs_info, REQ_GET_READ_MIRRORS, logical,
				      &mapped_length, &bbio, 0);
		if (ret || !bbio || mapped_length < sublen) {
			kfree(bbio);
			return -EIO;
		}

		BUG_ON(page_index >= SCRUB_PAGES_PER_RD_BIO);
		for (mirror_index = 0; mirror_index < (int)bbio->num_stripes;
		     mirror_index++) {
			struct scrub_block *sblock;
			struct scrub_page *page;

			if (mirror_index >= BTRFS_MAX_MIRRORS)
				continue;

			sblock = sblocks_for_recheck + mirror_index;
			sblock->sctx = sctx;
			page = kzalloc(sizeof(*page), GFP_NOFS);
			if (!page) {
leave_nomem:
				spin_lock(&sctx->stat_lock);
				sctx->stat.malloc_errors++;
				spin_unlock(&sctx->stat_lock);
				kfree(bbio);
				return -ENOMEM;
			}
			scrub_page_get(page);
			sblock->pagev[page_index] = page;
			page->logical = logical;
			page->physical = bbio->stripes[mirror_index].physical;
			BUG_ON(page_index >= original_sblock->page_count);
			page->physical_for_dev_replace =
				original_sblock->pagev[page_index]->
				physical_for_dev_replace;
			 
			page->dev = bbio->stripes[mirror_index].dev;
			page->mirror_num = mirror_index + 1;
			sblock->page_count++;
			page->page = alloc_page(GFP_NOFS);
			if (!page->page)
				goto leave_nomem;
		}
		kfree(bbio);
		length -= sublen;
		logical += sublen;
		page_index++;
	}

	return 0;
}

static void scrub_recheck_block(struct btrfs_fs_info *fs_info,
				struct scrub_block *sblock, int is_metadata,
				int have_csum, u8 *csum, u64 generation,
				u16 csum_size)
{
	int page_num;

	sblock->no_io_error_seen = 1;
	sblock->header_error = 0;
	sblock->checksum_error = 0;

	for (page_num = 0; page_num < sblock->page_count; page_num++) {
		struct bio *bio;
		struct scrub_page *page = sblock->pagev[page_num];
		DECLARE_COMPLETION_ONSTACK(complete);

		if (page->dev->bdev == NULL) {
			page->io_error = 1;
			sblock->no_io_error_seen = 0;
			continue;
		}

		WARN_ON(!page->page);
		bio = btrfs_io_bio_alloc(GFP_NOFS, 1);
		if (!bio) {
			page->io_error = 1;
			sblock->no_io_error_seen = 0;
			continue;
		}
		bio->bi_bdev = page->dev->bdev;
		bio->bi_sector = page->physical >> 9;
		bio->bi_end_io = scrub_complete_bio_end_io;
		bio->bi_private = &complete;

		bio_add_page(bio, page->page, PAGE_SIZE, 0);
		btrfsic_submit_bio(READ, bio);

		wait_for_completion(&complete);

		page->io_error = !test_bit(BIO_UPTODATE, &bio->bi_flags);
		if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
			sblock->no_io_error_seen = 0;
		bio_put(bio);
	}

	if (sblock->no_io_error_seen)
		scrub_recheck_block_checksum(fs_info, sblock, is_metadata,
					     have_csum, csum, generation,
					     csum_size);
	return;
}

static void scrub_recheck_block_checksum(struct btrfs_fs_info *fs_info,
					 struct scrub_block *sblock,
					 int is_metadata, int have_csum,
					 const u8 *csum, u64 generation,
					 u16 csum_size)
{
	int page_num;
	u8 calculated_csum[BTRFS_CSUM_SIZE];
	u32 crc = ~(u32)0;
	void *mapped_buffer;

	WARN_ON(!sblock->pagev[0]->page);
	if (is_metadata) {
		struct btrfs_header *h;

		mapped_buffer = kmap_atomic(sblock->pagev[0]->page);
		h = (struct btrfs_header *)mapped_buffer;

		if (sblock->pagev[0]->logical != btrfs_stack_header_bytenr(h) ||
		    memcmp(h->fsid, fs_info->fsid, BTRFS_UUID_SIZE) ||
		    memcmp(h->chunk_tree_uuid, fs_info->chunk_tree_uuid,
			   BTRFS_UUID_SIZE)) {
			sblock->header_error = 1;
		} else if (generation != btrfs_stack_header_generation(h)) {
			sblock->header_error = 1;
			sblock->generation_error = 1;
		}
		csum = h->csum;
	} else {
		if (!have_csum)
			return;

		mapped_buffer = kmap_atomic(sblock->pagev[0]->page);
	}

	for (page_num = 0;;) {
		if (page_num == 0 && is_metadata)
			crc = btrfs_csum_data(
				((u8 *)mapped_buffer) + BTRFS_CSUM_SIZE,
				crc, PAGE_SIZE - BTRFS_CSUM_SIZE);
		else
			crc = btrfs_csum_data(mapped_buffer, crc, PAGE_SIZE);

		kunmap_atomic(mapped_buffer);
		page_num++;
		if (page_num >= sblock->page_count)
			break;
		WARN_ON(!sblock->pagev[page_num]->page);

		mapped_buffer = kmap_atomic(sblock->pagev[page_num]->page);
	}

	btrfs_csum_final(crc, calculated_csum);
	if (memcmp(calculated_csum, csum, csum_size))
		sblock->checksum_error = 1;
}

static void scrub_complete_bio_end_io(struct bio *bio, int err)
{
	complete((struct completion *)bio->bi_private);
}

static int scrub_repair_block_from_good_copy(struct scrub_block *sblock_bad,
					     struct scrub_block *sblock_good,
					     int force_write)
{
	int page_num;
	int ret = 0;

	for (page_num = 0; page_num < sblock_bad->page_count; page_num++) {
		int ret_sub;

		ret_sub = scrub_repair_page_from_good_copy(sblock_bad,
							   sblock_good,
							   page_num,
							   force_write);
		if (ret_sub)
			ret = ret_sub;
	}

	return ret;
}

static int scrub_repair_page_from_good_copy(struct scrub_block *sblock_bad,
					    struct scrub_block *sblock_good,
					    int page_num, int force_write)
{
	struct scrub_page *page_bad = sblock_bad->pagev[page_num];
	struct scrub_page *page_good = sblock_good->pagev[page_num];

	BUG_ON(page_bad->page == NULL);
	BUG_ON(page_good->page == NULL);
	if (force_write || sblock_bad->header_error ||
	    sblock_bad->checksum_error || page_bad->io_error) {
		struct bio *bio;
		int ret;
		DECLARE_COMPLETION_ONSTACK(complete);

		if (!page_bad->dev->bdev) {
			printk_ratelimited(KERN_WARNING "BTRFS: "
				"scrub_repair_page_from_good_copy(bdev == NULL) "
				"is unexpected!\n");
			return -EIO;
		}

		bio = btrfs_io_bio_alloc(GFP_NOFS, 1);
		if (!bio)
			return -EIO;
		bio->bi_bdev = page_bad->dev->bdev;
		bio->bi_sector = page_bad->physical >> 9;
		bio->bi_end_io = scrub_complete_bio_end_io;
		bio->bi_private = &complete;

		ret = bio_add_page(bio, page_good->page, PAGE_SIZE, 0);
		if (PAGE_SIZE != ret) {
			bio_put(bio);
			return -EIO;
		}
		btrfsic_submit_bio(WRITE, bio);

		wait_for_completion(&complete);
		if (!bio_flagged(bio, BIO_UPTODATE)) {
			btrfs_dev_stat_inc_and_print(page_bad->dev,
				BTRFS_DEV_STAT_WRITE_ERRS);
			btrfs_dev_replace_stats_inc(
				&sblock_bad->sctx->dev_root->fs_info->
				dev_replace.num_write_errors);
			bio_put(bio);
			return -EIO;
		}
		bio_put(bio);
	}

	return 0;
}

static void scrub_write_block_to_dev_replace(struct scrub_block *sblock)
{
	int page_num;

	for (page_num = 0; page_num < sblock->page_count; page_num++) {
		int ret;

		ret = scrub_write_page_to_dev_replace(sblock, page_num);
		if (ret)
			btrfs_dev_replace_stats_inc(
				&sblock->sctx->dev_root->fs_info->dev_replace.
				num_write_errors);
	}
}

static int scrub_write_page_to_dev_replace(struct scrub_block *sblock,
					   int page_num)
{
	struct scrub_page *spage = sblock->pagev[page_num];

	BUG_ON(spage->page == NULL);
	if (spage->io_error) {
		void *mapped_buffer = kmap_atomic(spage->page);

		memset(mapped_buffer, 0, PAGE_CACHE_SIZE);
		flush_dcache_page(spage->page);
		kunmap_atomic(mapped_buffer);
	}
	return scrub_add_page_to_wr_bio(sblock->sctx, spage);
}

static int scrub_add_page_to_wr_bio(struct scrub_ctx *sctx,
				    struct scrub_page *spage)
{
	struct scrub_wr_ctx *wr_ctx = &sctx->wr_ctx;
	struct scrub_bio *sbio;
	int ret;

	mutex_lock(&wr_ctx->wr_lock);
again:
	if (!wr_ctx->wr_curr_bio) {
		wr_ctx->wr_curr_bio = kzalloc(sizeof(*wr_ctx->wr_curr_bio),
					      GFP_NOFS);
		if (!wr_ctx->wr_curr_bio) {
			mutex_unlock(&wr_ctx->wr_lock);
			return -ENOMEM;
		}
		wr_ctx->wr_curr_bio->sctx = sctx;
		wr_ctx->wr_curr_bio->page_count = 0;
	}
	sbio = wr_ctx->wr_curr_bio;
	if (sbio->page_count == 0) {
		struct bio *bio;

		sbio->physical = spage->physical_for_dev_replace;
		sbio->logical = spage->logical;
		sbio->dev = wr_ctx->tgtdev;
		bio = sbio->bio;
		if (!bio) {
			bio = btrfs_io_bio_alloc(GFP_NOFS, wr_ctx->pages_per_wr_bio);
			if (!bio) {
				mutex_unlock(&wr_ctx->wr_lock);
				return -ENOMEM;
			}
			sbio->bio = bio;
		}

		bio->bi_private = sbio;
		bio->bi_end_io = scrub_wr_bio_end_io;
		bio->bi_bdev = sbio->dev->bdev;
		bio->bi_sector = sbio->physical >> 9;
		sbio->err = 0;
	} else if (sbio->physical + sbio->page_count * PAGE_SIZE !=
		   spage->physical_for_dev_replace ||
		   sbio->logical + sbio->page_count * PAGE_SIZE !=
		   spage->logical) {
		scrub_wr_submit(sctx);
		goto again;
	}

	ret = bio_add_page(sbio->bio, spage->page, PAGE_SIZE, 0);
	if (ret != PAGE_SIZE) {
		if (sbio->page_count < 1) {
			bio_put(sbio->bio);
			sbio->bio = NULL;
			mutex_unlock(&wr_ctx->wr_lock);
			return -EIO;
		}
		scrub_wr_submit(sctx);
		goto again;
	}

	sbio->pagev[sbio->page_count] = spage;
	scrub_page_get(spage);
	sbio->page_count++;
	if (sbio->page_count == wr_ctx->pages_per_wr_bio)
		scrub_wr_submit(sctx);
	mutex_unlock(&wr_ctx->wr_lock);

	return 0;
}

static void scrub_wr_submit(struct scrub_ctx *sctx)
{
	struct scrub_wr_ctx *wr_ctx = &sctx->wr_ctx;
	struct scrub_bio *sbio;

	if (!wr_ctx->wr_curr_bio)
		return;

	sbio = wr_ctx->wr_curr_bio;
	wr_ctx->wr_curr_bio = NULL;
	WARN_ON(!sbio->bio->bi_bdev);
	scrub_pending_bio_inc(sctx);
	 
	btrfsic_submit_bio(WRITE, sbio->bio);
}

static void scrub_wr_bio_end_io(struct bio *bio, int err)
{
	struct scrub_bio *sbio = bio->bi_private;
	struct btrfs_fs_info *fs_info = sbio->dev->dev_root->fs_info;

	sbio->err = err;
	sbio->bio = bio;

	btrfs_init_work(&sbio->work, btrfs_scrubwrc_helper,
			 scrub_wr_bio_end_io_worker, NULL, NULL);
	btrfs_queue_work(fs_info->scrub_wr_completion_workers, &sbio->work);
}

static void scrub_wr_bio_end_io_worker(struct btrfs_work *work)
{
	struct scrub_bio *sbio = container_of(work, struct scrub_bio, work);
	struct scrub_ctx *sctx = sbio->sctx;
	int i;

	WARN_ON(sbio->page_count > SCRUB_PAGES_PER_WR_BIO);
	if (sbio->err) {
		struct btrfs_dev_replace *dev_replace =
			&sbio->sctx->dev_root->fs_info->dev_replace;

		for (i = 0; i < sbio->page_count; i++) {
			struct scrub_page *spage = sbio->pagev[i];

			spage->io_error = 1;
			btrfs_dev_replace_stats_inc(&dev_replace->
						    num_write_errors);
		}
	}

	for (i = 0; i < sbio->page_count; i++)
		scrub_page_put(sbio->pagev[i]);

	bio_put(sbio->bio);
	kfree(sbio);
	scrub_pending_bio_dec(sctx);
}

static int scrub_checksum(struct scrub_block *sblock)
{
	u64 flags;
	int ret;

	WARN_ON(sblock->page_count < 1);
	flags = sblock->pagev[0]->flags;
	ret = 0;
	if (flags & BTRFS_EXTENT_FLAG_DATA)
		ret = scrub_checksum_data(sblock);
	else if (flags & BTRFS_EXTENT_FLAG_TREE_BLOCK)
		ret = scrub_checksum_tree_block(sblock);
	else if (flags & BTRFS_EXTENT_FLAG_SUPER)
		(void)scrub_checksum_super(sblock);
	else
		WARN_ON(1);
	if (ret)
		scrub_handle_errored_block(sblock);

	return ret;
}

static int scrub_checksum_data(struct scrub_block *sblock)
{
	struct scrub_ctx *sctx = sblock->sctx;
	u8 csum[BTRFS_CSUM_SIZE];
	u8 *on_disk_csum;
	struct page *page;
	void *buffer;
	u32 crc = ~(u32)0;
	int fail = 0;
	u64 len;
	int index;

	BUG_ON(sblock->page_count < 1);
	if (!sblock->pagev[0]->have_csum)
		return 0;

	on_disk_csum = sblock->pagev[0]->csum;
	page = sblock->pagev[0]->page;
	buffer = kmap_atomic(page);

	len = sctx->sectorsize;
	index = 0;
	for (;;) {
		u64 l = min_t(u64, len, PAGE_SIZE);

		crc = btrfs_csum_data(buffer, crc, l);
		kunmap_atomic(buffer);
		len -= l;
		if (len == 0)
			break;
		index++;
		BUG_ON(index >= sblock->page_count);
		BUG_ON(!sblock->pagev[index]->page);
		page = sblock->pagev[index]->page;
		buffer = kmap_atomic(page);
	}

	btrfs_csum_final(crc, csum);
	if (memcmp(csum, on_disk_csum, sctx->csum_size))
		fail = 1;

	return fail;
}

static int scrub_checksum_tree_block(struct scrub_block *sblock)
{
	struct scrub_ctx *sctx = sblock->sctx;
	struct btrfs_header *h;
	struct btrfs_root *root = sctx->dev_root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	u8 calculated_csum[BTRFS_CSUM_SIZE];
	u8 on_disk_csum[BTRFS_CSUM_SIZE];
	struct page *page;
	void *mapped_buffer;
	u64 mapped_size;
	void *p;
	u32 crc = ~(u32)0;
	int fail = 0;
	int crc_fail = 0;
	u64 len;
	int index;

	BUG_ON(sblock->page_count < 1);
	page = sblock->pagev[0]->page;
	mapped_buffer = kmap_atomic(page);
	h = (struct btrfs_header *)mapped_buffer;
	memcpy(on_disk_csum, h->csum, sctx->csum_size);

	if (sblock->pagev[0]->logical != btrfs_stack_header_bytenr(h))
		++fail;

	if (sblock->pagev[0]->generation != btrfs_stack_header_generation(h))
		++fail;

	if (memcmp(h->fsid, fs_info->fsid, BTRFS_UUID_SIZE))
		++fail;

	if (memcmp(h->chunk_tree_uuid, fs_info->chunk_tree_uuid,
		   BTRFS_UUID_SIZE))
		++fail;

	WARN_ON(sctx->nodesize != sctx->leafsize);
	len = sctx->nodesize - BTRFS_CSUM_SIZE;
	mapped_size = PAGE_SIZE - BTRFS_CSUM_SIZE;
	p = ((u8 *)mapped_buffer) + BTRFS_CSUM_SIZE;
	index = 0;
	for (;;) {
		u64 l = min_t(u64, len, mapped_size);

		crc = btrfs_csum_data(p, crc, l);
		kunmap_atomic(mapped_buffer);
		len -= l;
		if (len == 0)
			break;
		index++;
		BUG_ON(index >= sblock->page_count);
		BUG_ON(!sblock->pagev[index]->page);
		page = sblock->pagev[index]->page;
		mapped_buffer = kmap_atomic(page);
		mapped_size = PAGE_SIZE;
		p = mapped_buffer;
	}

	btrfs_csum_final(crc, calculated_csum);
	if (memcmp(calculated_csum, on_disk_csum, sctx->csum_size))
		++crc_fail;

	return fail || crc_fail;
}

static int scrub_checksum_super(struct scrub_block *sblock)
{
	struct btrfs_super_block *s;
	struct scrub_ctx *sctx = sblock->sctx;
	struct btrfs_root *root = sctx->dev_root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	u8 calculated_csum[BTRFS_CSUM_SIZE];
	u8 on_disk_csum[BTRFS_CSUM_SIZE];
	struct page *page;
	void *mapped_buffer;
	u64 mapped_size;
	void *p;
	u32 crc = ~(u32)0;
	int fail_gen = 0;
	int fail_cor = 0;
	u64 len;
	int index;

	BUG_ON(sblock->page_count < 1);
	page = sblock->pagev[0]->page;
	mapped_buffer = kmap_atomic(page);
	s = (struct btrfs_super_block *)mapped_buffer;
	memcpy(on_disk_csum, s->csum, sctx->csum_size);

	if (sblock->pagev[0]->logical != btrfs_super_bytenr(s))
		++fail_cor;

	if (sblock->pagev[0]->generation != btrfs_super_generation(s))
		++fail_gen;

	if (memcmp(s->fsid, fs_info->fsid, BTRFS_UUID_SIZE))
		++fail_cor;

	len = BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE;
	mapped_size = PAGE_SIZE - BTRFS_CSUM_SIZE;
	p = ((u8 *)mapped_buffer) + BTRFS_CSUM_SIZE;
	index = 0;
	for (;;) {
		u64 l = min_t(u64, len, mapped_size);

		crc = btrfs_csum_data(p, crc, l);
		kunmap_atomic(mapped_buffer);
		len -= l;
		if (len == 0)
			break;
		index++;
		BUG_ON(index >= sblock->page_count);
		BUG_ON(!sblock->pagev[index]->page);
		page = sblock->pagev[index]->page;
		mapped_buffer = kmap_atomic(page);
		mapped_size = PAGE_SIZE;
		p = mapped_buffer;
	}

	btrfs_csum_final(crc, calculated_csum);
	if (memcmp(calculated_csum, on_disk_csum, sctx->csum_size))
		++fail_cor;

	if (fail_cor + fail_gen) {
		 
		spin_lock(&sctx->stat_lock);
		++sctx->stat.super_errors;
		spin_unlock(&sctx->stat_lock);
		if (fail_cor)
			btrfs_dev_stat_inc_and_print(sblock->pagev[0]->dev,
				BTRFS_DEV_STAT_CORRUPTION_ERRS);
		else
			btrfs_dev_stat_inc_and_print(sblock->pagev[0]->dev,
				BTRFS_DEV_STAT_GENERATION_ERRS);
	}

	return fail_cor + fail_gen;
}

static void scrub_block_get(struct scrub_block *sblock)
{
	atomic_inc(&sblock->ref_count);
}

static void scrub_block_put(struct scrub_block *sblock)
{
	if (atomic_dec_and_test(&sblock->ref_count)) {
		int i;

		for (i = 0; i < sblock->page_count; i++)
			scrub_page_put(sblock->pagev[i]);
		kfree(sblock);
	}
}

static void scrub_page_get(struct scrub_page *spage)
{
	atomic_inc(&spage->ref_count);
}

static void scrub_page_put(struct scrub_page *spage)
{
	if (atomic_dec_and_test(&spage->ref_count)) {
		if (spage->page)
			__free_page(spage->page);
		kfree(spage);
	}
}

static void scrub_submit(struct scrub_ctx *sctx)
{
	struct scrub_bio *sbio;

	if (sctx->curr == -1)
		return;

	sbio = sctx->bios[sctx->curr];
	sctx->curr = -1;
	scrub_pending_bio_inc(sctx);

	if (!sbio->bio->bi_bdev) {
		 
		printk_ratelimited(KERN_WARNING
			"BTRFS: scrub_submit(bio bdev == NULL) is unexpected!\n");
		bio_endio(sbio->bio, -EIO);
	} else {
		btrfsic_submit_bio(READ, sbio->bio);
	}
}

static int scrub_add_page_to_rd_bio(struct scrub_ctx *sctx,
				    struct scrub_page *spage)
{
	struct scrub_block *sblock = spage->sblock;
	struct scrub_bio *sbio;
	int ret;

again:
	 
	while (sctx->curr == -1) {
		spin_lock(&sctx->list_lock);
		sctx->curr = sctx->first_free;
		if (sctx->curr != -1) {
			sctx->first_free = sctx->bios[sctx->curr]->next_free;
			sctx->bios[sctx->curr]->next_free = -1;
			sctx->bios[sctx->curr]->page_count = 0;
			spin_unlock(&sctx->list_lock);
		} else {
			spin_unlock(&sctx->list_lock);
			wait_event(sctx->list_wait, sctx->first_free != -1);
		}
	}
	sbio = sctx->bios[sctx->curr];
	if (sbio->page_count == 0) {
		struct bio *bio;

		sbio->physical = spage->physical;
		sbio->logical = spage->logical;
		sbio->dev = spage->dev;
		bio = sbio->bio;
		if (!bio) {
			bio = btrfs_io_bio_alloc(GFP_NOFS, sctx->pages_per_rd_bio);
			if (!bio)
				return -ENOMEM;
			sbio->bio = bio;
		}

		bio->bi_private = sbio;
		bio->bi_end_io = scrub_bio_end_io;
		bio->bi_bdev = sbio->dev->bdev;
		bio->bi_sector = sbio->physical >> 9;
		sbio->err = 0;
	} else if (sbio->physical + sbio->page_count * PAGE_SIZE !=
		   spage->physical ||
		   sbio->logical + sbio->page_count * PAGE_SIZE !=
		   spage->logical ||
		   sbio->dev != spage->dev) {
		scrub_submit(sctx);
		goto again;
	}

	sbio->pagev[sbio->page_count] = spage;
	ret = bio_add_page(sbio->bio, spage->page, PAGE_SIZE, 0);
	if (ret != PAGE_SIZE) {
		if (sbio->page_count < 1) {
			bio_put(sbio->bio);
			sbio->bio = NULL;
			return -EIO;
		}
		scrub_submit(sctx);
		goto again;
	}

	scrub_block_get(sblock);  
	atomic_inc(&sblock->outstanding_pages);
	sbio->page_count++;
	if (sbio->page_count == sctx->pages_per_rd_bio)
		scrub_submit(sctx);

	return 0;
}

static int scrub_pages(struct scrub_ctx *sctx, u64 logical, u64 len,
		       u64 physical, struct btrfs_device *dev, u64 flags,
		       u64 gen, int mirror_num, u8 *csum, int force,
		       u64 physical_for_dev_replace)
{
	struct scrub_block *sblock;
	int index;

	sblock = kzalloc(sizeof(*sblock), GFP_NOFS);
	if (!sblock) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		spin_unlock(&sctx->stat_lock);
		return -ENOMEM;
	}

	atomic_set(&sblock->ref_count, 1);
	sblock->sctx = sctx;
	sblock->no_io_error_seen = 1;

	for (index = 0; len > 0; index++) {
		struct scrub_page *spage;
		u64 l = min_t(u64, len, PAGE_SIZE);

		spage = kzalloc(sizeof(*spage), GFP_NOFS);
		if (!spage) {
leave_nomem:
			spin_lock(&sctx->stat_lock);
			sctx->stat.malloc_errors++;
			spin_unlock(&sctx->stat_lock);
			scrub_block_put(sblock);
			return -ENOMEM;
		}
		BUG_ON(index >= SCRUB_MAX_PAGES_PER_BLOCK);
		scrub_page_get(spage);
		sblock->pagev[index] = spage;
		spage->sblock = sblock;
		spage->dev = dev;
		spage->flags = flags;
		spage->generation = gen;
		spage->logical = logical;
		spage->physical = physical;
		spage->physical_for_dev_replace = physical_for_dev_replace;
		spage->mirror_num = mirror_num;
		if (csum) {
			spage->have_csum = 1;
			memcpy(spage->csum, csum, sctx->csum_size);
		} else {
			spage->have_csum = 0;
		}
		sblock->page_count++;
		spage->page = alloc_page(GFP_NOFS);
		if (!spage->page)
			goto leave_nomem;
		len -= l;
		logical += l;
		physical += l;
		physical_for_dev_replace += l;
	}

	WARN_ON(sblock->page_count == 0);
	for (index = 0; index < sblock->page_count; index++) {
		struct scrub_page *spage = sblock->pagev[index];
		int ret;

		ret = scrub_add_page_to_rd_bio(sctx, spage);
		if (ret) {
			scrub_block_put(sblock);
			return ret;
		}
	}

	if (force)
		scrub_submit(sctx);

	scrub_block_put(sblock);
	return 0;
}

static void scrub_bio_end_io(struct bio *bio, int err)
{
	struct scrub_bio *sbio = bio->bi_private;
	struct btrfs_fs_info *fs_info = sbio->dev->dev_root->fs_info;

	sbio->err = err;
	sbio->bio = bio;

	btrfs_queue_work(fs_info->scrub_workers, &sbio->work);
}

static void scrub_bio_end_io_worker(struct btrfs_work *work)
{
	struct scrub_bio *sbio = container_of(work, struct scrub_bio, work);
	struct scrub_ctx *sctx = sbio->sctx;
	int i;

	BUG_ON(sbio->page_count > SCRUB_PAGES_PER_RD_BIO);
	if (sbio->err) {
		for (i = 0; i < sbio->page_count; i++) {
			struct scrub_page *spage = sbio->pagev[i];

			spage->io_error = 1;
			spage->sblock->no_io_error_seen = 0;
		}
	}

	for (i = 0; i < sbio->page_count; i++) {
		struct scrub_page *spage = sbio->pagev[i];
		struct scrub_block *sblock = spage->sblock;

		if (atomic_dec_and_test(&sblock->outstanding_pages))
			scrub_block_complete(sblock);
		scrub_block_put(sblock);
	}

	bio_put(sbio->bio);
	sbio->bio = NULL;
	spin_lock(&sctx->list_lock);
	sbio->next_free = sctx->first_free;
	sctx->first_free = sbio->index;
	spin_unlock(&sctx->list_lock);

	if (sctx->is_dev_replace &&
	    atomic_read(&sctx->wr_ctx.flush_all_writes)) {
		mutex_lock(&sctx->wr_ctx.wr_lock);
		scrub_wr_submit(sctx);
		mutex_unlock(&sctx->wr_ctx.wr_lock);
	}

	scrub_pending_bio_dec(sctx);
}

static void scrub_block_complete(struct scrub_block *sblock)
{
	if (!sblock->no_io_error_seen) {
		scrub_handle_errored_block(sblock);
	} else {
		 
		if (!scrub_checksum(sblock) && sblock->sctx->is_dev_replace)
			scrub_write_block_to_dev_replace(sblock);
	}
}

static int scrub_find_csum(struct scrub_ctx *sctx, u64 logical, u64 len,
			   u8 *csum)
{
	struct btrfs_ordered_sum *sum = NULL;
	unsigned long index;
	unsigned long num_sectors;

	while (!list_empty(&sctx->csum_list)) {
		sum = list_first_entry(&sctx->csum_list,
				       struct btrfs_ordered_sum, list);
		if (sum->bytenr > logical)
			return 0;
		if (sum->bytenr + sum->len > logical)
			break;

		++sctx->stat.csum_discards;
		list_del(&sum->list);
		kfree(sum);
		sum = NULL;
	}
	if (!sum)
		return 0;

	index = ((u32)(logical - sum->bytenr)) / sctx->sectorsize;
	num_sectors = sum->len / sctx->sectorsize;
	memcpy(csum, sum->sums + index, sctx->csum_size);
	if (index == num_sectors - 1) {
		list_del(&sum->list);
		kfree(sum);
	}
	return 1;
}

static int scrub_extent(struct scrub_ctx *sctx, u64 logical, u64 len,
			u64 physical, struct btrfs_device *dev, u64 flags,
			u64 gen, int mirror_num, u64 physical_for_dev_replace)
{
	int ret;
	u8 csum[BTRFS_CSUM_SIZE];
	u32 blocksize;

	if (flags & BTRFS_EXTENT_FLAG_DATA) {
		blocksize = sctx->sectorsize;
		spin_lock(&sctx->stat_lock);
		sctx->stat.data_extents_scrubbed++;
		sctx->stat.data_bytes_scrubbed += len;
		spin_unlock(&sctx->stat_lock);
	} else if (flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
		WARN_ON(sctx->nodesize != sctx->leafsize);
		blocksize = sctx->nodesize;
		spin_lock(&sctx->stat_lock);
		sctx->stat.tree_extents_scrubbed++;
		sctx->stat.tree_bytes_scrubbed += len;
		spin_unlock(&sctx->stat_lock);
	} else {
		blocksize = sctx->sectorsize;
		WARN_ON(1);
	}

	while (len) {
		u64 l = min_t(u64, len, blocksize);
		int have_csum = 0;

		if (flags & BTRFS_EXTENT_FLAG_DATA) {
			 
			have_csum = scrub_find_csum(sctx, logical, l, csum);
			if (have_csum == 0)
				++sctx->stat.no_csum;
			if (sctx->is_dev_replace && !have_csum) {
				ret = copy_nocow_pages(sctx, logical, l,
						       mirror_num,
						      physical_for_dev_replace);
				goto behind_scrub_pages;
			}
		}
		ret = scrub_pages(sctx, logical, l, physical, dev, flags, gen,
				  mirror_num, have_csum ? csum : NULL, 0,
				  physical_for_dev_replace);
behind_scrub_pages:
		if (ret)
			return ret;
		len -= l;
		logical += l;
		physical += l;
		physical_for_dev_replace += l;
	}
	return 0;
}

static int get_raid56_logic_offset(u64 physical, int num,
				   struct map_lookup *map, u64 *offset)
{
	int i;
	int j = 0;
	u64 stripe_nr;
	u64 last_offset;
	int stripe_index;
	int rot;

	last_offset = (physical - map->stripes[num].physical) *
		      nr_data_stripes(map);
	*offset = last_offset;
	for (i = 0; i < nr_data_stripes(map); i++) {
		*offset = last_offset + i * map->stripe_len;

		stripe_nr = *offset;
		do_div(stripe_nr, map->stripe_len);
		do_div(stripe_nr, nr_data_stripes(map));

		rot = do_div(stripe_nr, map->num_stripes);
		 
		rot += i;
		stripe_index = rot % map->num_stripes;
		if (stripe_index == num)
			return 0;
		if (stripe_index < num)
			j++;
	}
	*offset = last_offset + j * map->stripe_len;
	return 1;
}

static noinline_for_stack int scrub_stripe(struct scrub_ctx *sctx,
					   struct map_lookup *map,
					   struct btrfs_device *scrub_dev,
					   int num, u64 base, u64 length,
					   int is_dev_replace)
{
	struct btrfs_path *path;
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;
	struct btrfs_root *root = fs_info->extent_root;
	struct btrfs_root *csum_root = fs_info->csum_root;
	struct btrfs_extent_item *extent;
	struct blk_plug plug;
	u64 flags;
	int ret;
	int slot;
	u64 nstripes;
	struct extent_buffer *l;
	struct btrfs_key key;
	u64 physical;
	u64 logical;
	u64 logic_end;
	u64 physical_end;
	u64 generation;
	int mirror_num;
	struct reada_control *reada1;
	struct reada_control *reada2;
	struct btrfs_key key_start;
	struct btrfs_key key_end;
	u64 increment = map->stripe_len;
	u64 offset;
	u64 extent_logical;
	u64 extent_physical;
	u64 extent_len;
	struct btrfs_device *extent_dev;
	int extent_mirror_num;
	int stop_loop = 0;

	nstripes = length;
	physical = map->stripes[num].physical;
	offset = 0;
	do_div(nstripes, map->stripe_len);
	if (map->type & BTRFS_BLOCK_GROUP_RAID0) {
		offset = map->stripe_len * num;
		increment = map->stripe_len * map->num_stripes;
		mirror_num = 1;
	} else if (map->type & BTRFS_BLOCK_GROUP_RAID10) {
		int factor = map->num_stripes / map->sub_stripes;
		offset = map->stripe_len * (num / map->sub_stripes);
		increment = map->stripe_len * factor;
		mirror_num = num % map->sub_stripes + 1;
	} else if (map->type & BTRFS_BLOCK_GROUP_RAID1) {
		increment = map->stripe_len;
		mirror_num = num % map->num_stripes + 1;
	} else if (map->type & BTRFS_BLOCK_GROUP_DUP) {
		increment = map->stripe_len;
		mirror_num = num % map->num_stripes + 1;
	} else if (map->type & (BTRFS_BLOCK_GROUP_RAID5 |
				BTRFS_BLOCK_GROUP_RAID6)) {
		get_raid56_logic_offset(physical, num, map, &offset);
		increment = map->stripe_len * nr_data_stripes(map);
		mirror_num = 1;
	} else {
		increment = map->stripe_len;
		mirror_num = 1;
	}

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->search_commit_root = 1;
	path->skip_locking = 1;

	logical = base + offset;
	physical_end = physical + nstripes * map->stripe_len;
	if (map->type & (BTRFS_BLOCK_GROUP_RAID5 |
			 BTRFS_BLOCK_GROUP_RAID6)) {
		get_raid56_logic_offset(physical_end, num,
					map, &logic_end);
		logic_end += base;
	} else {
		logic_end = logical + increment * nstripes;
	}
	wait_event(sctx->list_wait,
		   atomic_read(&sctx->bios_in_flight) == 0);
	scrub_blocked_if_needed(fs_info);

	key_start.objectid = logical;
	key_start.type = BTRFS_EXTENT_ITEM_KEY;
	key_start.offset = (u64)0;
	key_end.objectid = logic_end;
	key_end.type = BTRFS_METADATA_ITEM_KEY;
	key_end.offset = (u64)-1;
	reada1 = btrfs_reada_add(root, &key_start, &key_end);

	key_start.objectid = BTRFS_EXTENT_CSUM_OBJECTID;
	key_start.type = BTRFS_EXTENT_CSUM_KEY;
	key_start.offset = logical;
	key_end.objectid = BTRFS_EXTENT_CSUM_OBJECTID;
	key_end.type = BTRFS_EXTENT_CSUM_KEY;
	key_end.offset = logic_end;
	reada2 = btrfs_reada_add(csum_root, &key_start, &key_end);

	if (!IS_ERR(reada1))
		btrfs_reada_wait(reada1);
	if (!IS_ERR(reada2))
		btrfs_reada_wait(reada2);

	blk_start_plug(&plug);

	ret = 0;
	while (physical < physical_end) {
		 
		if (map->type & (BTRFS_BLOCK_GROUP_RAID5 |
				BTRFS_BLOCK_GROUP_RAID6)) {
			ret = get_raid56_logic_offset(physical, num,
					map, &logical);
			logical += base;
			if (ret)
				goto skip;
		}
		 
		if (atomic_read(&fs_info->scrub_cancel_req) ||
		    atomic_read(&sctx->cancel_req)) {
			ret = -ECANCELED;
			goto out;
		}
		 
		if (atomic_read(&fs_info->scrub_pause_req)) {
			 
			atomic_set(&sctx->wr_ctx.flush_all_writes, 1);
			scrub_submit(sctx);
			mutex_lock(&sctx->wr_ctx.wr_lock);
			scrub_wr_submit(sctx);
			mutex_unlock(&sctx->wr_ctx.wr_lock);
			wait_event(sctx->list_wait,
				   atomic_read(&sctx->bios_in_flight) == 0);
			atomic_set(&sctx->wr_ctx.flush_all_writes, 0);
			scrub_blocked_if_needed(fs_info);
		}

		if (btrfs_fs_incompat(fs_info, SKINNY_METADATA))
			key.type = BTRFS_METADATA_ITEM_KEY;
		else
			key.type = BTRFS_EXTENT_ITEM_KEY;
		key.objectid = logical;
		key.offset = (u64)-1;

		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0)
			goto out;

		if (ret > 0) {
			ret = btrfs_previous_extent_item(root, path, 0);
			if (ret < 0)
				goto out;
			if (ret > 0) {
				 
				btrfs_release_path(path);
				ret = btrfs_search_slot(NULL, root, &key,
							path, 0, 0);
				if (ret < 0)
					goto out;
			}
		}

		stop_loop = 0;
		while (1) {
			u64 bytes;

			l = path->nodes[0];
			slot = path->slots[0];
			if (slot >= btrfs_header_nritems(l)) {
				ret = btrfs_next_leaf(root, path);
				if (ret == 0)
					continue;
				if (ret < 0)
					goto out;

				stop_loop = 1;
				break;
			}
			btrfs_item_key_to_cpu(l, &key, slot);

			if (key.type == BTRFS_METADATA_ITEM_KEY)
				bytes = root->leafsize;
			else
				bytes = key.offset;

			if (key.objectid + bytes <= logical)
				goto next;

			if (key.type != BTRFS_EXTENT_ITEM_KEY &&
			    key.type != BTRFS_METADATA_ITEM_KEY)
				goto next;

			if (key.objectid >= logical + map->stripe_len) {
				 
				if (key.objectid >= logic_end)
					stop_loop = 1;
				break;
			}

			extent = btrfs_item_ptr(l, slot,
						struct btrfs_extent_item);
			flags = btrfs_extent_flags(l, extent);
			generation = btrfs_extent_generation(l, extent);

			if (key.objectid < logical &&
			    (flags & BTRFS_EXTENT_FLAG_TREE_BLOCK)) {
				btrfs_err(fs_info,
					   "scrub: tree block %llu spanning "
					   "stripes, ignored. logical=%llu",
				       key.objectid, logical);
				goto next;
			}

again:
			extent_logical = key.objectid;
			extent_len = bytes;

			if (extent_logical < logical) {
				extent_len -= logical - extent_logical;
				extent_logical = logical;
			}
			if (extent_logical + extent_len >
			    logical + map->stripe_len) {
				extent_len = logical + map->stripe_len -
					     extent_logical;
			}

			extent_physical = extent_logical - logical + physical;
			extent_dev = scrub_dev;
			extent_mirror_num = mirror_num;
			if (is_dev_replace)
				scrub_remap_extent(fs_info, extent_logical,
						   extent_len, &extent_physical,
						   &extent_dev,
						   &extent_mirror_num);

			ret = btrfs_lookup_csums_range(csum_root, logical,
						logical + map->stripe_len - 1,
						&sctx->csum_list, 1);
			if (ret)
				goto out;

			ret = scrub_extent(sctx, extent_logical, extent_len,
					   extent_physical, extent_dev, flags,
					   generation, extent_mirror_num,
					   extent_logical - logical + physical);
			if (ret)
				goto out;

			scrub_free_csums(sctx);
			if (extent_logical + extent_len <
			    key.objectid + bytes) {
				if (map->type & (BTRFS_BLOCK_GROUP_RAID5 |
					BTRFS_BLOCK_GROUP_RAID6)) {
					 
					do {
						physical += map->stripe_len;
						ret = get_raid56_logic_offset(
								physical, num,
								map, &logical);
						logical += base;
					} while (physical < physical_end && ret);
				} else {
					physical += map->stripe_len;
					logical += increment;
				}
				if (logical < key.objectid + bytes) {
					cond_resched();
					goto again;
				}

				if (physical >= physical_end) {
					stop_loop = 1;
					break;
				}
			}
next:
			path->slots[0]++;
		}
		btrfs_release_path(path);
skip:
		logical += increment;
		physical += map->stripe_len;
		spin_lock(&sctx->stat_lock);
		if (stop_loop)
			sctx->stat.last_physical = map->stripes[num].physical +
						   length;
		else
			sctx->stat.last_physical = physical;
		spin_unlock(&sctx->stat_lock);
		if (stop_loop)
			break;
	}
out:
	 
	scrub_submit(sctx);
	mutex_lock(&sctx->wr_ctx.wr_lock);
	scrub_wr_submit(sctx);
	mutex_unlock(&sctx->wr_ctx.wr_lock);

	blk_finish_plug(&plug);
	btrfs_free_path(path);
	return ret < 0 ? ret : 0;
}

static noinline_for_stack int scrub_chunk(struct scrub_ctx *sctx,
					  struct btrfs_device *scrub_dev,
					  u64 chunk_tree, u64 chunk_objectid,
					  u64 chunk_offset, u64 length,
					  u64 dev_offset, int is_dev_replace)
{
	struct btrfs_mapping_tree *map_tree =
		&sctx->dev_root->fs_info->mapping_tree;
	struct map_lookup *map;
	struct extent_map *em;
	int i;
	int ret = 0;

	read_lock(&map_tree->map_tree.lock);
	em = lookup_extent_mapping(&map_tree->map_tree, chunk_offset, 1);
	read_unlock(&map_tree->map_tree.lock);

	if (!em)
		return -EINVAL;

	map = (struct map_lookup *)em->bdev;
	if (em->start != chunk_offset)
		goto out;

	if (em->len < length)
		goto out;

	for (i = 0; i < map->num_stripes; ++i) {
		if (map->stripes[i].dev->bdev == scrub_dev->bdev &&
		    map->stripes[i].physical == dev_offset) {
			ret = scrub_stripe(sctx, map, scrub_dev, i,
					   chunk_offset, length,
					   is_dev_replace);
			if (ret)
				goto out;
		}
	}
out:
	free_extent_map(em);

	return ret;
}

static noinline_for_stack
int scrub_enumerate_chunks(struct scrub_ctx *sctx,
			   struct btrfs_device *scrub_dev, u64 start, u64 end,
			   int is_dev_replace)
{
	struct btrfs_dev_extent *dev_extent = NULL;
	struct btrfs_path *path;
	struct btrfs_root *root = sctx->dev_root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	u64 length;
	u64 chunk_tree;
	u64 chunk_objectid;
	u64 chunk_offset;
	int ret;
	int slot;
	struct extent_buffer *l;
	struct btrfs_key key;
	struct btrfs_key found_key;
	struct btrfs_block_group_cache *cache;
	struct btrfs_dev_replace *dev_replace = &fs_info->dev_replace;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->reada = 2;
	path->search_commit_root = 1;
	path->skip_locking = 1;

	key.objectid = scrub_dev->devid;
	key.offset = 0ull;
	key.type = BTRFS_DEV_EXTENT_KEY;

	while (1) {
		ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
		if (ret < 0)
			break;
		if (ret > 0) {
			if (path->slots[0] >=
			    btrfs_header_nritems(path->nodes[0])) {
				ret = btrfs_next_leaf(root, path);
				if (ret)
					break;
			}
		}

		l = path->nodes[0];
		slot = path->slots[0];

		btrfs_item_key_to_cpu(l, &found_key, slot);

		if (found_key.objectid != scrub_dev->devid)
			break;

		if (btrfs_key_type(&found_key) != BTRFS_DEV_EXTENT_KEY)
			break;

		if (found_key.offset >= end)
			break;

		if (found_key.offset < key.offset)
			break;

		dev_extent = btrfs_item_ptr(l, slot, struct btrfs_dev_extent);
		length = btrfs_dev_extent_length(l, dev_extent);

		if (found_key.offset + length <= start)
			goto skip;

		chunk_tree = btrfs_dev_extent_chunk_tree(l, dev_extent);
		chunk_objectid = btrfs_dev_extent_chunk_objectid(l, dev_extent);
		chunk_offset = btrfs_dev_extent_chunk_offset(l, dev_extent);

		cache = btrfs_lookup_block_group(fs_info, chunk_offset);

		if (!cache)
			goto skip;

		dev_replace->cursor_right = found_key.offset + length;
		dev_replace->cursor_left = found_key.offset;
		dev_replace->item_needs_writeback = 1;
		ret = scrub_chunk(sctx, scrub_dev, chunk_tree, chunk_objectid,
				  chunk_offset, length, found_key.offset,
				  is_dev_replace);

		atomic_set(&sctx->wr_ctx.flush_all_writes, 1);
		scrub_submit(sctx);
		mutex_lock(&sctx->wr_ctx.wr_lock);
		scrub_wr_submit(sctx);
		mutex_unlock(&sctx->wr_ctx.wr_lock);

		wait_event(sctx->list_wait,
			   atomic_read(&sctx->bios_in_flight) == 0);
		atomic_inc(&fs_info->scrubs_paused);
		wake_up(&fs_info->scrub_pause_wait);

		wait_event(sctx->list_wait,
			   atomic_read(&sctx->workers_pending) == 0);
		atomic_set(&sctx->wr_ctx.flush_all_writes, 0);

		mutex_lock(&fs_info->scrub_lock);
		__scrub_blocked_if_needed(fs_info);
		atomic_dec(&fs_info->scrubs_paused);
		mutex_unlock(&fs_info->scrub_lock);
		wake_up(&fs_info->scrub_pause_wait);

		btrfs_put_block_group(cache);
		if (ret)
			break;
		if (is_dev_replace &&
		    atomic64_read(&dev_replace->num_write_errors) > 0) {
			ret = -EIO;
			break;
		}
		if (sctx->stat.malloc_errors > 0) {
			ret = -ENOMEM;
			break;
		}

		dev_replace->cursor_left = dev_replace->cursor_right;
		dev_replace->item_needs_writeback = 1;
skip:
		key.offset = found_key.offset + length;
		btrfs_release_path(path);
	}

	btrfs_free_path(path);

	return ret < 0 ? ret : 0;
}

static noinline_for_stack int scrub_supers(struct scrub_ctx *sctx,
					   struct btrfs_device *scrub_dev)
{
	int	i;
	u64	bytenr;
	u64	gen;
	int	ret;
	struct btrfs_root *root = sctx->dev_root;

	if (test_bit(BTRFS_FS_STATE_ERROR, &root->fs_info->fs_state))
		return -EIO;

	gen = root->fs_info->last_trans_committed;

	for (i = 0; i < BTRFS_SUPER_MIRROR_MAX; i++) {
		bytenr = btrfs_sb_offset(i);
		if (bytenr + BTRFS_SUPER_INFO_SIZE > scrub_dev->total_bytes)
			break;

		ret = scrub_pages(sctx, bytenr, BTRFS_SUPER_INFO_SIZE, bytenr,
				  scrub_dev, BTRFS_EXTENT_FLAG_SUPER, gen, i,
				  NULL, 1, bytenr);
		if (ret)
			return ret;
	}
	wait_event(sctx->list_wait, atomic_read(&sctx->bios_in_flight) == 0);

	return 0;
}

static noinline_for_stack int scrub_workers_get(struct btrfs_fs_info *fs_info,
						int is_dev_replace)
{
	int ret = 0;
	int flags = WQ_FREEZABLE | WQ_UNBOUND;
	int max_active = fs_info->thread_pool_size;

	if (fs_info->scrub_workers_refcnt == 0) {
		if (is_dev_replace)
			fs_info->scrub_workers =
				btrfs_alloc_workqueue("btrfs-scrub", flags,
						      1, 4);
		else
			fs_info->scrub_workers =
				btrfs_alloc_workqueue("btrfs-scrub", flags,
						      max_active, 4);
		if (!fs_info->scrub_workers) {
			ret = -ENOMEM;
			goto out;
		}
		fs_info->scrub_wr_completion_workers =
			btrfs_alloc_workqueue("btrfs-scrubwrc", flags,
					      max_active, 2);
		if (!fs_info->scrub_wr_completion_workers) {
			ret = -ENOMEM;
			goto out;
		}
		fs_info->scrub_nocow_workers =
			btrfs_alloc_workqueue("btrfs-scrubnc", flags, 1, 0);
		if (!fs_info->scrub_nocow_workers) {
			ret = -ENOMEM;
			goto out;
		}
	}
	++fs_info->scrub_workers_refcnt;
out:
	return ret;
}

static noinline_for_stack void scrub_workers_put(struct btrfs_fs_info *fs_info)
{
	if (--fs_info->scrub_workers_refcnt == 0) {
		btrfs_destroy_workqueue(fs_info->scrub_workers);
		btrfs_destroy_workqueue(fs_info->scrub_wr_completion_workers);
		btrfs_destroy_workqueue(fs_info->scrub_nocow_workers);
	}
	WARN_ON(fs_info->scrub_workers_refcnt < 0);
}

int btrfs_scrub_dev(struct btrfs_fs_info *fs_info, u64 devid, u64 start,
		    u64 end, struct btrfs_scrub_progress *progress,
		    int readonly, int is_dev_replace)
{
	struct scrub_ctx *sctx;
	int ret;
	struct btrfs_device *dev;

	if (btrfs_fs_closing(fs_info))
		return -EINVAL;

	if (fs_info->chunk_root->nodesize != fs_info->chunk_root->leafsize) {
		btrfs_err(fs_info,
			   "scrub: size assumption nodesize == leafsize (%d == %d) fails",
		       fs_info->chunk_root->nodesize,
		       fs_info->chunk_root->leafsize);
		return -EINVAL;
	}

	if (fs_info->chunk_root->nodesize > BTRFS_STRIPE_LEN) {
		 
		btrfs_err(fs_info,
			   "scrub: size assumption nodesize <= BTRFS_STRIPE_LEN (%d <= %d) fails",
		       fs_info->chunk_root->nodesize, BTRFS_STRIPE_LEN);
		return -EINVAL;
	}

	if (fs_info->chunk_root->sectorsize != PAGE_SIZE) {
		 
		btrfs_err(fs_info,
			   "scrub: size assumption sectorsize != PAGE_SIZE "
			   "(%d != %lu) fails",
		       fs_info->chunk_root->sectorsize, PAGE_SIZE);
		return -EINVAL;
	}

	if (fs_info->chunk_root->nodesize >
	    PAGE_SIZE * SCRUB_MAX_PAGES_PER_BLOCK ||
	    fs_info->chunk_root->sectorsize >
	    PAGE_SIZE * SCRUB_MAX_PAGES_PER_BLOCK) {
		 
		btrfs_err(fs_info, "scrub: size assumption nodesize and sectorsize "
			   "<= SCRUB_MAX_PAGES_PER_BLOCK (%d <= %d && %d <= %d) fails",
		       fs_info->chunk_root->nodesize,
		       SCRUB_MAX_PAGES_PER_BLOCK,
		       fs_info->chunk_root->sectorsize,
		       SCRUB_MAX_PAGES_PER_BLOCK);
		return -EINVAL;
	}

	mutex_lock(&fs_info->fs_devices->device_list_mutex);
	dev = btrfs_find_device(fs_info, devid, NULL, NULL);
	if (!dev || (dev->missing && !is_dev_replace)) {
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		return -ENODEV;
	}

	mutex_lock(&fs_info->scrub_lock);
	if (!dev->in_fs_metadata || dev->is_tgtdev_for_dev_replace) {
		mutex_unlock(&fs_info->scrub_lock);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		return -EIO;
	}

	btrfs_dev_replace_lock(&fs_info->dev_replace);
	if (dev->scrub_device ||
	    (!is_dev_replace &&
	     btrfs_dev_replace_is_ongoing(&fs_info->dev_replace))) {
		btrfs_dev_replace_unlock(&fs_info->dev_replace);
		mutex_unlock(&fs_info->scrub_lock);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		return -EINPROGRESS;
	}
	btrfs_dev_replace_unlock(&fs_info->dev_replace);

	ret = scrub_workers_get(fs_info, is_dev_replace);
	if (ret) {
		mutex_unlock(&fs_info->scrub_lock);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		return ret;
	}

	sctx = scrub_setup_ctx(dev, is_dev_replace);
	if (IS_ERR(sctx)) {
		mutex_unlock(&fs_info->scrub_lock);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
		scrub_workers_put(fs_info);
		return PTR_ERR(sctx);
	}
	sctx->readonly = readonly;
	dev->scrub_device = sctx;
	mutex_unlock(&fs_info->fs_devices->device_list_mutex);

	__scrub_blocked_if_needed(fs_info);
	atomic_inc(&fs_info->scrubs_running);
	mutex_unlock(&fs_info->scrub_lock);

	if (!is_dev_replace) {
		 
		mutex_lock(&fs_info->fs_devices->device_list_mutex);
		ret = scrub_supers(sctx, dev);
		mutex_unlock(&fs_info->fs_devices->device_list_mutex);
	}

	if (!ret)
		ret = scrub_enumerate_chunks(sctx, dev, start, end,
					     is_dev_replace);

	wait_event(sctx->list_wait, atomic_read(&sctx->bios_in_flight) == 0);
	atomic_dec(&fs_info->scrubs_running);
	wake_up(&fs_info->scrub_pause_wait);

	wait_event(sctx->list_wait, atomic_read(&sctx->workers_pending) == 0);

	if (progress)
		memcpy(progress, &sctx->stat, sizeof(*progress));

	mutex_lock(&fs_info->scrub_lock);
	dev->scrub_device = NULL;
	scrub_workers_put(fs_info);
	mutex_unlock(&fs_info->scrub_lock);

	scrub_free_ctx(sctx);

	return ret;
}

void btrfs_scrub_pause(struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;

	mutex_lock(&fs_info->scrub_lock);
	atomic_inc(&fs_info->scrub_pause_req);
	while (atomic_read(&fs_info->scrubs_paused) !=
	       atomic_read(&fs_info->scrubs_running)) {
		mutex_unlock(&fs_info->scrub_lock);
		wait_event(fs_info->scrub_pause_wait,
			   atomic_read(&fs_info->scrubs_paused) ==
			   atomic_read(&fs_info->scrubs_running));
		mutex_lock(&fs_info->scrub_lock);
	}
	mutex_unlock(&fs_info->scrub_lock);
}

void btrfs_scrub_continue(struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;

	atomic_dec(&fs_info->scrub_pause_req);
	wake_up(&fs_info->scrub_pause_wait);
}

int btrfs_scrub_cancel(struct btrfs_fs_info *fs_info)
{
	mutex_lock(&fs_info->scrub_lock);
	if (!atomic_read(&fs_info->scrubs_running)) {
		mutex_unlock(&fs_info->scrub_lock);
		return -ENOTCONN;
	}

	atomic_inc(&fs_info->scrub_cancel_req);
	while (atomic_read(&fs_info->scrubs_running)) {
		mutex_unlock(&fs_info->scrub_lock);
		wait_event(fs_info->scrub_pause_wait,
			   atomic_read(&fs_info->scrubs_running) == 0);
		mutex_lock(&fs_info->scrub_lock);
	}
	atomic_dec(&fs_info->scrub_cancel_req);
	mutex_unlock(&fs_info->scrub_lock);

	return 0;
}

int btrfs_scrub_cancel_dev(struct btrfs_fs_info *fs_info,
			   struct btrfs_device *dev)
{
	struct scrub_ctx *sctx;

	mutex_lock(&fs_info->scrub_lock);
	sctx = dev->scrub_device;
	if (!sctx) {
		mutex_unlock(&fs_info->scrub_lock);
		return -ENOTCONN;
	}
	atomic_inc(&sctx->cancel_req);
	while (dev->scrub_device) {
		mutex_unlock(&fs_info->scrub_lock);
		wait_event(fs_info->scrub_pause_wait,
			   dev->scrub_device == NULL);
		mutex_lock(&fs_info->scrub_lock);
	}
	mutex_unlock(&fs_info->scrub_lock);

	return 0;
}

int btrfs_scrub_progress(struct btrfs_root *root, u64 devid,
			 struct btrfs_scrub_progress *progress)
{
	struct btrfs_device *dev;
	struct scrub_ctx *sctx = NULL;

	mutex_lock(&root->fs_info->fs_devices->device_list_mutex);
	dev = btrfs_find_device(root->fs_info, devid, NULL, NULL);
	if (dev)
		sctx = dev->scrub_device;
	if (sctx)
		memcpy(progress, &sctx->stat, sizeof(*progress));
	mutex_unlock(&root->fs_info->fs_devices->device_list_mutex);

	return dev ? (sctx ? 0 : -ENOTCONN) : -ENODEV;
}

static void scrub_remap_extent(struct btrfs_fs_info *fs_info,
			       u64 extent_logical, u64 extent_len,
			       u64 *extent_physical,
			       struct btrfs_device **extent_dev,
			       int *extent_mirror_num)
{
	u64 mapped_length;
	struct btrfs_bio *bbio = NULL;
	int ret;

	mapped_length = extent_len;
	ret = btrfs_map_block(fs_info, READ, extent_logical,
			      &mapped_length, &bbio, 0);
	if (ret || !bbio || mapped_length < extent_len ||
	    !bbio->stripes[0].dev->bdev) {
		kfree(bbio);
		return;
	}

	*extent_physical = bbio->stripes[0].physical;
	*extent_mirror_num = bbio->mirror_num;
	*extent_dev = bbio->stripes[0].dev;
	kfree(bbio);
}

static int scrub_setup_wr_ctx(struct scrub_ctx *sctx,
			      struct scrub_wr_ctx *wr_ctx,
			      struct btrfs_fs_info *fs_info,
			      struct btrfs_device *dev,
			      int is_dev_replace)
{
	WARN_ON(wr_ctx->wr_curr_bio != NULL);

	mutex_init(&wr_ctx->wr_lock);
	wr_ctx->wr_curr_bio = NULL;
	if (!is_dev_replace)
		return 0;

	WARN_ON(!dev->bdev);
	wr_ctx->pages_per_wr_bio = min_t(int, SCRUB_PAGES_PER_WR_BIO,
					 bio_get_nr_vecs(dev->bdev));
	wr_ctx->tgtdev = dev;
	atomic_set(&wr_ctx->flush_all_writes, 0);
	return 0;
}

static void scrub_free_wr_ctx(struct scrub_wr_ctx *wr_ctx)
{
	mutex_lock(&wr_ctx->wr_lock);
	kfree(wr_ctx->wr_curr_bio);
	wr_ctx->wr_curr_bio = NULL;
	mutex_unlock(&wr_ctx->wr_lock);
}

static int copy_nocow_pages(struct scrub_ctx *sctx, u64 logical, u64 len,
			    int mirror_num, u64 physical_for_dev_replace)
{
	struct scrub_copy_nocow_ctx *nocow_ctx;
	struct btrfs_fs_info *fs_info = sctx->dev_root->fs_info;

	nocow_ctx = kzalloc(sizeof(*nocow_ctx), GFP_NOFS);
	if (!nocow_ctx) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		spin_unlock(&sctx->stat_lock);
		return -ENOMEM;
	}

	scrub_pending_trans_workers_inc(sctx);

	nocow_ctx->sctx = sctx;
	nocow_ctx->logical = logical;
	nocow_ctx->len = len;
	nocow_ctx->mirror_num = mirror_num;
	nocow_ctx->physical_for_dev_replace = physical_for_dev_replace;
	btrfs_init_work(&nocow_ctx->work, btrfs_scrubnc_helper,
			copy_nocow_pages_worker, NULL, NULL);
	INIT_LIST_HEAD(&nocow_ctx->inodes);
	btrfs_queue_work(fs_info->scrub_nocow_workers,
			 &nocow_ctx->work);

	return 0;
}

static int record_inode_for_nocow(u64 inum, u64 offset, u64 root, void *ctx)
{
	struct scrub_copy_nocow_ctx *nocow_ctx = ctx;
	struct scrub_nocow_inode *nocow_inode;

	nocow_inode = kzalloc(sizeof(*nocow_inode), GFP_NOFS);
	if (!nocow_inode)
		return -ENOMEM;
	nocow_inode->inum = inum;
	nocow_inode->offset = offset;
	nocow_inode->root = root;
	list_add_tail(&nocow_inode->list, &nocow_ctx->inodes);
	return 0;
}

#define COPY_COMPLETE 1

static void copy_nocow_pages_worker(struct btrfs_work *work)
{
	struct scrub_copy_nocow_ctx *nocow_ctx =
		container_of(work, struct scrub_copy_nocow_ctx, work);
	struct scrub_ctx *sctx = nocow_ctx->sctx;
	u64 logical = nocow_ctx->logical;
	u64 len = nocow_ctx->len;
	int mirror_num = nocow_ctx->mirror_num;
	u64 physical_for_dev_replace = nocow_ctx->physical_for_dev_replace;
	int ret;
	struct btrfs_trans_handle *trans = NULL;
	struct btrfs_fs_info *fs_info;
	struct btrfs_path *path;
	struct btrfs_root *root;
	int not_written = 0;

	fs_info = sctx->dev_root->fs_info;
	root = fs_info->extent_root;

	path = btrfs_alloc_path();
	if (!path) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		spin_unlock(&sctx->stat_lock);
		not_written = 1;
		goto out;
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		not_written = 1;
		goto out;
	}

	ret = iterate_inodes_from_logical(logical, fs_info, path,
					  record_inode_for_nocow, nocow_ctx);
	if (ret != 0 && ret != -ENOENT) {
		btrfs_warn(fs_info, "iterate_inodes_from_logical() failed: log %llu, "
			"phys %llu, len %llu, mir %u, ret %d",
			logical, physical_for_dev_replace, len, mirror_num,
			ret);
		not_written = 1;
		goto out;
	}

	btrfs_end_transaction(trans, root);
	trans = NULL;
	while (!list_empty(&nocow_ctx->inodes)) {
		struct scrub_nocow_inode *entry;
		entry = list_first_entry(&nocow_ctx->inodes,
					 struct scrub_nocow_inode,
					 list);
		list_del_init(&entry->list);
		ret = copy_nocow_pages_for_inode(entry->inum, entry->offset,
						 entry->root, nocow_ctx);
		kfree(entry);
		if (ret == COPY_COMPLETE) {
			ret = 0;
			break;
		} else if (ret) {
			break;
		}
	}
out:
	while (!list_empty(&nocow_ctx->inodes)) {
		struct scrub_nocow_inode *entry;
		entry = list_first_entry(&nocow_ctx->inodes,
					 struct scrub_nocow_inode,
					 list);
		list_del_init(&entry->list);
		kfree(entry);
	}
	if (trans && !IS_ERR(trans))
		btrfs_end_transaction(trans, root);
	if (not_written)
		btrfs_dev_replace_stats_inc(&fs_info->dev_replace.
					    num_uncorrectable_read_errors);

	btrfs_free_path(path);
	kfree(nocow_ctx);

	scrub_pending_trans_workers_dec(sctx);
}

static int copy_nocow_pages_for_inode(u64 inum, u64 offset, u64 root,
				      struct scrub_copy_nocow_ctx *nocow_ctx)
{
	struct btrfs_fs_info *fs_info = nocow_ctx->sctx->dev_root->fs_info;
	struct btrfs_key key;
	struct inode *inode;
	struct page *page;
	struct btrfs_root *local_root;
	struct btrfs_ordered_extent *ordered;
	struct extent_map *em;
	struct extent_state *cached_state = NULL;
	struct extent_io_tree *io_tree;
	u64 physical_for_dev_replace;
	u64 len = nocow_ctx->len;
	u64 lockstart = offset, lockend = offset + len - 1;
	unsigned long index;
	int srcu_index;
	int ret = 0;
	int err = 0;

	key.objectid = root;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;

	srcu_index = srcu_read_lock(&fs_info->subvol_srcu);

	local_root = btrfs_read_fs_root_no_name(fs_info, &key);
	if (IS_ERR(local_root)) {
		srcu_read_unlock(&fs_info->subvol_srcu, srcu_index);
		return PTR_ERR(local_root);
	}

	key.type = BTRFS_INODE_ITEM_KEY;
	key.objectid = inum;
	key.offset = 0;
	inode = btrfs_iget(fs_info->sb, &key, local_root, NULL);
	srcu_read_unlock(&fs_info->subvol_srcu, srcu_index);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	mutex_lock(&inode->i_mutex);
	inode_dio_wait(inode);

	physical_for_dev_replace = nocow_ctx->physical_for_dev_replace;
	io_tree = &BTRFS_I(inode)->io_tree;

	lock_extent_bits(io_tree, lockstart, lockend, 0, &cached_state);
	ordered = btrfs_lookup_ordered_range(inode, lockstart, len);
	if (ordered) {
		btrfs_put_ordered_extent(ordered);
		goto out_unlock;
	}

	em = btrfs_get_extent(inode, NULL, 0, lockstart, len, 0);
	if (IS_ERR(em)) {
		ret = PTR_ERR(em);
		goto out_unlock;
	}

	if (em->block_start > nocow_ctx->logical ||
	    em->block_start + em->block_len < nocow_ctx->logical + len) {
		free_extent_map(em);
		goto out_unlock;
	}
	free_extent_map(em);

	while (len >= PAGE_CACHE_SIZE) {
		index = offset >> PAGE_CACHE_SHIFT;
again:
		page = find_or_create_page(inode->i_mapping, index, GFP_NOFS);
		if (!page) {
			btrfs_err(fs_info, "find_or_create_page() failed");
			ret = -ENOMEM;
			goto out;
		}

		if (PageUptodate(page)) {
			if (PageDirty(page))
				goto next_page;
		} else {
			ClearPageError(page);
			err = extent_read_full_page_nolock(io_tree, page,
							   btrfs_get_extent,
							   nocow_ctx->mirror_num);
			if (err) {
				ret = err;
				goto next_page;
			}

			lock_page(page);
			 
			if (page->mapping != inode->i_mapping) {
				unlock_page(page);
				page_cache_release(page);
				goto again;
			}
			if (!PageUptodate(page)) {
				ret = -EIO;
				goto next_page;
			}
		}
		err = write_page_nocow(nocow_ctx->sctx,
				       physical_for_dev_replace, page);
		if (err)
			ret = err;
next_page:
		unlock_page(page);
		page_cache_release(page);

		if (ret)
			break;

		offset += PAGE_CACHE_SIZE;
		physical_for_dev_replace += PAGE_CACHE_SIZE;
		len -= PAGE_CACHE_SIZE;
	}
	ret = COPY_COMPLETE;
out_unlock:
	unlock_extent_cached(io_tree, lockstart, lockend, &cached_state,
			     GFP_NOFS);
out:
	mutex_unlock(&inode->i_mutex);
	iput(inode);
	return ret;
}

static int write_page_nocow(struct scrub_ctx *sctx,
			    u64 physical_for_dev_replace, struct page *page)
{
	struct bio *bio;
	struct btrfs_device *dev;
	int ret;
	DECLARE_COMPLETION_ONSTACK(compl);

	dev = sctx->wr_ctx.tgtdev;
	if (!dev)
		return -EIO;
	if (!dev->bdev) {
		printk_ratelimited(KERN_WARNING
			"BTRFS: scrub write_page_nocow(bdev == NULL) is unexpected!\n");
		return -EIO;
	}
	bio = btrfs_io_bio_alloc(GFP_NOFS, 1);
	if (!bio) {
		spin_lock(&sctx->stat_lock);
		sctx->stat.malloc_errors++;
		spin_unlock(&sctx->stat_lock);
		return -ENOMEM;
	}
	bio->bi_private = &compl;
	bio->bi_end_io = scrub_complete_bio_end_io;
	bio->bi_size = 0;
	bio->bi_sector = physical_for_dev_replace >> 9;
	bio->bi_bdev = dev->bdev;
	ret = bio_add_page(bio, page, PAGE_CACHE_SIZE, 0);
	if (ret != PAGE_CACHE_SIZE) {
leave_with_eio:
		bio_put(bio);
		btrfs_dev_stat_inc_and_print(dev, BTRFS_DEV_STAT_WRITE_ERRS);
		return -EIO;
	}
	btrfsic_submit_bio(WRITE_SYNC, bio);
	wait_for_completion(&compl);

	if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
		goto leave_with_eio;

	bio_put(bio);
	return 0;
}
