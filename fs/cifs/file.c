#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/fs.h>
#include <linux/backing-dev.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/writeback.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/delay.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <asm/div64.h>
#include "cifsfs.h"
#include "cifspdu.h"
#include "cifsglob.h"
#include "cifsproto.h"
#include "cifs_unicode.h"
#include "cifs_debug.h"
#include "cifs_fs_sb.h"
#include "fscache.h"

static inline int cifs_convert_flags(unsigned int flags)
{
	if ((flags & O_ACCMODE) == O_RDONLY)
		return GENERIC_READ;
	else if ((flags & O_ACCMODE) == O_WRONLY)
		return GENERIC_WRITE;
	else if ((flags & O_ACCMODE) == O_RDWR) {
		 
		return (GENERIC_READ | GENERIC_WRITE);
	}

	return (READ_CONTROL | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES |
		FILE_WRITE_EA | FILE_APPEND_DATA | FILE_WRITE_DATA |
		FILE_READ_DATA);
}

static u32 cifs_posix_convert_flags(unsigned int flags)
{
	u32 posix_flags = 0;

	if ((flags & O_ACCMODE) == O_RDONLY)
		posix_flags = SMB_O_RDONLY;
	else if ((flags & O_ACCMODE) == O_WRONLY)
		posix_flags = SMB_O_WRONLY;
	else if ((flags & O_ACCMODE) == O_RDWR)
		posix_flags = SMB_O_RDWR;

	if (flags & O_CREAT) {
		posix_flags |= SMB_O_CREAT;
		if (flags & O_EXCL)
			posix_flags |= SMB_O_EXCL;
	} else if (flags & O_EXCL)
		cifs_dbg(FYI, "Application %s pid %d has incorrectly set O_EXCL flag but not O_CREAT on file open. Ignoring O_EXCL\n",
			 current->comm, current->tgid);

	if (flags & O_TRUNC)
		posix_flags |= SMB_O_TRUNC;
	 
	if (flags & O_DSYNC)
		posix_flags |= SMB_O_SYNC;
	if (flags & O_DIRECTORY)
		posix_flags |= SMB_O_DIRECTORY;
	if (flags & O_NOFOLLOW)
		posix_flags |= SMB_O_NOFOLLOW;
	if (flags & O_DIRECT)
		posix_flags |= SMB_O_DIRECT;

	return posix_flags;
}

static inline int cifs_get_disposition(unsigned int flags)
{
	if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
		return FILE_CREATE;
	else if ((flags & (O_CREAT | O_TRUNC)) == (O_CREAT | O_TRUNC))
		return FILE_OVERWRITE_IF;
	else if ((flags & O_CREAT) == O_CREAT)
		return FILE_OPEN_IF;
	else if ((flags & O_TRUNC) == O_TRUNC)
		return FILE_OVERWRITE;
	else
		return FILE_OPEN;
}

int cifs_posix_open(char *full_path, struct inode **pinode,
			struct super_block *sb, int mode, unsigned int f_flags,
			__u32 *poplock, __u16 *pnetfid, unsigned int xid)
{
	int rc;
	FILE_UNIX_BASIC_INFO *presp_data;
	__u32 posix_flags = 0;
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	struct cifs_fattr fattr;
	struct tcon_link *tlink;
	struct cifs_tcon *tcon;

	cifs_dbg(FYI, "posix open %s\n", full_path);

	presp_data = kzalloc(sizeof(FILE_UNIX_BASIC_INFO), GFP_KERNEL);
	if (presp_data == NULL)
		return -ENOMEM;

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink)) {
		rc = PTR_ERR(tlink);
		goto posix_open_ret;
	}

	tcon = tlink_tcon(tlink);
	mode &= ~current_umask();

	posix_flags = cifs_posix_convert_flags(f_flags);
	rc = CIFSPOSIXCreate(xid, tcon, posix_flags, mode, pnetfid, presp_data,
			     poplock, full_path, cifs_sb->local_nls,
			     cifs_sb->mnt_cifs_flags &
					CIFS_MOUNT_MAP_SPECIAL_CHR);
	cifs_put_tlink(tlink);

	if (rc)
		goto posix_open_ret;

	if (presp_data->Type == cpu_to_le32(-1))
		goto posix_open_ret;  

	if (!pinode)
		goto posix_open_ret;  

	cifs_unix_basic_to_fattr(&fattr, presp_data, cifs_sb);

	if (*pinode == NULL) {
		cifs_fill_uniqueid(sb, &fattr);
		*pinode = cifs_iget(sb, &fattr);
		if (!*pinode) {
			rc = -ENOMEM;
			goto posix_open_ret;
		}
	} else {
		cifs_fattr_to_inode(*pinode, &fattr);
	}

posix_open_ret:
	kfree(presp_data);
	return rc;
}

static int
cifs_nt_open(char *full_path, struct inode *inode, struct cifs_sb_info *cifs_sb,
	     struct cifs_tcon *tcon, unsigned int f_flags, __u32 *oplock,
	     struct cifs_fid *fid, unsigned int xid)
{
	int rc;
	int desired_access;
	int disposition;
	int create_options = CREATE_NOT_DIR;
	FILE_ALL_INFO *buf;
	struct TCP_Server_Info *server = tcon->ses->server;

	if (!server->ops->open)
		return -ENOSYS;

	desired_access = cifs_convert_flags(f_flags);

	disposition = cifs_get_disposition(f_flags);

	buf = kmalloc(sizeof(FILE_ALL_INFO), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (backup_cred(cifs_sb))
		create_options |= CREATE_OPEN_BACKUP_INTENT;

	rc = server->ops->open(xid, tcon, full_path, disposition,
			       desired_access, create_options, fid, oplock, buf,
			       cifs_sb);

	if (rc)
		goto out;

	if (tcon->unix_ext)
		rc = cifs_get_inode_info_unix(&inode, full_path, inode->i_sb,
					      xid);
	else
		rc = cifs_get_inode_info(&inode, full_path, buf, inode->i_sb,
					 xid, &fid->netfid);

out:
	kfree(buf);
	return rc;
}

static bool
cifs_has_mand_locks(struct cifsInodeInfo *cinode)
{
	struct cifs_fid_locks *cur;
	bool has_locks = false;

	down_read(&cinode->lock_sem);
	list_for_each_entry(cur, &cinode->llist, llist) {
		if (!list_empty(&cur->locks)) {
			has_locks = true;
			break;
		}
	}
	up_read(&cinode->lock_sem);
	return has_locks;
}

struct cifsFileInfo *
cifs_new_fileinfo(struct cifs_fid *fid, struct file *file,
		  struct tcon_link *tlink, __u32 oplock)
{
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct cifsFileInfo *cfile;
	struct cifs_fid_locks *fdlocks;
	struct cifs_tcon *tcon = tlink_tcon(tlink);
	struct TCP_Server_Info *server = tcon->ses->server;

	cfile = kzalloc(sizeof(struct cifsFileInfo), GFP_KERNEL);
	if (cfile == NULL)
		return cfile;

	fdlocks = kzalloc(sizeof(struct cifs_fid_locks), GFP_KERNEL);
	if (!fdlocks) {
		kfree(cfile);
		return NULL;
	}

	INIT_LIST_HEAD(&fdlocks->locks);
	fdlocks->cfile = cfile;
	cfile->llist = fdlocks;
	down_write(&cinode->lock_sem);
	list_add(&fdlocks->llist, &cinode->llist);
	up_write(&cinode->lock_sem);

	cfile->count = 1;
	cfile->pid = current->tgid;
	cfile->uid = current_fsuid();
	cfile->dentry = dget(dentry);
	cfile->f_flags = file->f_flags;
	cfile->invalidHandle = false;
	cfile->tlink = cifs_get_tlink(tlink);
	INIT_WORK(&cfile->oplock_break, cifs_oplock_break);
	mutex_init(&cfile->fh_mutex);

	cifs_sb_active(inode->i_sb);

	if (oplock == server->vals->oplock_read &&
						cifs_has_mand_locks(cinode)) {
		cifs_dbg(FYI, "Reset oplock val from read to None due to mand locks\n");
		oplock = 0;
	}

	spin_lock(&cifs_file_list_lock);
	if (fid->pending_open->oplock != CIFS_OPLOCK_NO_CHANGE && oplock)
		oplock = fid->pending_open->oplock;
	list_del(&fid->pending_open->olist);

	server->ops->set_fid(cfile, fid, oplock);

	list_add(&cfile->tlist, &tcon->openFileList);
	 
	if (file->f_mode & FMODE_READ)
		list_add(&cfile->flist, &cinode->openFileList);
	else
		list_add_tail(&cfile->flist, &cinode->openFileList);
	spin_unlock(&cifs_file_list_lock);

	file->private_data = cfile;
	return cfile;
}

struct cifsFileInfo *
cifsFileInfo_get(struct cifsFileInfo *cifs_file)
{
	spin_lock(&cifs_file_list_lock);
	cifsFileInfo_get_locked(cifs_file);
	spin_unlock(&cifs_file_list_lock);
	return cifs_file;
}

void cifsFileInfo_put(struct cifsFileInfo *cifs_file)
{
	struct inode *inode = cifs_file->dentry->d_inode;
	struct cifs_tcon *tcon = tlink_tcon(cifs_file->tlink);
	struct TCP_Server_Info *server = tcon->ses->server;
	struct cifsInodeInfo *cifsi = CIFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	struct cifsLockInfo *li, *tmp;
	struct cifs_fid fid;
	struct cifs_pending_open open;

	spin_lock(&cifs_file_list_lock);
	if (--cifs_file->count > 0) {
		spin_unlock(&cifs_file_list_lock);
		return;
	}

	if (server->ops->get_lease_key)
		server->ops->get_lease_key(inode, &fid);

	cifs_add_pending_open_locked(&fid, cifs_file->tlink, &open);

	list_del(&cifs_file->flist);
	list_del(&cifs_file->tlist);

	if (list_empty(&cifsi->openFileList)) {
		cifs_dbg(FYI, "closing last open instance for inode %p\n",
			 cifs_file->dentry->d_inode);
		 
		if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_STRICT_IO)
			CIFS_I(inode)->invalid_mapping = true;
		cifs_set_oplock_level(cifsi, 0);
	}
	spin_unlock(&cifs_file_list_lock);

	cancel_work_sync(&cifs_file->oplock_break);

	if (!tcon->need_reconnect && !cifs_file->invalidHandle) {
		struct TCP_Server_Info *server = tcon->ses->server;
		unsigned int xid;

		xid = get_xid();
		if (server->ops->close)
			server->ops->close(xid, tcon, &cifs_file->fid);
		_free_xid(xid);
	}

	cifs_del_pending_open(&open);

	down_write(&cifsi->lock_sem);
	list_for_each_entry_safe(li, tmp, &cifs_file->llist->locks, llist) {
		list_del(&li->llist);
		cifs_del_lock_waiters(li);
		kfree(li);
	}
	list_del(&cifs_file->llist->llist);
	kfree(cifs_file->llist);
	up_write(&cifsi->lock_sem);

	cifs_put_tlink(cifs_file->tlink);
	dput(cifs_file->dentry);
	cifs_sb_deactive(sb);
	kfree(cifs_file);
}

int cifs_open(struct inode *inode, struct file *file)

{
	int rc = -EACCES;
	unsigned int xid;
	__u32 oplock;
	struct cifs_sb_info *cifs_sb;
	struct TCP_Server_Info *server;
	struct cifs_tcon *tcon;
	struct tcon_link *tlink;
	struct cifsFileInfo *cfile = NULL;
	char *full_path = NULL;
	bool posix_open_ok = false;
	struct cifs_fid fid;
	struct cifs_pending_open open;

	xid = get_xid();

	cifs_sb = CIFS_SB(inode->i_sb);
	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink)) {
		free_xid(xid);
		return PTR_ERR(tlink);
	}
	tcon = tlink_tcon(tlink);
	server = tcon->ses->server;

	full_path = build_path_from_dentry(file->f_path.dentry);
	if (full_path == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	cifs_dbg(FYI, "inode = 0x%p file flags are 0x%x for %s\n",
		 inode, file->f_flags, full_path);

	if (server->oplocks)
		oplock = REQ_OPLOCK;
	else
		oplock = 0;

	if (!tcon->broken_posix_open && tcon->unix_ext &&
	    cap_unix(tcon->ses) && (CIFS_UNIX_POSIX_PATH_OPS_CAP &
				le64_to_cpu(tcon->fsUnixInfo.Capability))) {
		 
		rc = cifs_posix_open(full_path, &inode, inode->i_sb,
				cifs_sb->mnt_file_mode  ,
				file->f_flags, &oplock, &fid.netfid, xid);
		if (rc == 0) {
			cifs_dbg(FYI, "posix open succeeded\n");
			posix_open_ok = true;
		} else if ((rc == -EINVAL) || (rc == -EOPNOTSUPP)) {
			if (tcon->ses->serverNOS)
				cifs_dbg(VFS, "server %s of type %s returned unexpected error on SMB posix open, disabling posix open support. Check if server update available.\n",
					 tcon->ses->serverName,
					 tcon->ses->serverNOS);
			tcon->broken_posix_open = true;
		} else if ((rc != -EIO) && (rc != -EREMOTE) &&
			 (rc != -EOPNOTSUPP))  
			goto out;
		 
	}

	if (server->ops->get_lease_key)
		server->ops->get_lease_key(inode, &fid);

	cifs_add_pending_open(&fid, tlink, &open);

	if (!posix_open_ok) {
		if (server->ops->get_lease_key)
			server->ops->get_lease_key(inode, &fid);

		rc = cifs_nt_open(full_path, inode, cifs_sb, tcon,
				  file->f_flags, &oplock, &fid, xid);
		if (rc) {
			cifs_del_pending_open(&open);
			goto out;
		}
	}

	cfile = cifs_new_fileinfo(&fid, file, tlink, oplock);
	if (cfile == NULL) {
		if (server->ops->close)
			server->ops->close(xid, tcon, &fid);
		cifs_del_pending_open(&open);
		rc = -ENOMEM;
		goto out;
	}

	cifs_fscache_set_inode_cookie(inode, file);

	if ((oplock & CIFS_CREATE_ACTION) && !posix_open_ok && tcon->unix_ext) {
		 
		struct cifs_unix_set_info_args args = {
			.mode	= inode->i_mode,
			.uid	= INVALID_UID,  
			.gid	= INVALID_GID,  
			.ctime	= NO_CHANGE_64,
			.atime	= NO_CHANGE_64,
			.mtime	= NO_CHANGE_64,
			.device	= 0,
		};
		CIFSSMBUnixSetFileInfo(xid, tcon, &args, fid.netfid,
				       cfile->pid);
	}

out:
	kfree(full_path);
	free_xid(xid);
	cifs_put_tlink(tlink);
	return rc;
}

static int cifs_push_posix_locks(struct cifsFileInfo *cfile);

static int
cifs_relock_file(struct cifsFileInfo *cfile)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(cfile->dentry->d_sb);
	struct cifsInodeInfo *cinode = CIFS_I(cfile->dentry->d_inode);
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	int rc = 0;

	down_read(&cinode->lock_sem);
	if (cinode->can_cache_brlcks) {
		 
		up_read(&cinode->lock_sem);
		return rc;
	}

	if (cap_unix(tcon->ses) &&
	    (CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability)) &&
	    ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0))
		rc = cifs_push_posix_locks(cfile);
	else
		rc = tcon->ses->server->ops->push_mand_locks(cfile);

	up_read(&cinode->lock_sem);
	return rc;
}

static int
cifs_reopen_file(struct cifsFileInfo *cfile, bool can_flush)
{
	int rc = -EACCES;
	unsigned int xid;
	__u32 oplock;
	struct cifs_sb_info *cifs_sb;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	struct cifsInodeInfo *cinode;
	struct inode *inode;
	char *full_path = NULL;
	int desired_access;
	int disposition = FILE_OPEN;
	int create_options = CREATE_NOT_DIR;
	struct cifs_fid fid;

	xid = get_xid();
	mutex_lock(&cfile->fh_mutex);
	if (!cfile->invalidHandle) {
		mutex_unlock(&cfile->fh_mutex);
		rc = 0;
		free_xid(xid);
		return rc;
	}

	inode = cfile->dentry->d_inode;
	cifs_sb = CIFS_SB(inode->i_sb);
	tcon = tlink_tcon(cfile->tlink);
	server = tcon->ses->server;

	full_path = build_path_from_dentry(cfile->dentry);
	if (full_path == NULL) {
		rc = -ENOMEM;
		mutex_unlock(&cfile->fh_mutex);
		free_xid(xid);
		return rc;
	}

	cifs_dbg(FYI, "inode = 0x%p file flags 0x%x for %s\n",
		 inode, cfile->f_flags, full_path);

	if (tcon->ses->server->oplocks)
		oplock = REQ_OPLOCK;
	else
		oplock = 0;

	if (tcon->unix_ext && cap_unix(tcon->ses) &&
	    (CIFS_UNIX_POSIX_PATH_OPS_CAP &
				le64_to_cpu(tcon->fsUnixInfo.Capability))) {
		 
		unsigned int oflags = cfile->f_flags &
						~(O_CREAT | O_EXCL | O_TRUNC);

		rc = cifs_posix_open(full_path, NULL, inode->i_sb,
				     cifs_sb->mnt_file_mode  ,
				     oflags, &oplock, &fid.netfid, xid);
		if (rc == 0) {
			cifs_dbg(FYI, "posix reopen succeeded\n");
			goto reopen_success;
		}
		 
	}

	desired_access = cifs_convert_flags(cfile->f_flags);

	if (backup_cred(cifs_sb))
		create_options |= CREATE_OPEN_BACKUP_INTENT;

	if (server->ops->get_lease_key)
		server->ops->get_lease_key(inode, &fid);

	rc = server->ops->open(xid, tcon, full_path, disposition,
			       desired_access, create_options, &fid, &oplock,
			       NULL, cifs_sb);
	if (rc) {
		mutex_unlock(&cfile->fh_mutex);
		cifs_dbg(FYI, "cifs_reopen returned 0x%x\n", rc);
		cifs_dbg(FYI, "oplock: %d\n", oplock);
		goto reopen_error_exit;
	}

reopen_success:
	cfile->invalidHandle = false;
	mutex_unlock(&cfile->fh_mutex);
	cinode = CIFS_I(inode);

	if (can_flush) {
		rc = filemap_write_and_wait(inode->i_mapping);
		mapping_set_error(inode->i_mapping, rc);

		if (tcon->unix_ext)
			rc = cifs_get_inode_info_unix(&inode, full_path,
						      inode->i_sb, xid);
		else
			rc = cifs_get_inode_info(&inode, full_path, NULL,
						 inode->i_sb, xid, NULL);
	}
	 
	server->ops->set_fid(cfile, &fid, oplock);
	cifs_relock_file(cfile);

reopen_error_exit:
	kfree(full_path);
	free_xid(xid);
	return rc;
}

int cifs_close(struct inode *inode, struct file *file)
{
	if (file->private_data != NULL) {
		cifsFileInfo_put(file->private_data);
		file->private_data = NULL;
	}

	return 0;
}

int cifs_closedir(struct inode *inode, struct file *file)
{
	int rc = 0;
	unsigned int xid;
	struct cifsFileInfo *cfile = file->private_data;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	char *buf;

	cifs_dbg(FYI, "Closedir inode = 0x%p\n", inode);

	if (cfile == NULL)
		return rc;

	xid = get_xid();
	tcon = tlink_tcon(cfile->tlink);
	server = tcon->ses->server;

	cifs_dbg(FYI, "Freeing private data in close dir\n");
	spin_lock(&cifs_file_list_lock);
	if (server->ops->dir_needs_close(cfile)) {
		cfile->invalidHandle = true;
		spin_unlock(&cifs_file_list_lock);
		if (server->ops->close_dir)
			rc = server->ops->close_dir(xid, tcon, &cfile->fid);
		else
			rc = -ENOSYS;
		cifs_dbg(FYI, "Closing uncompleted readdir with rc %d\n", rc);
		 
		rc = 0;
	} else
		spin_unlock(&cifs_file_list_lock);

	buf = cfile->srch_inf.ntwrk_buf_start;
	if (buf) {
		cifs_dbg(FYI, "closedir free smb buf in srch struct\n");
		cfile->srch_inf.ntwrk_buf_start = NULL;
		if (cfile->srch_inf.smallBuf)
			cifs_small_buf_release(buf);
		else
			cifs_buf_release(buf);
	}

	cifs_put_tlink(cfile->tlink);
	kfree(file->private_data);
	file->private_data = NULL;
	 
	free_xid(xid);
	return rc;
}

static struct cifsLockInfo *
cifs_lock_init(__u64 offset, __u64 length, __u8 type)
{
	struct cifsLockInfo *lock =
		kmalloc(sizeof(struct cifsLockInfo), GFP_KERNEL);
	if (!lock)
		return lock;
	lock->offset = offset;
	lock->length = length;
	lock->type = type;
	lock->pid = current->tgid;
	INIT_LIST_HEAD(&lock->blist);
	init_waitqueue_head(&lock->block_q);
	return lock;
}

void
cifs_del_lock_waiters(struct cifsLockInfo *lock)
{
	struct cifsLockInfo *li, *tmp;
	list_for_each_entry_safe(li, tmp, &lock->blist, blist) {
		list_del_init(&li->blist);
		wake_up(&li->block_q);
	}
}

#define CIFS_LOCK_OP	0
#define CIFS_READ_OP	1
#define CIFS_WRITE_OP	2

static bool
cifs_find_fid_lock_conflict(struct cifs_fid_locks *fdlocks, __u64 offset,
			    __u64 length, __u8 type, struct cifsFileInfo *cfile,
			    struct cifsLockInfo **conf_lock, int rw_check)
{
	struct cifsLockInfo *li;
	struct cifsFileInfo *cur_cfile = fdlocks->cfile;
	struct TCP_Server_Info *server = tlink_tcon(cfile->tlink)->ses->server;

	list_for_each_entry(li, &fdlocks->locks, llist) {
		if (offset + length <= li->offset ||
		    offset >= li->offset + li->length)
			continue;
		if (rw_check != CIFS_LOCK_OP && current->tgid == li->pid &&
		    server->ops->compare_fids(cfile, cur_cfile)) {
			 
			if (!(li->type & server->vals->shared_lock_type) ||
			    rw_check != CIFS_WRITE_OP)
				continue;
		}
		if ((type & server->vals->shared_lock_type) &&
		    ((server->ops->compare_fids(cfile, cur_cfile) &&
		     current->tgid == li->pid) || type == li->type))
			continue;
		if (conf_lock)
			*conf_lock = li;
		return true;
	}
	return false;
}

bool
cifs_find_lock_conflict(struct cifsFileInfo *cfile, __u64 offset, __u64 length,
			__u8 type, struct cifsLockInfo **conf_lock,
			int rw_check)
{
	bool rc = false;
	struct cifs_fid_locks *cur;
	struct cifsInodeInfo *cinode = CIFS_I(cfile->dentry->d_inode);

	list_for_each_entry(cur, &cinode->llist, llist) {
		rc = cifs_find_fid_lock_conflict(cur, offset, length, type,
						 cfile, conf_lock, rw_check);
		if (rc)
			break;
	}

	return rc;
}

static int
cifs_lock_test(struct cifsFileInfo *cfile, __u64 offset, __u64 length,
	       __u8 type, struct file_lock *flock)
{
	int rc = 0;
	struct cifsLockInfo *conf_lock;
	struct cifsInodeInfo *cinode = CIFS_I(cfile->dentry->d_inode);
	struct TCP_Server_Info *server = tlink_tcon(cfile->tlink)->ses->server;
	bool exist;

	down_read(&cinode->lock_sem);

	exist = cifs_find_lock_conflict(cfile, offset, length, type,
					&conf_lock, CIFS_LOCK_OP);
	if (exist) {
		flock->fl_start = conf_lock->offset;
		flock->fl_end = conf_lock->offset + conf_lock->length - 1;
		flock->fl_pid = conf_lock->pid;
		if (conf_lock->type & server->vals->shared_lock_type)
			flock->fl_type = F_RDLCK;
		else
			flock->fl_type = F_WRLCK;
	} else if (!cinode->can_cache_brlcks)
		rc = 1;
	else
		flock->fl_type = F_UNLCK;

	up_read(&cinode->lock_sem);
	return rc;
}

static void
cifs_lock_add(struct cifsFileInfo *cfile, struct cifsLockInfo *lock)
{
	struct cifsInodeInfo *cinode = CIFS_I(cfile->dentry->d_inode);
	down_write(&cinode->lock_sem);
	list_add_tail(&lock->llist, &cfile->llist->locks);
	up_write(&cinode->lock_sem);
}

static int
cifs_lock_add_if(struct cifsFileInfo *cfile, struct cifsLockInfo *lock,
		 bool wait)
{
	struct cifsLockInfo *conf_lock;
	struct cifsInodeInfo *cinode = CIFS_I(cfile->dentry->d_inode);
	bool exist;
	int rc = 0;

try_again:
	exist = false;
	down_write(&cinode->lock_sem);

	exist = cifs_find_lock_conflict(cfile, lock->offset, lock->length,
					lock->type, &conf_lock, CIFS_LOCK_OP);
	if (!exist && cinode->can_cache_brlcks) {
		list_add_tail(&lock->llist, &cfile->llist->locks);
		up_write(&cinode->lock_sem);
		return rc;
	}

	if (!exist)
		rc = 1;
	else if (!wait)
		rc = -EACCES;
	else {
		list_add_tail(&lock->blist, &conf_lock->blist);
		up_write(&cinode->lock_sem);
		rc = wait_event_interruptible(lock->block_q,
					(lock->blist.prev == &lock->blist) &&
					(lock->blist.next == &lock->blist));
		if (!rc)
			goto try_again;
		down_write(&cinode->lock_sem);
		list_del_init(&lock->blist);
	}

	up_write(&cinode->lock_sem);
	return rc;
}

static int
cifs_posix_lock_test(struct file *file, struct file_lock *flock)
{
	int rc = 0;
	struct cifsInodeInfo *cinode = CIFS_I(file_inode(file));
	unsigned char saved_type = flock->fl_type;

	if ((flock->fl_flags & FL_POSIX) == 0)
		return 1;

	down_read(&cinode->lock_sem);
	posix_test_lock(file, flock);

	if (flock->fl_type == F_UNLCK && !cinode->can_cache_brlcks) {
		flock->fl_type = saved_type;
		rc = 1;
	}

	up_read(&cinode->lock_sem);
	return rc;
}

static int
cifs_posix_lock_set(struct file *file, struct file_lock *flock)
{
	struct cifsInodeInfo *cinode = CIFS_I(file_inode(file));
	int rc = 1;

	if ((flock->fl_flags & FL_POSIX) == 0)
		return rc;

try_again:
	down_write(&cinode->lock_sem);
	if (!cinode->can_cache_brlcks) {
		up_write(&cinode->lock_sem);
		return rc;
	}

	rc = posix_lock_file(file, flock, NULL);
	up_write(&cinode->lock_sem);
	if (rc == FILE_LOCK_DEFERRED) {
		rc = wait_event_interruptible(flock->fl_wait, !flock->fl_next);
		if (!rc)
			goto try_again;
		locks_delete_block(flock);
	}
	return rc;
}

int
cifs_push_mandatory_locks(struct cifsFileInfo *cfile)
{
	unsigned int xid;
	int rc = 0, stored_rc;
	struct cifsLockInfo *li, *tmp;
	struct cifs_tcon *tcon;
	unsigned int num, max_num, max_buf;
	LOCKING_ANDX_RANGE *buf, *cur;
	int types[] = {LOCKING_ANDX_LARGE_FILES,
		       LOCKING_ANDX_SHARED_LOCK | LOCKING_ANDX_LARGE_FILES};
	int i;

	xid = get_xid();
	tcon = tlink_tcon(cfile->tlink);

	max_buf = tcon->ses->server->maxBuf;
	if (!max_buf) {
		free_xid(xid);
		return -EINVAL;
	}

	max_num = (max_buf - sizeof(struct smb_hdr)) /
						sizeof(LOCKING_ANDX_RANGE);
	buf = kzalloc(max_num * sizeof(LOCKING_ANDX_RANGE), GFP_KERNEL);
	if (!buf) {
		free_xid(xid);
		return -ENOMEM;
	}

	for (i = 0; i < 2; i++) {
		cur = buf;
		num = 0;
		list_for_each_entry_safe(li, tmp, &cfile->llist->locks, llist) {
			if (li->type != types[i])
				continue;
			cur->Pid = cpu_to_le16(li->pid);
			cur->LengthLow = cpu_to_le32((u32)li->length);
			cur->LengthHigh = cpu_to_le32((u32)(li->length>>32));
			cur->OffsetLow = cpu_to_le32((u32)li->offset);
			cur->OffsetHigh = cpu_to_le32((u32)(li->offset>>32));
			if (++num == max_num) {
				stored_rc = cifs_lockv(xid, tcon,
						       cfile->fid.netfid,
						       (__u8)li->type, 0, num,
						       buf);
				if (stored_rc)
					rc = stored_rc;
				cur = buf;
				num = 0;
			} else
				cur++;
		}

		if (num) {
			stored_rc = cifs_lockv(xid, tcon, cfile->fid.netfid,
					       (__u8)types[i], 0, num, buf);
			if (stored_rc)
				rc = stored_rc;
		}
	}

	kfree(buf);
	free_xid(xid);
	return rc;
}

#define cifs_for_each_lock(inode, lockp) \
	for (lockp = &inode->i_flock; *lockp != NULL; \
	     lockp = &(*lockp)->fl_next)

struct lock_to_push {
	struct list_head llist;
	__u64 offset;
	__u64 length;
	__u32 pid;
	__u16 netfid;
	__u8 type;
};

static int
cifs_push_posix_locks(struct cifsFileInfo *cfile)
{
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	struct file_lock *flock, **before;
	unsigned int count = 0, i = 0;
	int rc = 0, xid, type;
	struct list_head locks_to_send, *el;
	struct lock_to_push *lck, *tmp;
	__u64 length;

	xid = get_xid();

	lock_flocks();
	cifs_for_each_lock(cfile->dentry->d_inode, before) {
		if ((*before)->fl_flags & FL_POSIX)
			count++;
	}
	unlock_flocks();

	INIT_LIST_HEAD(&locks_to_send);

	for (; i < count; i++) {
		lck = kmalloc(sizeof(struct lock_to_push), GFP_KERNEL);
		if (!lck) {
			rc = -ENOMEM;
			goto err_out;
		}
		list_add_tail(&lck->llist, &locks_to_send);
	}

	el = locks_to_send.next;
	lock_flocks();
	cifs_for_each_lock(cfile->dentry->d_inode, before) {
		flock = *before;
		if ((flock->fl_flags & FL_POSIX) == 0)
			continue;
		if (el == &locks_to_send) {
			 
			cifs_dbg(VFS, "Can't push all brlocks!\n");
			break;
		}
		length = 1 + flock->fl_end - flock->fl_start;
		if (flock->fl_type == F_RDLCK || flock->fl_type == F_SHLCK)
			type = CIFS_RDLCK;
		else
			type = CIFS_WRLCK;
		lck = list_entry(el, struct lock_to_push, llist);
		lck->pid = flock->fl_pid;
		lck->netfid = cfile->fid.netfid;
		lck->length = length;
		lck->type = type;
		lck->offset = flock->fl_start;
		el = el->next;
	}
	unlock_flocks();

	list_for_each_entry_safe(lck, tmp, &locks_to_send, llist) {
		int stored_rc;

		stored_rc = CIFSSMBPosixLock(xid, tcon, lck->netfid, lck->pid,
					     lck->offset, lck->length, NULL,
					     lck->type, 0);
		if (stored_rc)
			rc = stored_rc;
		list_del(&lck->llist);
		kfree(lck);
	}

out:
	free_xid(xid);
	return rc;
err_out:
	list_for_each_entry_safe(lck, tmp, &locks_to_send, llist) {
		list_del(&lck->llist);
		kfree(lck);
	}
	goto out;
}

static int
cifs_push_locks(struct cifsFileInfo *cfile)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(cfile->dentry->d_sb);
	struct cifsInodeInfo *cinode = CIFS_I(cfile->dentry->d_inode);
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	int rc = 0;

	down_write(&cinode->lock_sem);
	if (!cinode->can_cache_brlcks) {
		up_write(&cinode->lock_sem);
		return rc;
	}

	if (cap_unix(tcon->ses) &&
	    (CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability)) &&
	    ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0))
		rc = cifs_push_posix_locks(cfile);
	else
		rc = tcon->ses->server->ops->push_mand_locks(cfile);

	cinode->can_cache_brlcks = false;
	up_write(&cinode->lock_sem);
	return rc;
}

static void
cifs_read_flock(struct file_lock *flock, __u32 *type, int *lock, int *unlock,
		bool *wait_flag, struct TCP_Server_Info *server)
{
	if (flock->fl_flags & FL_POSIX)
		cifs_dbg(FYI, "Posix\n");
	if (flock->fl_flags & FL_FLOCK)
		cifs_dbg(FYI, "Flock\n");
	if (flock->fl_flags & FL_SLEEP) {
		cifs_dbg(FYI, "Blocking lock\n");
		*wait_flag = true;
	}
	if (flock->fl_flags & FL_ACCESS)
		cifs_dbg(FYI, "Process suspended by mandatory locking - not implemented yet\n");
	if (flock->fl_flags & FL_LEASE)
		cifs_dbg(FYI, "Lease on file - not implemented yet\n");
	if (flock->fl_flags &
	    (~(FL_POSIX | FL_FLOCK | FL_SLEEP |
	       FL_ACCESS | FL_LEASE | FL_CLOSE)))
		cifs_dbg(FYI, "Unknown lock flags 0x%x\n", flock->fl_flags);

	*type = server->vals->large_lock_type;
	if (flock->fl_type == F_WRLCK) {
		cifs_dbg(FYI, "F_WRLCK\n");
		*type |= server->vals->exclusive_lock_type;
		*lock = 1;
	} else if (flock->fl_type == F_UNLCK) {
		cifs_dbg(FYI, "F_UNLCK\n");
		*type |= server->vals->unlock_lock_type;
		*unlock = 1;
		 
	} else if (flock->fl_type == F_RDLCK) {
		cifs_dbg(FYI, "F_RDLCK\n");
		*type |= server->vals->shared_lock_type;
		*lock = 1;
	} else if (flock->fl_type == F_EXLCK) {
		cifs_dbg(FYI, "F_EXLCK\n");
		*type |= server->vals->exclusive_lock_type;
		*lock = 1;
	} else if (flock->fl_type == F_SHLCK) {
		cifs_dbg(FYI, "F_SHLCK\n");
		*type |= server->vals->shared_lock_type;
		*lock = 1;
	} else
		cifs_dbg(FYI, "Unknown type of lock\n");
}

static int
cifs_getlk(struct file *file, struct file_lock *flock, __u32 type,
	   bool wait_flag, bool posix_lck, unsigned int xid)
{
	int rc = 0;
	__u64 length = 1 + flock->fl_end - flock->fl_start;
	struct cifsFileInfo *cfile = (struct cifsFileInfo *)file->private_data;
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	struct TCP_Server_Info *server = tcon->ses->server;
	__u16 netfid = cfile->fid.netfid;

	if (posix_lck) {
		int posix_lock_type;

		rc = cifs_posix_lock_test(file, flock);
		if (!rc)
			return rc;

		if (type & server->vals->shared_lock_type)
			posix_lock_type = CIFS_RDLCK;
		else
			posix_lock_type = CIFS_WRLCK;
		rc = CIFSSMBPosixLock(xid, tcon, netfid, current->tgid,
				      flock->fl_start, length, flock,
				      posix_lock_type, wait_flag);
		return rc;
	}

	rc = cifs_lock_test(cfile, flock->fl_start, length, type, flock);
	if (!rc)
		return rc;

	rc = server->ops->mand_lock(xid, cfile, flock->fl_start, length, type,
				    1, 0, false);
	if (rc == 0) {
		rc = server->ops->mand_lock(xid, cfile, flock->fl_start, length,
					    type, 0, 1, false);
		flock->fl_type = F_UNLCK;
		if (rc != 0)
			cifs_dbg(VFS, "Error unlocking previously locked range %d during test of lock\n",
				 rc);
		return 0;
	}

	if (type & server->vals->shared_lock_type) {
		flock->fl_type = F_WRLCK;
		return 0;
	}

	type &= ~server->vals->exclusive_lock_type;

	rc = server->ops->mand_lock(xid, cfile, flock->fl_start, length,
				    type | server->vals->shared_lock_type,
				    1, 0, false);
	if (rc == 0) {
		rc = server->ops->mand_lock(xid, cfile, flock->fl_start, length,
			type | server->vals->shared_lock_type, 0, 1, false);
		flock->fl_type = F_RDLCK;
		if (rc != 0)
			cifs_dbg(VFS, "Error unlocking previously locked range %d during test of lock\n",
				 rc);
	} else
		flock->fl_type = F_WRLCK;

	return 0;
}

void
cifs_move_llist(struct list_head *source, struct list_head *dest)
{
	struct list_head *li, *tmp;
	list_for_each_safe(li, tmp, source)
		list_move(li, dest);
}

void
cifs_free_llist(struct list_head *llist)
{
	struct cifsLockInfo *li, *tmp;
	list_for_each_entry_safe(li, tmp, llist, llist) {
		cifs_del_lock_waiters(li);
		list_del(&li->llist);
		kfree(li);
	}
}

int
cifs_unlock_range(struct cifsFileInfo *cfile, struct file_lock *flock,
		  unsigned int xid)
{
	int rc = 0, stored_rc;
	int types[] = {LOCKING_ANDX_LARGE_FILES,
		       LOCKING_ANDX_SHARED_LOCK | LOCKING_ANDX_LARGE_FILES};
	unsigned int i;
	unsigned int max_num, num, max_buf;
	LOCKING_ANDX_RANGE *buf, *cur;
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	struct cifsInodeInfo *cinode = CIFS_I(cfile->dentry->d_inode);
	struct cifsLockInfo *li, *tmp;
	__u64 length = 1 + flock->fl_end - flock->fl_start;
	struct list_head tmp_llist;

	INIT_LIST_HEAD(&tmp_llist);

	max_buf = tcon->ses->server->maxBuf;
	if (!max_buf)
		return -EINVAL;

	max_num = (max_buf - sizeof(struct smb_hdr)) /
						sizeof(LOCKING_ANDX_RANGE);
	buf = kzalloc(max_num * sizeof(LOCKING_ANDX_RANGE), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	down_write(&cinode->lock_sem);
	for (i = 0; i < 2; i++) {
		cur = buf;
		num = 0;
		list_for_each_entry_safe(li, tmp, &cfile->llist->locks, llist) {
			if (flock->fl_start > li->offset ||
			    (flock->fl_start + length) <
			    (li->offset + li->length))
				continue;
			if (current->tgid != li->pid)
				continue;
			if (types[i] != li->type)
				continue;
			if (cinode->can_cache_brlcks) {
				 
				list_del(&li->llist);
				cifs_del_lock_waiters(li);
				kfree(li);
				continue;
			}
			cur->Pid = cpu_to_le16(li->pid);
			cur->LengthLow = cpu_to_le32((u32)li->length);
			cur->LengthHigh = cpu_to_le32((u32)(li->length>>32));
			cur->OffsetLow = cpu_to_le32((u32)li->offset);
			cur->OffsetHigh = cpu_to_le32((u32)(li->offset>>32));
			 
			list_move(&li->llist, &tmp_llist);
			if (++num == max_num) {
				stored_rc = cifs_lockv(xid, tcon,
						       cfile->fid.netfid,
						       li->type, num, 0, buf);
				if (stored_rc) {
					 
					cifs_move_llist(&tmp_llist,
							&cfile->llist->locks);
					rc = stored_rc;
				} else
					 
					cifs_free_llist(&tmp_llist);
				cur = buf;
				num = 0;
			} else
				cur++;
		}
		if (num) {
			stored_rc = cifs_lockv(xid, tcon, cfile->fid.netfid,
					       types[i], num, 0, buf);
			if (stored_rc) {
				cifs_move_llist(&tmp_llist,
						&cfile->llist->locks);
				rc = stored_rc;
			} else
				cifs_free_llist(&tmp_llist);
		}
	}

	up_write(&cinode->lock_sem);
	kfree(buf);
	return rc;
}

static int
cifs_setlk(struct file *file, struct file_lock *flock, __u32 type,
	   bool wait_flag, bool posix_lck, int lock, int unlock,
	   unsigned int xid)
{
	int rc = 0;
	__u64 length = 1 + flock->fl_end - flock->fl_start;
	struct cifsFileInfo *cfile = (struct cifsFileInfo *)file->private_data;
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	struct TCP_Server_Info *server = tcon->ses->server;
	struct inode *inode = cfile->dentry->d_inode;

	if (posix_lck) {
		int posix_lock_type;

		rc = cifs_posix_lock_set(file, flock);
		if (!rc || rc < 0)
			return rc;

		if (type & server->vals->shared_lock_type)
			posix_lock_type = CIFS_RDLCK;
		else
			posix_lock_type = CIFS_WRLCK;

		if (unlock == 1)
			posix_lock_type = CIFS_UNLCK;

		rc = CIFSSMBPosixLock(xid, tcon, cfile->fid.netfid,
				      current->tgid, flock->fl_start, length,
				      NULL, posix_lock_type, wait_flag);
		goto out;
	}

	if (lock) {
		struct cifsLockInfo *lock;

		lock = cifs_lock_init(flock->fl_start, length, type);
		if (!lock)
			return -ENOMEM;

		rc = cifs_lock_add_if(cfile, lock, wait_flag);
		if (rc < 0) {
			kfree(lock);
			return rc;
		}
		if (!rc)
			goto out;

		if (!CIFS_I(inode)->clientCanCacheAll &&
					CIFS_I(inode)->clientCanCacheRead) {
			cifs_invalidate_mapping(inode);
			cifs_dbg(FYI, "Set no oplock for inode=%p due to mand locks\n",
				 inode);
			CIFS_I(inode)->clientCanCacheRead = false;
		}

		rc = server->ops->mand_lock(xid, cfile, flock->fl_start, length,
					    type, 1, 0, wait_flag);
		if (rc) {
			kfree(lock);
			return rc;
		}

		cifs_lock_add(cfile, lock);
	} else if (unlock)
		rc = server->ops->mand_unlock_range(cfile, flock, xid);

out:
	if (flock->fl_flags & FL_POSIX)
		posix_lock_file_wait(file, flock);
	return rc;
}

int cifs_lock(struct file *file, int cmd, struct file_lock *flock)
{
	int rc, xid;
	int lock = 0, unlock = 0;
	bool wait_flag = false;
	bool posix_lck = false;
	struct cifs_sb_info *cifs_sb;
	struct cifs_tcon *tcon;
	struct cifsInodeInfo *cinode;
	struct cifsFileInfo *cfile;
	__u16 netfid;
	__u32 type;

	rc = -EACCES;
	xid = get_xid();

	cifs_dbg(FYI, "Lock parm: 0x%x flockflags: 0x%x flocktype: 0x%x start: %lld end: %lld\n",
		 cmd, flock->fl_flags, flock->fl_type,
		 flock->fl_start, flock->fl_end);

	cfile = (struct cifsFileInfo *)file->private_data;
	tcon = tlink_tcon(cfile->tlink);

	cifs_read_flock(flock, &type, &lock, &unlock, &wait_flag,
			tcon->ses->server);

	cifs_sb = CIFS_SB(file->f_path.dentry->d_sb);
	netfid = cfile->fid.netfid;
	cinode = CIFS_I(file_inode(file));

	if (cap_unix(tcon->ses) &&
	    (CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability)) &&
	    ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0))
		posix_lck = true;
	 
	if (IS_GETLK(cmd)) {
		rc = cifs_getlk(file, flock, type, wait_flag, posix_lck, xid);
		free_xid(xid);
		return rc;
	}

	if (!lock && !unlock) {
		 
		free_xid(xid);
		return -EOPNOTSUPP;
	}

	rc = cifs_setlk(file, flock, type, wait_flag, posix_lck, lock, unlock,
			xid);
	free_xid(xid);
	return rc;
}

void
cifs_update_eof(struct cifsInodeInfo *cifsi, loff_t offset,
		      unsigned int bytes_written)
{
	loff_t end_of_write = offset + bytes_written;

	if (end_of_write > cifsi->server_eof)
		cifsi->server_eof = end_of_write;
}

static ssize_t
cifs_write(struct cifsFileInfo *open_file, __u32 pid, const char *write_data,
	   size_t write_size, loff_t *offset)
{
	int rc = 0;
	unsigned int bytes_written = 0;
	unsigned int total_written;
	struct cifs_sb_info *cifs_sb;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	unsigned int xid;
	struct dentry *dentry = open_file->dentry;
	struct cifsInodeInfo *cifsi = CIFS_I(dentry->d_inode);
	struct cifs_io_parms io_parms;

	cifs_sb = CIFS_SB(dentry->d_sb);

	cifs_dbg(FYI, "write %zd bytes to offset %lld of %s\n",
		 write_size, *offset, dentry->d_name.name);

	tcon = tlink_tcon(open_file->tlink);
	server = tcon->ses->server;

	if (!server->ops->sync_write)
		return -ENOSYS;

	xid = get_xid();

	for (total_written = 0; write_size > total_written;
	     total_written += bytes_written) {
		rc = -EAGAIN;
		while (rc == -EAGAIN) {
			struct kvec iov[2];
			unsigned int len;

			if (open_file->invalidHandle) {
				 
				rc = cifs_reopen_file(open_file, false);
				if (rc != 0)
					break;
			}

			len = min((size_t)cifs_sb->wsize,
				  write_size - total_written);
			 
			iov[1].iov_base = (char *)write_data + total_written;
			iov[1].iov_len = len;
			io_parms.pid = pid;
			io_parms.tcon = tcon;
			io_parms.offset = *offset;
			io_parms.length = len;
			rc = server->ops->sync_write(xid, open_file, &io_parms,
						     &bytes_written, iov, 1);
		}
		if (rc || (bytes_written == 0)) {
			if (total_written)
				break;
			else {
				free_xid(xid);
				return rc;
			}
		} else {
			spin_lock(&dentry->d_inode->i_lock);
			cifs_update_eof(cifsi, *offset, bytes_written);
			spin_unlock(&dentry->d_inode->i_lock);
			*offset += bytes_written;
		}
	}

	cifs_stats_bytes_written(tcon, total_written);

	if (total_written > 0) {
		spin_lock(&dentry->d_inode->i_lock);
		if (*offset > dentry->d_inode->i_size)
			i_size_write(dentry->d_inode, *offset);
		spin_unlock(&dentry->d_inode->i_lock);
	}
	mark_inode_dirty_sync(dentry->d_inode);
	free_xid(xid);
	return total_written;
}

struct cifsFileInfo *find_readable_file(struct cifsInodeInfo *cifs_inode,
					bool fsuid_only)
{
	struct cifsFileInfo *open_file = NULL;
	struct cifs_sb_info *cifs_sb = CIFS_SB(cifs_inode->vfs_inode.i_sb);

	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MULTIUSER))
		fsuid_only = false;

	spin_lock(&cifs_file_list_lock);
	 
	list_for_each_entry(open_file, &cifs_inode->openFileList, flist) {
		if (fsuid_only && !uid_eq(open_file->uid, current_fsuid()))
			continue;
		if (OPEN_FMODE(open_file->f_flags) & FMODE_READ) {
			if (!open_file->invalidHandle) {
				 
				cifsFileInfo_get_locked(open_file);
				spin_unlock(&cifs_file_list_lock);
				return open_file;
			}  
		} else  
			break;  
	}
	spin_unlock(&cifs_file_list_lock);
	return NULL;
}

struct cifsFileInfo *find_writable_file(struct cifsInodeInfo *cifs_inode,
					bool fsuid_only)
{
	struct cifsFileInfo *open_file, *inv_file = NULL;
	struct cifs_sb_info *cifs_sb;
	bool any_available = false;
	int rc;
	unsigned int refind = 0;

	if (cifs_inode == NULL) {
		cifs_dbg(VFS, "Null inode passed to cifs_writeable_file\n");
		dump_stack();
		return NULL;
	}

	cifs_sb = CIFS_SB(cifs_inode->vfs_inode.i_sb);

	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MULTIUSER))
		fsuid_only = false;

	spin_lock(&cifs_file_list_lock);
refind_writable:
	if (refind > MAX_REOPEN_ATT) {
		spin_unlock(&cifs_file_list_lock);
		return NULL;
	}
	list_for_each_entry(open_file, &cifs_inode->openFileList, flist) {
		if (!any_available && open_file->pid != current->tgid)
			continue;
		if (fsuid_only && !uid_eq(open_file->uid, current_fsuid()))
			continue;
		if (OPEN_FMODE(open_file->f_flags) & FMODE_WRITE) {
			if (!open_file->invalidHandle) {
				 
				cifsFileInfo_get_locked(open_file);
				spin_unlock(&cifs_file_list_lock);
				return open_file;
			} else {
				if (!inv_file)
					inv_file = open_file;
			}
		}
	}
	 
	if (!any_available) {
		any_available = true;
		goto refind_writable;
	}

	if (inv_file) {
		any_available = false;
		cifsFileInfo_get_locked(inv_file);
	}

	spin_unlock(&cifs_file_list_lock);

	if (inv_file) {
		rc = cifs_reopen_file(inv_file, false);
		if (!rc)
			return inv_file;
		else {
			spin_lock(&cifs_file_list_lock);
			list_move_tail(&inv_file->flist,
					&cifs_inode->openFileList);
			spin_unlock(&cifs_file_list_lock);
			cifsFileInfo_put(inv_file);
#ifdef MY_ABC_HERE
			inv_file = NULL;
#endif
			spin_lock(&cifs_file_list_lock);
			++refind;
			inv_file = NULL;
			goto refind_writable;
		}
	}

	return NULL;
}

static int cifs_partialpagewrite(struct page *page, unsigned from, unsigned to)
{
	struct address_space *mapping = page->mapping;
	loff_t offset = (loff_t)page->index << PAGE_CACHE_SHIFT;
	char *write_data;
	int rc = -EFAULT;
	int bytes_written = 0;
	struct inode *inode;
	struct cifsFileInfo *open_file;

	if (!mapping || !mapping->host)
		return -EFAULT;

	inode = page->mapping->host;

	offset += (loff_t)from;
	write_data = kmap(page);
	write_data += from;

	if ((to > PAGE_CACHE_SIZE) || (from > to)) {
		kunmap(page);
		return -EIO;
	}

	if (offset > mapping->host->i_size) {
		kunmap(page);
		return 0;  
	}

	if (mapping->host->i_size - offset < (loff_t)to)
		to = (unsigned)(mapping->host->i_size - offset);

	open_file = find_writable_file(CIFS_I(mapping->host), false);
	if (open_file) {
		bytes_written = cifs_write(open_file, open_file->pid,
					   write_data, to - from, &offset);
		cifsFileInfo_put(open_file);
		 
		inode->i_atime = inode->i_mtime = current_fs_time(inode->i_sb);
		if ((bytes_written > 0) && (offset))
			rc = 0;
		else if (bytes_written < 0)
			rc = bytes_written;
	} else {
		cifs_dbg(FYI, "No writeable filehandles for inode\n");
		rc = -EIO;
	}

	kunmap(page);
	return rc;
}

static int cifs_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(mapping->host->i_sb);
	bool done = false, scanned = false, range_whole = false;
	pgoff_t end, index;
	struct cifs_writedata *wdata;
	struct TCP_Server_Info *server;
	struct page *page;
	int rc = 0;

	if (cifs_sb->wsize < PAGE_CACHE_SIZE)
		return generic_writepages(mapping, wbc);

	if (wbc->range_cyclic) {
		index = mapping->writeback_index;  
		end = -1;
	} else {
		index = wbc->range_start >> PAGE_CACHE_SHIFT;
		end = wbc->range_end >> PAGE_CACHE_SHIFT;
		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = true;
		scanned = true;
	}
retry:
	while (!done && index <= end) {
		unsigned int i, nr_pages, found_pages;
		pgoff_t next = 0, tofind;
		struct page **pages;

		tofind = min((cifs_sb->wsize / PAGE_CACHE_SIZE) - 1,
				end - index) + 1;

		wdata = cifs_writedata_alloc((unsigned int)tofind,
					     cifs_writev_complete);
		if (!wdata) {
			rc = -ENOMEM;
			break;
		}

		found_pages = 0;
		pages = wdata->pages;
		do {
			nr_pages = find_get_pages_tag(mapping, &index,
							PAGECACHE_TAG_DIRTY,
							tofind, pages);
			found_pages += nr_pages;
			tofind -= nr_pages;
			pages += nr_pages;
		} while (nr_pages && tofind && index <= end);

		if (found_pages == 0) {
			kref_put(&wdata->refcount, cifs_writedata_release);
			break;
		}

		nr_pages = 0;
		for (i = 0; i < found_pages; i++) {
			page = wdata->pages[i];
			 
			if (nr_pages == 0)
				lock_page(page);
			else if (!trylock_page(page))
				break;

			if (unlikely(page->mapping != mapping)) {
				unlock_page(page);
				break;
			}

			if (!wbc->range_cyclic && page->index > end) {
				done = true;
				unlock_page(page);
				break;
			}

			if (next && (page->index != next)) {
				 
				unlock_page(page);
				break;
			}

			if (wbc->sync_mode != WB_SYNC_NONE)
				wait_on_page_writeback(page);

			if (PageWriteback(page) ||
					!clear_page_dirty_for_io(page)) {
				unlock_page(page);
				break;
			}

			set_page_writeback(page);

			if (page_offset(page) >= i_size_read(mapping->host)) {
				done = true;
				unlock_page(page);
				end_page_writeback(page);
				break;
			}

			wdata->pages[i] = page;
			next = page->index + 1;
			++nr_pages;
		}

		if (nr_pages == 0)
			index = wdata->pages[0]->index + 1;

		for (i = nr_pages; i < found_pages; i++) {
			page_cache_release(wdata->pages[i]);
			wdata->pages[i] = NULL;
		}

		if (nr_pages == 0) {
			kref_put(&wdata->refcount, cifs_writedata_release);
			continue;
		}

		wdata->sync_mode = wbc->sync_mode;
		wdata->nr_pages = nr_pages;
		wdata->offset = page_offset(wdata->pages[0]);
		wdata->pagesz = PAGE_CACHE_SIZE;
		wdata->tailsz =
			min(i_size_read(mapping->host) -
			    page_offset(wdata->pages[nr_pages - 1]),
			    (loff_t)PAGE_CACHE_SIZE);
		wdata->bytes = ((nr_pages - 1) * PAGE_CACHE_SIZE) +
					wdata->tailsz;

		do {
			if (wdata->cfile != NULL)
				cifsFileInfo_put(wdata->cfile);
			wdata->cfile = find_writable_file(CIFS_I(mapping->host),
							  false);
			if (!wdata->cfile) {
				cifs_dbg(VFS, "No writable handles for inode\n");
				rc = -EBADF;
				break;
			}
			wdata->pid = wdata->cfile->pid;
			server = tlink_tcon(wdata->cfile->tlink)->ses->server;
			rc = server->ops->async_writev(wdata);
		} while (wbc->sync_mode == WB_SYNC_ALL && rc == -EAGAIN);

		for (i = 0; i < nr_pages; ++i)
			unlock_page(wdata->pages[i]);

		if (rc != 0) {
			for (i = 0; i < nr_pages; ++i) {
				if (rc == -EAGAIN)
					redirty_page_for_writepage(wbc,
							   wdata->pages[i]);
				else
					SetPageError(wdata->pages[i]);
				end_page_writeback(wdata->pages[i]);
				page_cache_release(wdata->pages[i]);
			}
			if (rc != -EAGAIN)
				mapping_set_error(mapping, rc);
		}
		kref_put(&wdata->refcount, cifs_writedata_release);

		wbc->nr_to_write -= nr_pages;
		if (wbc->nr_to_write <= 0)
			done = true;

		index = next;
	}

	if (!scanned && !done) {
		 
		scanned = true;
		index = 0;
		goto retry;
	}

	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = index;

	return rc;
}

static int
cifs_writepage_locked(struct page *page, struct writeback_control *wbc)
{
	int rc;
	unsigned int xid;

	xid = get_xid();
 
	page_cache_get(page);
	if (!PageUptodate(page))
		cifs_dbg(FYI, "ppw - page not up to date\n");

	set_page_writeback(page);
retry_write:
	rc = cifs_partialpagewrite(page, 0, PAGE_CACHE_SIZE);
	if (rc == -EAGAIN && wbc->sync_mode == WB_SYNC_ALL)
		goto retry_write;
	else if (rc == -EAGAIN)
		redirty_page_for_writepage(wbc, page);
	else if (rc != 0)
		SetPageError(page);
	else
		SetPageUptodate(page);
	end_page_writeback(page);
	page_cache_release(page);
	free_xid(xid);
	return rc;
}

static int cifs_writepage(struct page *page, struct writeback_control *wbc)
{
	int rc = cifs_writepage_locked(page, wbc);
	unlock_page(page);
	return rc;
}

static int cifs_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	int rc;
	struct inode *inode = mapping->host;
	struct cifsFileInfo *cfile = file->private_data;
	struct cifs_sb_info *cifs_sb = CIFS_SB(cfile->dentry->d_sb);
	__u32 pid;

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		pid = cfile->pid;
	else
		pid = current->tgid;

	cifs_dbg(FYI, "write_end for page %p from pos %lld with %d bytes\n",
		 page, pos, copied);

	if (PageChecked(page)) {
		if (copied == len)
			SetPageUptodate(page);
		ClearPageChecked(page);
	} else if (!PageUptodate(page) && copied == PAGE_CACHE_SIZE)
		SetPageUptodate(page);

	if (!PageUptodate(page)) {
		char *page_data;
		unsigned offset = pos & (PAGE_CACHE_SIZE - 1);
		unsigned int xid;

		xid = get_xid();
		 
		page_data = kmap(page);
		rc = cifs_write(cfile, pid, page_data + offset, copied, &pos);
		 
		kunmap(page);

		free_xid(xid);
	} else {
		rc = copied;
		pos += copied;
		set_page_dirty(page);
	}

	if (rc > 0) {
		spin_lock(&inode->i_lock);
		if (pos > inode->i_size)
			i_size_write(inode, pos);
		spin_unlock(&inode->i_lock);
	}

	unlock_page(page);
	page_cache_release(page);

	return rc;
}

int cifs_strict_fsync(struct file *file, loff_t start, loff_t end,
		      int datasync)
{
	unsigned int xid;
	int rc = 0;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	struct cifsFileInfo *smbfile = file->private_data;
	struct inode *inode = file_inode(file);
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);

	rc = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (rc)
		return rc;
	mutex_lock(&inode->i_mutex);

	xid = get_xid();

	cifs_dbg(FYI, "Sync file - name: %s datasync: 0x%x\n",
		 file->f_path.dentry->d_name.name, datasync);

	if (!CIFS_I(inode)->clientCanCacheRead) {
		rc = cifs_invalidate_mapping(inode);
		if (rc) {
			cifs_dbg(FYI, "rc: %d during invalidate phase\n", rc);
			rc = 0;  
		}
	}

	tcon = tlink_tcon(smbfile->tlink);
	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOSSYNC)) {
		server = tcon->ses->server;
		if (server->ops->flush)
			rc = server->ops->flush(xid, tcon, &smbfile->fid);
		else
			rc = -ENOSYS;
	}

	free_xid(xid);
	mutex_unlock(&inode->i_mutex);
	return rc;
}

int cifs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	unsigned int xid;
	int rc = 0;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	struct cifsFileInfo *smbfile = file->private_data;
	struct cifs_sb_info *cifs_sb = CIFS_SB(file->f_path.dentry->d_sb);
	struct inode *inode = file->f_mapping->host;

	rc = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (rc)
		return rc;
	mutex_lock(&inode->i_mutex);

	xid = get_xid();

	cifs_dbg(FYI, "Sync file - name: %s datasync: 0x%x\n",
		 file->f_path.dentry->d_name.name, datasync);

	tcon = tlink_tcon(smbfile->tlink);
	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOSSYNC)) {
		server = tcon->ses->server;
		if (server->ops->flush)
			rc = server->ops->flush(xid, tcon, &smbfile->fid);
		else
			rc = -ENOSYS;
	}

	free_xid(xid);
	mutex_unlock(&inode->i_mutex);
	return rc;
}

int cifs_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);
	int rc = 0;

	if (file->f_mode & FMODE_WRITE)
		rc = filemap_write_and_wait(inode->i_mapping);

	cifs_dbg(FYI, "Flush inode %p file %p rc %d\n", inode, file, rc);

	return rc;
}

static int
cifs_write_allocate_pages(struct page **pages, unsigned long num_pages)
{
	int rc = 0;
	unsigned long i;

	for (i = 0; i < num_pages; i++) {
		pages[i] = alloc_page(GFP_KERNEL|__GFP_HIGHMEM);
		if (!pages[i]) {
			 
			num_pages = i;
			rc = -ENOMEM;
			break;
		}
	}

	if (rc) {
		for (i = 0; i < num_pages; i++)
			put_page(pages[i]);
	}
	return rc;
}

static inline
size_t get_numpages(const size_t wsize, const size_t len, size_t *cur_len)
{
	size_t num_pages;
	size_t clen;

	clen = min_t(const size_t, len, wsize);
	num_pages = DIV_ROUND_UP(clen, PAGE_SIZE);

	if (cur_len)
		*cur_len = clen;

	return num_pages;
}

static void
cifs_uncached_writev_complete(struct work_struct *work)
{
	int i;
	struct cifs_writedata *wdata = container_of(work,
					struct cifs_writedata, work);
	struct inode *inode = wdata->cfile->dentry->d_inode;
	struct cifsInodeInfo *cifsi = CIFS_I(inode);

	spin_lock(&inode->i_lock);
	cifs_update_eof(cifsi, wdata->offset, wdata->bytes);
	if (cifsi->server_eof > inode->i_size)
		i_size_write(inode, cifsi->server_eof);
	spin_unlock(&inode->i_lock);

	complete(&wdata->done);

	if (wdata->result != -EAGAIN) {
		for (i = 0; i < wdata->nr_pages; i++)
			put_page(wdata->pages[i]);
	}

	kref_put(&wdata->refcount, cifs_writedata_release);
}

static int
cifs_uncached_retry_writev(struct cifs_writedata *wdata)
{
	int rc;
	struct TCP_Server_Info *server;

	server = tlink_tcon(wdata->cfile->tlink)->ses->server;

	do {
		if (wdata->cfile->invalidHandle) {
			rc = cifs_reopen_file(wdata->cfile, false);
			if (rc != 0)
				continue;
		}
		rc = server->ops->async_writev(wdata);
	} while (rc == -EAGAIN);

	return rc;
}

static ssize_t
cifs_iovec_write(struct file *file, const struct iovec *iov,
		 unsigned long nr_segs, loff_t *poffset)
{
	unsigned long nr_pages, i;
	size_t bytes, copied, len, cur_len;
	ssize_t total_written = 0;
	loff_t offset;
	struct iov_iter it;
	struct cifsFileInfo *open_file;
	struct cifs_tcon *tcon;
	struct cifs_sb_info *cifs_sb;
	struct cifs_writedata *wdata, *tmp;
	struct list_head wdata_list;
	int rc;
	pid_t pid;

	len = iov_length(iov, nr_segs);
	if (!len)
		return 0;

	rc = generic_write_checks(file, poffset, &len, 0);
	if (rc)
		return rc;

	INIT_LIST_HEAD(&wdata_list);
	cifs_sb = CIFS_SB(file->f_path.dentry->d_sb);
	open_file = file->private_data;
	tcon = tlink_tcon(open_file->tlink);

	if (!tcon->ses->server->ops->async_writev)
		return -ENOSYS;

	offset = *poffset;

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		pid = open_file->pid;
	else
		pid = current->tgid;

	iov_iter_init(&it, iov, nr_segs, len, 0);
	do {
		size_t save_len;

		nr_pages = get_numpages(cifs_sb->wsize, len, &cur_len);
		wdata = cifs_writedata_alloc(nr_pages,
					     cifs_uncached_writev_complete);
		if (!wdata) {
			rc = -ENOMEM;
			break;
		}

		rc = cifs_write_allocate_pages(wdata->pages, nr_pages);
		if (rc) {
			kfree(wdata);
			break;
		}

		save_len = cur_len;
		for (i = 0; i < nr_pages; i++) {
			bytes = min_t(const size_t, cur_len, PAGE_SIZE);
			copied = iov_iter_copy_from_user(wdata->pages[i], &it,
							 0, bytes);
			cur_len -= copied;
			iov_iter_advance(&it, copied);
			 
			if (copied < bytes)
				break;
		}
		cur_len = save_len - cur_len;

		if (!cur_len) {
			for (i = 0; i < nr_pages; i++)
				put_page(wdata->pages[i]);
			kfree(wdata);
			rc = -EFAULT;
			break;
		}

		for ( ; nr_pages > i + 1; nr_pages--)
			put_page(wdata->pages[nr_pages - 1]);

		wdata->sync_mode = WB_SYNC_ALL;
		wdata->nr_pages = nr_pages;
		wdata->offset = (__u64)offset;
		wdata->cfile = cifsFileInfo_get(open_file);
		wdata->pid = pid;
		wdata->bytes = cur_len;
		wdata->pagesz = PAGE_SIZE;
		wdata->tailsz = cur_len - ((nr_pages - 1) * PAGE_SIZE);
		rc = cifs_uncached_retry_writev(wdata);
		if (rc) {
			kref_put(&wdata->refcount, cifs_writedata_release);
			break;
		}

		list_add_tail(&wdata->list, &wdata_list);
		offset += cur_len;
		len -= cur_len;
	} while (len > 0);

	if (!list_empty(&wdata_list))
		rc = 0;

restart_loop:
	list_for_each_entry_safe(wdata, tmp, &wdata_list, list) {
		if (!rc) {
			 
			rc = wait_for_completion_killable(&wdata->done);
			if (rc)
				rc = -EINTR;
			else if (wdata->result)
				rc = wdata->result;
			else
				total_written += wdata->bytes;

			if (rc == -EAGAIN) {
				rc = cifs_uncached_retry_writev(wdata);
				goto restart_loop;
			}
		}
		list_del_init(&wdata->list);
		kref_put(&wdata->refcount, cifs_writedata_release);
	}

	if (total_written > 0)
		*poffset += total_written;

	cifs_stats_bytes_written(tcon, total_written);
	return total_written ? total_written : (ssize_t)rc;
}

ssize_t cifs_user_writev(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	ssize_t written;
	struct inode *inode;

	inode = file_inode(iocb->ki_filp);

	written = cifs_iovec_write(iocb->ki_filp, iov, nr_segs, &pos);
	if (written > 0) {
		CIFS_I(inode)->invalid_mapping = true;
		iocb->ki_pos = pos;
	}

	return written;
}

static ssize_t
cifs_writev(struct kiocb *iocb, const struct iovec *iov,
	    unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct cifsFileInfo *cfile = (struct cifsFileInfo *)file->private_data;
	struct inode *inode = file->f_mapping->host;
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct TCP_Server_Info *server = tlink_tcon(cfile->tlink)->ses->server;
	ssize_t rc = -EACCES;

	BUG_ON(iocb->ki_pos != pos);

	down_read(&cinode->lock_sem);
	if (!cifs_find_lock_conflict(cfile, pos, iov_length(iov, nr_segs),
				     server->vals->exclusive_lock_type, NULL,
				     CIFS_WRITE_OP)) {
		mutex_lock(&inode->i_mutex);
		rc = __generic_file_aio_write(iocb, iov, nr_segs,
					       &iocb->ki_pos);
		mutex_unlock(&inode->i_mutex);
	}

	if (rc > 0 || rc == -EIOCBQUEUED) {
		ssize_t err;

		err = generic_write_sync(file, pos, rc);
		if (err < 0 && rc > 0)
			rc = err;
	}

	up_read(&cinode->lock_sem);
	return rc;
}

ssize_t
cifs_strict_writev(struct kiocb *iocb, const struct iovec *iov,
		   unsigned long nr_segs, loff_t pos)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct cifsFileInfo *cfile = (struct cifsFileInfo *)
						iocb->ki_filp->private_data;
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	ssize_t written;

	if (cinode->clientCanCacheAll) {
		if (cap_unix(tcon->ses) &&
		(CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability))
		    && ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0))
			return generic_file_aio_write(iocb, iov, nr_segs, pos);
		return cifs_writev(iocb, iov, nr_segs, pos);
	}
	 
	written = cifs_user_writev(iocb, iov, nr_segs, pos);
	if (written > 0 && cinode->clientCanCacheRead) {
		 
		cifs_invalidate_mapping(inode);
		cifs_dbg(FYI, "Set no oplock for inode=%p after a write operation\n",
			 inode);
		cinode->clientCanCacheRead = false;
	}
	return written;
}

static struct cifs_readdata *
cifs_readdata_alloc(unsigned int nr_pages, work_func_t complete)
{
	struct cifs_readdata *rdata;

	rdata = kzalloc(sizeof(*rdata) + (sizeof(struct page *) * nr_pages),
			GFP_KERNEL);
	if (rdata != NULL) {
		kref_init(&rdata->refcount);
		INIT_LIST_HEAD(&rdata->list);
		init_completion(&rdata->done);
		INIT_WORK(&rdata->work, complete);
	}

	return rdata;
}

void
cifs_readdata_release(struct kref *refcount)
{
	struct cifs_readdata *rdata = container_of(refcount,
					struct cifs_readdata, refcount);

	if (rdata->cfile)
		cifsFileInfo_put(rdata->cfile);

	kfree(rdata);
}

static int
cifs_read_allocate_pages(struct cifs_readdata *rdata, unsigned int nr_pages)
{
	int rc = 0;
	struct page *page;
	unsigned int i;

	for (i = 0; i < nr_pages; i++) {
		page = alloc_page(GFP_KERNEL|__GFP_HIGHMEM);
		if (!page) {
			rc = -ENOMEM;
			break;
		}
		rdata->pages[i] = page;
	}

	if (rc) {
		for (i = 0; i < nr_pages; i++) {
			put_page(rdata->pages[i]);
			rdata->pages[i] = NULL;
		}
	}
	return rc;
}

static void
cifs_uncached_readdata_release(struct kref *refcount)
{
	struct cifs_readdata *rdata = container_of(refcount,
					struct cifs_readdata, refcount);
	unsigned int i;

	for (i = 0; i < rdata->nr_pages; i++) {
		put_page(rdata->pages[i]);
		rdata->pages[i] = NULL;
	}
	cifs_readdata_release(refcount);
}

static int
cifs_retry_async_readv(struct cifs_readdata *rdata)
{
	int rc;
	struct TCP_Server_Info *server;

	server = tlink_tcon(rdata->cfile->tlink)->ses->server;

	do {
		if (rdata->cfile->invalidHandle) {
			rc = cifs_reopen_file(rdata->cfile, true);
			if (rc != 0)
				continue;
		}
		rc = server->ops->async_readv(rdata);
	} while (rc == -EAGAIN);

	return rc;
}

static ssize_t
cifs_readdata_to_iov(struct cifs_readdata *rdata, const struct iovec *iov,
			unsigned long nr_segs, loff_t offset, ssize_t *copied)
{
	int rc = 0;
	struct iov_iter ii;
	size_t pos = rdata->offset - offset;
	ssize_t remaining = rdata->bytes;
	unsigned char *pdata;
	unsigned int i;

	iov_iter_init(&ii, iov, nr_segs, iov_length(iov, nr_segs), 0);
	iov_iter_advance(&ii, pos);

	*copied = 0;
	for (i = 0; i < rdata->nr_pages; i++) {
		ssize_t copy;
		struct page *page = rdata->pages[i];

		copy = min_t(ssize_t, remaining, PAGE_SIZE);

		copy = min_t(ssize_t, copy, iov_iter_count(&ii));

		if (copy && !rc) {
			pdata = kmap(page);
			rc = memcpy_toiovecend(ii.iov, pdata, ii.iov_offset,
						(int)copy);
			kunmap(page);
			if (!rc) {
				*copied += copy;
				remaining -= copy;
				iov_iter_advance(&ii, copy);
			}
		}
	}

	return rc;
}

static void
cifs_uncached_readv_complete(struct work_struct *work)
{
	struct cifs_readdata *rdata = container_of(work,
						struct cifs_readdata, work);

	complete(&rdata->done);
	kref_put(&rdata->refcount, cifs_uncached_readdata_release);
}

static int
cifs_uncached_read_into_pages(struct TCP_Server_Info *server,
			struct cifs_readdata *rdata, unsigned int len)
{
	int total_read = 0, result = 0;
	unsigned int i;
	unsigned int nr_pages = rdata->nr_pages;
	struct kvec iov;

	rdata->tailsz = PAGE_SIZE;
	for (i = 0; i < nr_pages; i++) {
		struct page *page = rdata->pages[i];

		if (len >= PAGE_SIZE) {
			 
			iov.iov_base = kmap(page);
			iov.iov_len = PAGE_SIZE;
			cifs_dbg(FYI, "%u: iov_base=%p iov_len=%zu\n",
				 i, iov.iov_base, iov.iov_len);
			len -= PAGE_SIZE;
		} else if (len > 0) {
			 
			iov.iov_base = kmap(page);
			iov.iov_len = len;
			cifs_dbg(FYI, "%u: iov_base=%p iov_len=%zu\n",
				 i, iov.iov_base, iov.iov_len);
			memset(iov.iov_base + len, '\0', PAGE_SIZE - len);
			rdata->tailsz = len;
			len = 0;
		} else {
			 
			rdata->pages[i] = NULL;
			rdata->nr_pages--;
			put_page(page);
			continue;
		}

		result = cifs_readv_from_socket(server, &iov, 1, iov.iov_len);
		kunmap(page);
		if (result < 0)
			break;

		total_read += result;
	}

	return total_read > 0 && result != -EAGAIN ? total_read : result;
}

static ssize_t
cifs_iovec_read(struct file *file, const struct iovec *iov,
		 unsigned long nr_segs, loff_t *poffset)
{
	ssize_t rc;
	size_t len, cur_len;
	ssize_t total_read = 0;
	loff_t offset = *poffset;
	unsigned int npages;
	struct cifs_sb_info *cifs_sb;
	struct cifs_tcon *tcon;
	struct cifsFileInfo *open_file;
	struct cifs_readdata *rdata, *tmp;
	struct list_head rdata_list;
	pid_t pid;

	if (!nr_segs)
		return 0;

	len = iov_length(iov, nr_segs);
	if (!len)
		return 0;

	INIT_LIST_HEAD(&rdata_list);
	cifs_sb = CIFS_SB(file->f_path.dentry->d_sb);
	open_file = file->private_data;
	tcon = tlink_tcon(open_file->tlink);

	if (!tcon->ses->server->ops->async_readv)
		return -ENOSYS;

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		pid = open_file->pid;
	else
		pid = current->tgid;

	if ((file->f_flags & O_ACCMODE) == O_WRONLY)
		cifs_dbg(FYI, "attempting read on write only file instance\n");

	do {
		cur_len = min_t(const size_t, len - total_read, cifs_sb->rsize);
		npages = DIV_ROUND_UP(cur_len, PAGE_SIZE);

		rdata = cifs_readdata_alloc(npages,
					    cifs_uncached_readv_complete);
		if (!rdata) {
			rc = -ENOMEM;
			goto error;
		}

		rc = cifs_read_allocate_pages(rdata, npages);
		if (rc)
			goto error;

		rdata->cfile = cifsFileInfo_get(open_file);
		rdata->nr_pages = npages;
		rdata->offset = offset;
		rdata->bytes = cur_len;
		rdata->pid = pid;
		rdata->pagesz = PAGE_SIZE;
		rdata->read_into_pages = cifs_uncached_read_into_pages;

		rc = cifs_retry_async_readv(rdata);
error:
		if (rc) {
			kref_put(&rdata->refcount,
				 cifs_uncached_readdata_release);
			break;
		}

		list_add_tail(&rdata->list, &rdata_list);
		offset += cur_len;
		len -= cur_len;
	} while (len > 0);

	if (!list_empty(&rdata_list))
		rc = 0;

restart_loop:
	list_for_each_entry_safe(rdata, tmp, &rdata_list, list) {
		if (!rc) {
			ssize_t copied;

			rc = wait_for_completion_killable(&rdata->done);
			if (rc)
				rc = -EINTR;
			else if (rdata->result)
				rc = rdata->result;
			else {
				rc = cifs_readdata_to_iov(rdata, iov,
							nr_segs, *poffset,
							&copied);
				total_read += copied;
			}

			if (rc == -EAGAIN) {
				rc = cifs_retry_async_readv(rdata);
				goto restart_loop;
			}
		}
		list_del_init(&rdata->list);
		kref_put(&rdata->refcount, cifs_uncached_readdata_release);
	}

	cifs_stats_bytes_read(tcon, total_read);
	*poffset += total_read;

	if (rc == -ENODATA)
		rc = 0;

	return total_read ? total_read : rc;
}

ssize_t cifs_user_readv(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos)
{
	ssize_t read;

	read = cifs_iovec_read(iocb->ki_filp, iov, nr_segs, &pos);
	if (read > 0)
		iocb->ki_pos = pos;

	return read;
}

ssize_t
cifs_strict_readv(struct kiocb *iocb, const struct iovec *iov,
		  unsigned long nr_segs, loff_t pos)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct cifsFileInfo *cfile = (struct cifsFileInfo *)
						iocb->ki_filp->private_data;
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	int rc = -EACCES;

	if (!cinode->clientCanCacheRead)
		return cifs_user_readv(iocb, iov, nr_segs, pos);

	if (cap_unix(tcon->ses) &&
	    (CIFS_UNIX_FCNTL_CAP & le64_to_cpu(tcon->fsUnixInfo.Capability)) &&
	    ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL) == 0))
		return generic_file_aio_read(iocb, iov, nr_segs, pos);

	down_read(&cinode->lock_sem);
	if (!cifs_find_lock_conflict(cfile, pos, iov_length(iov, nr_segs),
				     tcon->ses->server->vals->shared_lock_type,
				     NULL, CIFS_READ_OP))
		rc = generic_file_aio_read(iocb, iov, nr_segs, pos);
	up_read(&cinode->lock_sem);
	return rc;
}

static ssize_t
cifs_read(struct file *file, char *read_data, size_t read_size, loff_t *offset)
{
	int rc = -EACCES;
	unsigned int bytes_read = 0;
	unsigned int total_read;
	unsigned int current_read_size;
	unsigned int rsize;
	struct cifs_sb_info *cifs_sb;
	struct cifs_tcon *tcon;
	struct TCP_Server_Info *server;
	unsigned int xid;
	char *cur_offset;
	struct cifsFileInfo *open_file;
	struct cifs_io_parms io_parms;
	int buf_type = CIFS_NO_BUFFER;
	__u32 pid;

	xid = get_xid();
	cifs_sb = CIFS_SB(file->f_path.dentry->d_sb);

	rsize = min_t(unsigned int, cifs_sb->rsize, CIFSMaxBufSize);

	if (file->private_data == NULL) {
		rc = -EBADF;
		free_xid(xid);
		return rc;
	}
	open_file = file->private_data;
	tcon = tlink_tcon(open_file->tlink);
	server = tcon->ses->server;

	if (!server->ops->sync_read) {
		free_xid(xid);
		return -ENOSYS;
	}

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		pid = open_file->pid;
	else
		pid = current->tgid;

	if ((file->f_flags & O_ACCMODE) == O_WRONLY)
		cifs_dbg(FYI, "attempting read on write only file instance\n");

	for (total_read = 0, cur_offset = read_data; read_size > total_read;
	     total_read += bytes_read, cur_offset += bytes_read) {
		current_read_size = min_t(uint, read_size - total_read, rsize);
		 
		if ((tcon->ses) && !(tcon->ses->capabilities &
				tcon->ses->server->vals->cap_large_files)) {
			current_read_size = min_t(uint, current_read_size,
					CIFSMaxBufSize);
		}
		rc = -EAGAIN;
		while (rc == -EAGAIN) {
			if (open_file->invalidHandle) {
				rc = cifs_reopen_file(open_file, true);
				if (rc != 0)
					break;
			}
			io_parms.pid = pid;
			io_parms.tcon = tcon;
			io_parms.offset = *offset;
			io_parms.length = current_read_size;
			rc = server->ops->sync_read(xid, open_file, &io_parms,
						    &bytes_read, &cur_offset,
						    &buf_type);
		}
		if (rc || (bytes_read == 0)) {
			if (total_read) {
				break;
			} else {
				free_xid(xid);
				return rc;
			}
		} else {
			cifs_stats_bytes_read(tcon, total_read);
			*offset += bytes_read;
		}
	}
	free_xid(xid);
	return total_read;
}

static int
cifs_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;

	lock_page(page);
	return VM_FAULT_LOCKED;
}

static struct vm_operations_struct cifs_file_vm_ops = {
	.fault = filemap_fault,
	.page_mkwrite = cifs_page_mkwrite,
	.remap_pages = generic_file_remap_pages,
};

int cifs_file_strict_mmap(struct file *file, struct vm_area_struct *vma)
{
	int rc, xid;
	struct inode *inode = file_inode(file);

	xid = get_xid();

	if (!CIFS_I(inode)->clientCanCacheRead) {
		rc = cifs_invalidate_mapping(inode);
		if (rc)
			return rc;
	}

	rc = generic_file_mmap(file, vma);
	if (rc == 0)
		vma->vm_ops = &cifs_file_vm_ops;
	free_xid(xid);
	return rc;
}

int cifs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	int rc, xid;

	xid = get_xid();
	rc = cifs_revalidate_file(file);
	if (rc) {
		cifs_dbg(FYI, "Validation prior to mmap failed, error=%d\n",
			 rc);
		free_xid(xid);
		return rc;
	}
	rc = generic_file_mmap(file, vma);
	if (rc == 0)
		vma->vm_ops = &cifs_file_vm_ops;
	free_xid(xid);
	return rc;
}

static void
cifs_readv_complete(struct work_struct *work)
{
	unsigned int i;
	struct cifs_readdata *rdata = container_of(work,
						struct cifs_readdata, work);

	for (i = 0; i < rdata->nr_pages; i++) {
		struct page *page = rdata->pages[i];

		lru_cache_add_file(page);

		if (rdata->result == 0) {
			flush_dcache_page(page);
			SetPageUptodate(page);
		}

		unlock_page(page);

		if (rdata->result == 0)
			cifs_readpage_to_fscache(rdata->mapping->host, page);

		page_cache_release(page);
		rdata->pages[i] = NULL;
	}
	kref_put(&rdata->refcount, cifs_readdata_release);
}

static int
cifs_readpages_read_into_pages(struct TCP_Server_Info *server,
			struct cifs_readdata *rdata, unsigned int len)
{
	int total_read = 0, result = 0;
	unsigned int i;
	u64 eof;
	pgoff_t eof_index;
	unsigned int nr_pages = rdata->nr_pages;
	struct kvec iov;

	eof = CIFS_I(rdata->mapping->host)->server_eof;
	eof_index = eof ? (eof - 1) >> PAGE_CACHE_SHIFT : 0;
	cifs_dbg(FYI, "eof=%llu eof_index=%lu\n", eof, eof_index);

	rdata->tailsz = PAGE_CACHE_SIZE;
	for (i = 0; i < nr_pages; i++) {
		struct page *page = rdata->pages[i];

		if (len >= PAGE_CACHE_SIZE) {
			 
			iov.iov_base = kmap(page);
			iov.iov_len = PAGE_CACHE_SIZE;
			cifs_dbg(FYI, "%u: idx=%lu iov_base=%p iov_len=%zu\n",
				 i, page->index, iov.iov_base, iov.iov_len);
			len -= PAGE_CACHE_SIZE;
		} else if (len > 0) {
			 
			iov.iov_base = kmap(page);
			iov.iov_len = len;
			cifs_dbg(FYI, "%u: idx=%lu iov_base=%p iov_len=%zu\n",
				 i, page->index, iov.iov_base, iov.iov_len);
			memset(iov.iov_base + len,
				'\0', PAGE_CACHE_SIZE - len);
			rdata->tailsz = len;
			len = 0;
		} else if (page->index > eof_index) {
			 
			zero_user(page, 0, PAGE_CACHE_SIZE);
			lru_cache_add_file(page);
			flush_dcache_page(page);
			SetPageUptodate(page);
			unlock_page(page);
			page_cache_release(page);
			rdata->pages[i] = NULL;
			rdata->nr_pages--;
			continue;
		} else {
			 
			lru_cache_add_file(page);
			unlock_page(page);
			page_cache_release(page);
			rdata->pages[i] = NULL;
			rdata->nr_pages--;
			continue;
		}

		result = cifs_readv_from_socket(server, &iov, 1, iov.iov_len);
		kunmap(page);
		if (result < 0)
			break;

		total_read += result;
	}

	return total_read > 0 && result != -EAGAIN ? total_read : result;
}

static int cifs_readpages(struct file *file, struct address_space *mapping,
	struct list_head *page_list, unsigned num_pages)
{
	int rc;
	struct list_head tmplist;
	struct cifsFileInfo *open_file = file->private_data;
	struct cifs_sb_info *cifs_sb = CIFS_SB(file->f_path.dentry->d_sb);
	unsigned int rsize = cifs_sb->rsize;
	pid_t pid;

	if (unlikely(rsize < PAGE_CACHE_SIZE))
		return 0;

	rc = cifs_readpages_from_fscache(mapping->host, mapping, page_list,
					 &num_pages);
	if (rc == 0)
		return rc;

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		pid = open_file->pid;
	else
		pid = current->tgid;

	rc = 0;
	INIT_LIST_HEAD(&tmplist);

	cifs_dbg(FYI, "%s: file=%p mapping=%p num_pages=%u\n",
		 __func__, file, mapping, num_pages);

	while (!list_empty(page_list)) {
		unsigned int i;
		unsigned int bytes = PAGE_CACHE_SIZE;
		unsigned int expected_index;
		unsigned int nr_pages = 1;
		loff_t offset;
		struct page *page, *tpage;
		struct cifs_readdata *rdata;

		page = list_entry(page_list->prev, struct page, lru);

		__set_page_locked(page);
		rc = add_to_page_cache_locked(page, mapping,
					      page->index, GFP_KERNEL);

		if (rc) {
			__clear_page_locked(page);
			break;
		}

		offset = (loff_t)page->index << PAGE_CACHE_SHIFT;
		list_move_tail(&page->lru, &tmplist);

		expected_index = page->index + 1;
		list_for_each_entry_safe_reverse(page, tpage, page_list, lru) {
			 
			if (page->index != expected_index)
				break;

			if (bytes + PAGE_CACHE_SIZE > rsize)
				break;

			__set_page_locked(page);
			if (add_to_page_cache_locked(page, mapping,
						page->index, GFP_KERNEL)) {
				__clear_page_locked(page);
				break;
			}
			list_move_tail(&page->lru, &tmplist);
			bytes += PAGE_CACHE_SIZE;
			expected_index++;
			nr_pages++;
		}

		rdata = cifs_readdata_alloc(nr_pages, cifs_readv_complete);
		if (!rdata) {
			 
			list_for_each_entry_safe(page, tpage, &tmplist, lru) {
				list_del(&page->lru);
				lru_cache_add_file(page);
				unlock_page(page);
				page_cache_release(page);
			}
			rc = -ENOMEM;
			break;
		}

		rdata->cfile = cifsFileInfo_get(open_file);
		rdata->mapping = mapping;
		rdata->offset = offset;
		rdata->bytes = bytes;
		rdata->pid = pid;
		rdata->pagesz = PAGE_CACHE_SIZE;
		rdata->read_into_pages = cifs_readpages_read_into_pages;

		list_for_each_entry_safe(page, tpage, &tmplist, lru) {
			list_del(&page->lru);
			rdata->pages[rdata->nr_pages++] = page;
		}

		rc = cifs_retry_async_readv(rdata);
		if (rc != 0) {
			for (i = 0; i < rdata->nr_pages; i++) {
				page = rdata->pages[i];
				lru_cache_add_file(page);
				unlock_page(page);
				page_cache_release(page);
			}
			kref_put(&rdata->refcount, cifs_readdata_release);
			break;
		}

		kref_put(&rdata->refcount, cifs_readdata_release);
	}

	return rc;
}

static int cifs_readpage_worker(struct file *file, struct page *page,
	loff_t *poffset)
{
	char *read_data;
	int rc;

	rc = cifs_readpage_from_fscache(file_inode(file), page);
	if (rc == 0)
		goto read_complete;

	page_cache_get(page);
	read_data = kmap(page);
	 
	rc = cifs_read(file, read_data, PAGE_CACHE_SIZE, poffset);

	if (rc < 0)
		goto io_error;
	else
		cifs_dbg(FYI, "Bytes read %d\n", rc);

	file_inode(file)->i_atime =
		current_fs_time(file_inode(file)->i_sb);

	if (PAGE_CACHE_SIZE > rc)
		memset(read_data + rc, 0, PAGE_CACHE_SIZE - rc);

	flush_dcache_page(page);
	SetPageUptodate(page);

	cifs_readpage_to_fscache(file_inode(file), page);

	rc = 0;

io_error:
	kunmap(page);
	page_cache_release(page);

read_complete:
	return rc;
}

static int cifs_readpage(struct file *file, struct page *page)
{
	loff_t offset = (loff_t)page->index << PAGE_CACHE_SHIFT;
	int rc = -EACCES;
	unsigned int xid;

	xid = get_xid();

	if (file->private_data == NULL) {
		rc = -EBADF;
		free_xid(xid);
		return rc;
	}

	cifs_dbg(FYI, "readpage %p at offset %d 0x%x\n",
		 page, (int)offset, (int)offset);

	rc = cifs_readpage_worker(file, page, &offset);

	unlock_page(page);

	free_xid(xid);
	return rc;
}

static int is_inode_writable(struct cifsInodeInfo *cifs_inode)
{
	struct cifsFileInfo *open_file;

	spin_lock(&cifs_file_list_lock);
	list_for_each_entry(open_file, &cifs_inode->openFileList, flist) {
		if (OPEN_FMODE(open_file->f_flags) & FMODE_WRITE) {
			spin_unlock(&cifs_file_list_lock);
			return 1;
		}
	}
	spin_unlock(&cifs_file_list_lock);
	return 0;
}

bool is_size_safe_to_change(struct cifsInodeInfo *cifsInode, __u64 end_of_file)
{
	if (!cifsInode)
		return true;

	if (is_inode_writable(cifsInode)) {
		 
		struct cifs_sb_info *cifs_sb;

		cifs_sb = CIFS_SB(cifsInode->vfs_inode.i_sb);
		if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_DIRECT_IO) {
			 
			return true;
		}

		if (i_size_read(&cifsInode->vfs_inode) < end_of_file)
			return true;

		return false;
	} else
		return true;
}

static int cifs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	loff_t offset = pos & (PAGE_CACHE_SIZE - 1);
	loff_t page_start = pos & PAGE_MASK;
	loff_t i_size;
	struct page *page;
	int rc = 0;

	cifs_dbg(FYI, "write_begin from %lld len %d\n", (long long)pos, len);

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		rc = -ENOMEM;
		goto out;
	}

	if (PageUptodate(page))
		goto out;

	if (len == PAGE_CACHE_SIZE)
		goto out;

	if (CIFS_I(mapping->host)->clientCanCacheRead) {
		i_size = i_size_read(mapping->host);
		if (page_start >= i_size ||
		    (offset == 0 && (pos + len) >= i_size)) {
			zero_user_segments(page, 0, offset,
					   offset + len,
					   PAGE_CACHE_SIZE);
			 
			SetPageChecked(page);
			goto out;
		}
	}

	if ((file->f_flags & O_ACCMODE) != O_WRONLY) {
		 
		cifs_readpage_worker(file, page, &page_start);
	} else {
		 
	}
out:
	*pagep = page;
	return rc;
}

static int cifs_release_page(struct page *page, gfp_t gfp)
{
	if (PagePrivate(page))
		return 0;

	return cifs_fscache_release_page(page, gfp);
}

static void cifs_invalidate_page(struct page *page, unsigned long offset)
{
	struct cifsInodeInfo *cifsi = CIFS_I(page->mapping->host);

	if (offset == 0)
		cifs_fscache_invalidate_page(page, &cifsi->vfs_inode);
}

static int cifs_launder_page(struct page *page)
{
	int rc = 0;
	loff_t range_start = page_offset(page);
	loff_t range_end = range_start + (loff_t)(PAGE_CACHE_SIZE - 1);
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = 0,
		.range_start = range_start,
		.range_end = range_end,
	};

	cifs_dbg(FYI, "Launder page: %p\n", page);

	if (clear_page_dirty_for_io(page))
		rc = cifs_writepage_locked(page, &wbc);

	cifs_fscache_invalidate_page(page, page->mapping->host);
	return rc;
}

void cifs_oplock_break(struct work_struct *work)
{
	struct cifsFileInfo *cfile = container_of(work, struct cifsFileInfo,
						  oplock_break);
	struct inode *inode = cfile->dentry->d_inode;
	struct cifsInodeInfo *cinode = CIFS_I(inode);
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	int rc = 0;

	if (!cinode->clientCanCacheAll && cinode->clientCanCacheRead &&
						cifs_has_mand_locks(cinode)) {
		cifs_dbg(FYI, "Reset oplock to None for inode=%p due to mand locks\n",
			 inode);
		cinode->clientCanCacheRead = false;
	}

	if (inode && S_ISREG(inode->i_mode)) {
		if (cinode->clientCanCacheRead)
			break_lease(inode, O_RDONLY);
		else
			break_lease(inode, O_WRONLY);
		rc = filemap_fdatawrite(inode->i_mapping);
		if (cinode->clientCanCacheRead == 0) {
			rc = filemap_fdatawait(inode->i_mapping);
			mapping_set_error(inode->i_mapping, rc);
			cifs_invalidate_mapping(inode);
		}
		cifs_dbg(FYI, "Oplock flush inode %p rc %d\n", inode, rc);
	}

	rc = cifs_push_locks(cfile);
	if (rc)
		cifs_dbg(VFS, "Push locks rc = %d\n", rc);

	if (!cfile->oplock_break_cancelled) {
		rc = tcon->ses->server->ops->oplock_response(tcon, &cfile->fid,
							     cinode);
		cifs_dbg(FYI, "Oplock release rc = %d\n", rc);
	}
}

const struct address_space_operations cifs_addr_ops = {
	.readpage = cifs_readpage,
	.readpages = cifs_readpages,
	.writepage = cifs_writepage,
	.writepages = cifs_writepages,
	.write_begin = cifs_write_begin,
	.write_end = cifs_write_end,
	.set_page_dirty = __set_page_dirty_nobuffers,
	.releasepage = cifs_release_page,
	.invalidatepage = cifs_invalidate_page,
	.launder_page = cifs_launder_page,
};

const struct address_space_operations cifs_addr_ops_smallbuf = {
	.readpage = cifs_readpage,
	.writepage = cifs_writepage,
	.writepages = cifs_writepages,
	.write_begin = cifs_write_begin,
	.write_end = cifs_write_end,
	.set_page_dirty = __set_page_dirty_nobuffers,
	.releasepage = cifs_release_page,
	.invalidatepage = cifs_invalidate_page,
	.launder_page = cifs_launder_page,
};
