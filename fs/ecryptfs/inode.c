#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/crypto.h>
#include <linux/fs_stack.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <asm/unaligned.h>
#include "ecryptfs_kernel.h"

static struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir;

	dir = dget_parent(dentry);
	mutex_lock_nested(&(dir->d_inode->i_mutex), I_MUTEX_PARENT);
	return dir;
}

static void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}

static int ecryptfs_inode_test(struct inode *inode, void *lower_inode)
{
	if (ecryptfs_inode_to_lower(inode) == (struct inode *)lower_inode)
		return 1;
	return 0;
}

static int ecryptfs_inode_set(struct inode *inode, void *opaque)
{
	struct inode *lower_inode = opaque;

	ecryptfs_set_inode_lower(inode, lower_inode);
	fsstack_copy_attr_all(inode, lower_inode);
	 
	fsstack_copy_inode_size(inode, lower_inode);
	inode->i_ino = lower_inode->i_ino;
	inode->i_version++;
	inode->i_mapping->a_ops = &ecryptfs_aops;
	inode->i_mapping->backing_dev_info = inode->i_sb->s_bdi;

	if (S_ISLNK(inode->i_mode))
		inode->i_op = &ecryptfs_symlink_iops;
	else if (S_ISDIR(inode->i_mode))
		inode->i_op = &ecryptfs_dir_iops;
	else
		inode->i_op = &ecryptfs_main_iops;

	if (S_ISDIR(inode->i_mode))
		inode->i_fop = &ecryptfs_dir_fops;
	else if (special_file(inode->i_mode))
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	else
		inode->i_fop = &ecryptfs_main_fops;

	return 0;
}

static struct inode *__ecryptfs_get_inode(struct inode *lower_inode,
					  struct super_block *sb)
{
	struct inode *inode;

	if (lower_inode->i_sb != ecryptfs_superblock_to_lower(sb))
		return ERR_PTR(-EXDEV);
	if (!igrab(lower_inode))
		return ERR_PTR(-ESTALE);
	inode = iget5_locked(sb, (unsigned long)lower_inode,
			     ecryptfs_inode_test, ecryptfs_inode_set,
			     lower_inode);
	if (!inode) {
		iput(lower_inode);
		return ERR_PTR(-EACCES);
	}
	if (!(inode->i_state & I_NEW))
		iput(lower_inode);

	return inode;
}

struct inode *ecryptfs_get_inode(struct inode *lower_inode,
				 struct super_block *sb)
{
	struct inode *inode = __ecryptfs_get_inode(lower_inode, sb);

	if (!IS_ERR(inode) && (inode->i_state & I_NEW))
		unlock_new_inode(inode);

	return inode;
}

static int ecryptfs_interpose(struct dentry *lower_dentry,
			      struct dentry *dentry, struct super_block *sb)
{
	struct inode *inode = ecryptfs_get_inode(lower_dentry->d_inode, sb);

	if (IS_ERR(inode))
		return PTR_ERR(inode);
	d_instantiate(dentry, inode);

	return 0;
}

static int ecryptfs_do_unlink(struct inode *dir, struct dentry *dentry,
			      struct inode *inode)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);
	struct inode *lower_dir_inode = ecryptfs_inode_to_lower(dir);
	struct dentry *lower_dir_dentry;
	int rc;

	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_unlink(lower_dir_inode, lower_dentry);
	if (rc) {
		printk(KERN_ERR "Error in vfs_unlink; rc = [%d]\n", rc);
		goto out_unlock;
	}
	fsstack_copy_attr_times(dir, lower_dir_inode);
	set_nlink(inode, ecryptfs_inode_to_lower(inode)->i_nlink);
	inode->i_ctime = dir->i_ctime;
	d_drop(dentry);
out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	return rc;
}

static struct inode *
ecryptfs_do_create(struct inode *directory_inode,
		   struct dentry *ecryptfs_dentry, umode_t mode)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct inode *inode;

	lower_dentry = ecryptfs_dentry_to_lower(ecryptfs_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_dir_dentry)) {
		ecryptfs_printk(KERN_ERR, "Error locking directory of "
				"dentry\n");
		inode = ERR_CAST(lower_dir_dentry);
		goto out;
	}
	rc = vfs_create(lower_dir_dentry->d_inode, lower_dentry, mode, true);
	if (rc) {
#ifdef MY_ABC_HERE
		if (-EDQUOT != rc && -ENOSPC != rc)
#endif  
		printk(KERN_ERR "%s: Failure to create dentry in lower fs; "
		       "rc = [%d]\n", __func__, rc);
		inode = ERR_PTR(rc);
		goto out_lock;
	}
	inode = __ecryptfs_get_inode(lower_dentry->d_inode,
				     directory_inode->i_sb);
	if (IS_ERR(inode)) {
		vfs_unlink(lower_dir_dentry->d_inode, lower_dentry);
		goto out_lock;
	}
	fsstack_copy_attr_times(directory_inode, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(directory_inode, lower_dir_dentry->d_inode);
out_lock:
	unlock_dir(lower_dir_dentry);
out:
	return inode;
}

int ecryptfs_initialize_file(struct dentry *ecryptfs_dentry,
			     struct inode *ecryptfs_inode)
{
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	int rc = 0;

	if (S_ISDIR(ecryptfs_inode->i_mode)) {
		ecryptfs_printk(KERN_DEBUG, "This is a directory\n");
		crypt_stat->flags &= ~(ECRYPTFS_ENCRYPTED);
		goto out;
	}
	ecryptfs_printk(KERN_DEBUG, "Initializing crypto context\n");
	rc = ecryptfs_new_file_context(ecryptfs_inode);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error creating new file "
				"context; rc = [%d]\n", rc);
		goto out;
	}
	rc = ecryptfs_get_lower_file(ecryptfs_dentry, ecryptfs_inode);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
			"the lower file for the dentry with name "
			"[%s]; rc = [%d]\n", __func__,
			ecryptfs_dentry->d_name.name, rc);
		goto out;
	}
	rc = ecryptfs_write_metadata(ecryptfs_dentry, ecryptfs_inode);
	if (rc)
#ifdef MY_ABC_HERE
		if (-EDQUOT != rc && -ENOSPC != rc)
#endif  
		printk(KERN_ERR "Error writing headers; rc = [%d]\n", rc);
	ecryptfs_put_lower_file(ecryptfs_inode);
out:
	return rc;
}

static int
ecryptfs_create(struct inode *directory_inode, struct dentry *ecryptfs_dentry,
		umode_t mode, bool excl)
{
	struct inode *ecryptfs_inode;
	int rc;

	ecryptfs_inode = ecryptfs_do_create(directory_inode, ecryptfs_dentry,
					    mode);
	if (unlikely(IS_ERR(ecryptfs_inode))) {
#ifdef MY_ABC_HERE
		if (-EDQUOT != PTR_ERR(ecryptfs_inode) && -ENOSPC != PTR_ERR(ecryptfs_inode))
#endif  
		ecryptfs_printk(KERN_WARNING, "Failed to create file in"
				"lower filesystem\n");
		rc = PTR_ERR(ecryptfs_inode);
		goto out;
	}
	 
	rc = ecryptfs_initialize_file(ecryptfs_dentry, ecryptfs_inode);
	if (rc) {
		ecryptfs_do_unlink(directory_inode, ecryptfs_dentry,
				   ecryptfs_inode);
		make_bad_inode(ecryptfs_inode);
		unlock_new_inode(ecryptfs_inode);
		iput(ecryptfs_inode);
		goto out;
	}
	unlock_new_inode(ecryptfs_inode);
	d_instantiate(ecryptfs_dentry, ecryptfs_inode);
out:
	return rc;
}

static int ecryptfs_i_size_read(struct dentry *dentry, struct inode *inode)
{
	struct ecryptfs_crypt_stat *crypt_stat;
#ifdef MY_ABC_HERE
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&ecryptfs_superblock_to_private(dentry->d_sb)->mount_crypt_stat;
#endif  
	int rc;

	rc = ecryptfs_get_lower_file(dentry, inode);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
			"the lower file for the dentry with name "
			"[%s]; rc = [%d]\n", __func__,
			dentry->d_name.name, rc);
		return rc;
	}

	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	 
	if (!(crypt_stat->flags & ECRYPTFS_POLICY_APPLIED))
		ecryptfs_set_default_sizes(crypt_stat);

#ifdef MY_ABC_HERE
	if (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_FAST_LOOKUP_ENABLED) {
		rc = ecryptfs_read_and_validate_xattr_region(dentry, inode);
		if (rc) {
			rc = ecryptfs_read_and_validate_header_region(inode);
		}
		ecryptfs_put_lower_file(inode);
	}
	else {
#endif  
	rc = ecryptfs_read_and_validate_header_region(inode);
	ecryptfs_put_lower_file(inode);
	if (rc) {
		rc = ecryptfs_read_and_validate_xattr_region(dentry, inode);
		if (!rc)
			crypt_stat->flags |= ECRYPTFS_METADATA_IN_XATTR;
	}
#ifdef MY_ABC_HERE
	}
#endif  
	 
	return 0;
}

static int ecryptfs_lookup_interpose(struct dentry *dentry,
				     struct dentry *lower_dentry,
				     struct inode *dir_inode)
{
	struct inode *inode, *lower_inode = lower_dentry->d_inode;
	struct ecryptfs_dentry_info *dentry_info;
	struct vfsmount *lower_mnt;
	int rc = 0;

	dentry_info = kmem_cache_alloc(ecryptfs_dentry_info_cache, GFP_KERNEL);
	if (!dentry_info) {
		printk(KERN_ERR "%s: Out of memory whilst attempting "
		       "to allocate ecryptfs_dentry_info struct\n",
			__func__);
		dput(lower_dentry);
		return -ENOMEM;
	}

	lower_mnt = mntget(ecryptfs_dentry_to_lower_mnt(dentry->d_parent));
	fsstack_copy_attr_atime(dir_inode, lower_dentry->d_parent->d_inode);
	BUG_ON(!lower_dentry->d_count);

	ecryptfs_set_dentry_private(dentry, dentry_info);
	ecryptfs_set_dentry_lower(dentry, lower_dentry);
	ecryptfs_set_dentry_lower_mnt(dentry, lower_mnt);

	if (!lower_dentry->d_inode) {
		 
		d_add(dentry, NULL);
		return 0;
	}
	inode = __ecryptfs_get_inode(lower_inode, dir_inode->i_sb);
	if (IS_ERR(inode)) {
		printk(KERN_ERR "%s: Error interposing; rc = [%ld]\n",
		       __func__, PTR_ERR(inode));
		return PTR_ERR(inode);
	}
	if (S_ISREG(inode->i_mode)) {
		rc = ecryptfs_i_size_read(dentry, inode);
		if (rc) {
			make_bad_inode(inode);
			return rc;
		}
	}

	if (inode->i_state & I_NEW)
		unlock_new_inode(inode);
	d_add(dentry, inode);

	return rc;
}

static struct dentry *ecryptfs_lookup(struct inode *ecryptfs_dir_inode,
				      struct dentry *ecryptfs_dentry,
				      unsigned int flags)
{
	char *encrypted_and_encoded_name = NULL;
	size_t encrypted_and_encoded_name_size;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat = NULL;
	struct dentry *lower_dir_dentry, *lower_dentry;
	int rc = 0;

	lower_dir_dentry = ecryptfs_dentry_to_lower(ecryptfs_dentry->d_parent);
	mutex_lock(&lower_dir_dentry->d_inode->i_mutex);
	lower_dentry = lookup_one_len(ecryptfs_dentry->d_name.name,
				      lower_dir_dentry,
				      ecryptfs_dentry->d_name.len);
	mutex_unlock(&lower_dir_dentry->d_inode->i_mutex);
	if (IS_ERR(lower_dentry)) {
		rc = PTR_ERR(lower_dentry);
		ecryptfs_printk(KERN_DEBUG, "%s: lookup_one_len() returned "
				"[%d] on lower_dentry = [%s]\n", __func__, rc,
				ecryptfs_dentry->d_name.name);
		goto out;
	}
	if (lower_dentry->d_inode)
		goto interpose;
	mount_crypt_stat = &ecryptfs_superblock_to_private(
				ecryptfs_dentry->d_sb)->mount_crypt_stat;
	if (!(mount_crypt_stat
	    && (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)))
		goto interpose;
	dput(lower_dentry);
	rc = ecryptfs_encrypt_and_encode_filename(
		&encrypted_and_encoded_name, &encrypted_and_encoded_name_size,
		NULL, mount_crypt_stat, ecryptfs_dentry->d_name.name,
		ecryptfs_dentry->d_name.len);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to encrypt and encode "
		       "filename; rc = [%d]\n", __func__, rc);
		goto out;
	}
	mutex_lock(&lower_dir_dentry->d_inode->i_mutex);
	lower_dentry = lookup_one_len(encrypted_and_encoded_name,
				      lower_dir_dentry,
				      encrypted_and_encoded_name_size);
	mutex_unlock(&lower_dir_dentry->d_inode->i_mutex);
	if (IS_ERR(lower_dentry)) {
		rc = PTR_ERR(lower_dentry);
		ecryptfs_printk(KERN_DEBUG, "%s: lookup_one_len() returned "
				"[%d] on lower_dentry = [%s]\n", __func__, rc,
				encrypted_and_encoded_name);
		goto out;
	}
interpose:
	rc = ecryptfs_lookup_interpose(ecryptfs_dentry, lower_dentry,
				       ecryptfs_dir_inode);
out:
	kfree(encrypted_and_encoded_name);
	return ERR_PTR(rc);
}

static int ecryptfs_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int rc;

	file_size_save = i_size_read(old_dentry->d_inode);
	lower_old_dentry = ecryptfs_dentry_to_lower(old_dentry);
	lower_new_dentry = ecryptfs_dentry_to_lower(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_dir_dentry = lock_parent(lower_new_dentry);
	rc = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
		      lower_new_dentry);
	if (rc || !lower_new_dentry->d_inode)
		goto out_lock;
	rc = ecryptfs_interpose(lower_new_dentry, new_dentry, dir->i_sb);
	if (rc)
		goto out_lock;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
		  ecryptfs_inode_to_lower(old_dentry->d_inode)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);
out_lock:
	unlock_dir(lower_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	return rc;
}

static int ecryptfs_unlink(struct inode *dir, struct dentry *dentry)
{
	return ecryptfs_do_unlink(dir, dentry, dentry->d_inode);
}

static int ecryptfs_symlink(struct inode *dir, struct dentry *dentry,
			    const char *symname)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	char *encoded_symname;
	size_t encoded_symlen;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat = NULL;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	mount_crypt_stat = &ecryptfs_superblock_to_private(
		dir->i_sb)->mount_crypt_stat;
	rc = ecryptfs_encrypt_and_encode_filename(&encoded_symname,
						  &encoded_symlen,
						  NULL,
						  mount_crypt_stat, symname,
						  strlen(symname));
	if (rc)
		goto out_lock;
#ifdef MY_ABC_HERE
	if (encoded_symlen > PATH_MAX - 1) {
		kfree(encoded_symname);
		rc = -ENAMETOOLONG;
		goto out_lock;
	}
#endif  
	rc = vfs_symlink(lower_dir_dentry->d_inode, lower_dentry,
			 encoded_symname);
	kfree(encoded_symname);
	if (rc || !lower_dentry->d_inode)
		goto out_lock;
	rc = ecryptfs_interpose(lower_dentry, dentry, dir->i_sb);
	if (rc)
		goto out_lock;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
out_lock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return rc;
}

static int ecryptfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_mkdir(lower_dir_dentry->d_inode, lower_dentry, mode);
	if (rc || !lower_dentry->d_inode)
		goto out;
	rc = ecryptfs_interpose(lower_dentry, dentry, dir->i_sb);
	if (rc)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);
out:
	unlock_dir(lower_dir_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return rc;
}

static int ecryptfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int rc;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	dget(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	dget(lower_dentry);
	rc = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	dput(lower_dentry);
	if (!rc && dentry->d_inode)
		clear_nlink(dentry->d_inode);
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);
	unlock_dir(lower_dir_dentry);
	if (!rc)
		d_drop(dentry);
	dput(dentry);
	return rc;
}

static int
ecryptfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_mknod(lower_dir_dentry->d_inode, lower_dentry, mode, dev);
	if (rc || !lower_dentry->d_inode)
		goto out;
	rc = ecryptfs_interpose(lower_dentry, dentry, dir->i_sb);
	if (rc)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
out:
	unlock_dir(lower_dir_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return rc;
}

static int
ecryptfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	int rc;
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_old_dir_dentry;
	struct dentry *lower_new_dir_dentry;
	struct dentry *trap = NULL;
	struct inode *target_inode;

	lower_old_dentry = ecryptfs_dentry_to_lower(old_dentry);
	lower_new_dentry = ecryptfs_dentry_to_lower(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);
	target_inode = new_dentry->d_inode;
	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	 
	if (trap == lower_old_dentry) {
		rc = -EINVAL;
		goto out_lock;
	}
	 
	if (trap == lower_new_dentry) {
		rc = -ENOTEMPTY;
		goto out_lock;
	}
	rc = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			lower_new_dir_dentry->d_inode, lower_new_dentry);

	if (rc)
		goto out_lock;
	if (target_inode)
		fsstack_copy_attr_all(target_inode,
				      ecryptfs_inode_to_lower(target_inode));
	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir)
		fsstack_copy_attr_all(old_dir, lower_old_dir_dentry->d_inode);
out_lock:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	return rc;
}

static int ecryptfs_readlink_lower(struct dentry *dentry, char **buf,
				   size_t *bufsiz)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);
	char *lower_buf;
	mm_segment_t old_fs;
	int rc;

	lower_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!lower_buf) {
		rc = -ENOMEM;
		goto out;
	}
	old_fs = get_fs();
	set_fs(get_ds());
	rc = lower_dentry->d_inode->i_op->readlink(lower_dentry,
						   (char __user *)lower_buf,
						   PATH_MAX);
	set_fs(old_fs);
	if (rc < 0)
		goto out;
	rc = ecryptfs_decode_and_decrypt_filename(buf, bufsiz, dentry,
						  lower_buf, rc);
out:
	kfree(lower_buf);
	return rc;
}

static void *ecryptfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	size_t len = PATH_MAX;
	int rc;

	rc = ecryptfs_readlink_lower(dentry, &buf, &len);
	if (rc)
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode,
				ecryptfs_dentry_to_lower(dentry)->d_inode);
	buf[len] = '\0';
out:
	nd_set_link(nd, buf);
	return NULL;
}

static void
ecryptfs_put_link(struct dentry *dentry, struct nameidata *nd, void *ptr)
{
	char *buf = nd_get_link(nd);
	if (!IS_ERR(buf)) {
		 
		kfree(buf);
	}
}

static loff_t
upper_size_to_lower_size(struct ecryptfs_crypt_stat *crypt_stat,
			 loff_t upper_size)
{
	loff_t lower_size;

	lower_size = ecryptfs_lower_header_size(crypt_stat);
	if (upper_size != 0) {
		loff_t num_extents;

		num_extents = upper_size >> crypt_stat->extent_shift;
		if (upper_size & ~crypt_stat->extent_mask)
			num_extents++;
		lower_size += (num_extents * crypt_stat->extent_size);
	}
	return lower_size;
}

static int truncate_upper(struct dentry *dentry, struct iattr *ia,
			  struct iattr *lower_ia)
{
	int rc = 0;
	struct inode *inode = dentry->d_inode;
	struct ecryptfs_crypt_stat *crypt_stat;
	loff_t i_size = i_size_read(inode);
#ifdef MY_ABC_HERE
	 
#else
	loff_t lower_size_before_truncate;
#endif  
	loff_t lower_size_after_truncate;

	if (unlikely((ia->ia_size == i_size))) {
		lower_ia->ia_valid &= ~ATTR_SIZE;
		return 0;
	}
	rc = ecryptfs_get_lower_file(dentry, inode);
	if (rc)
		return rc;
	crypt_stat = &ecryptfs_inode_to_private(dentry->d_inode)->crypt_stat;

#ifdef MY_ABC_HERE
	 
#else
	 
	if (ia->ia_size > i_size) {
		char zero[] = { 0x00 };

		lower_ia->ia_valid &= ~ATTR_SIZE;
		 
		rc = ecryptfs_write(inode, zero,
				    (ia->ia_size - 1), 1);
	} else {  
		 
		size_t num_zeros = (PAGE_CACHE_SIZE
				    - (ia->ia_size & ~PAGE_CACHE_MASK));
#endif  

		if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
#ifdef MY_ABC_HERE
			ecryptfs_truncate_setsize(inode, ia->ia_size);
#else
			truncate_setsize(inode, ia->ia_size);
#endif   
			lower_ia->ia_size = ia->ia_size;
			lower_ia->ia_valid |= ATTR_SIZE;
			goto out;
		}
#ifdef MY_ABC_HERE
		 
#else
		if (num_zeros) {
			char *zeros_virt;

			zeros_virt = kzalloc(num_zeros, GFP_KERNEL);
			if (!zeros_virt) {
				rc = -ENOMEM;
				goto out;
			}
			rc = ecryptfs_write(inode, zeros_virt,
					    ia->ia_size, num_zeros);
			kfree(zeros_virt);
			if (rc) {
				printk(KERN_ERR "Error attempting to zero out "
				       "the remainder of the end page on "
				       "reducing truncate; rc = [%d]\n", rc);
				goto out;
			}
		}
#endif  
#ifdef MY_ABC_HERE
		ecryptfs_truncate_setsize(inode, ia->ia_size);
#else
		truncate_setsize(inode, ia->ia_size);
#endif  
		rc = ecryptfs_write_inode_size_to_metadata(inode);
		if (rc) {
#ifdef MY_ABC_HERE
			if (-EDQUOT != rc && -ENOSPC != rc)
#endif  
			printk(KERN_ERR	"Problem with "
			       "ecryptfs_write_inode_size_to_metadata; "
			       "rc = [%d]\n", rc);
			goto out;
		}
#ifdef MY_ABC_HERE
		 
#else
		 
		lower_size_before_truncate =
		    upper_size_to_lower_size(crypt_stat, i_size);
#endif  
		lower_size_after_truncate =
		    upper_size_to_lower_size(crypt_stat, ia->ia_size);
#ifdef MY_ABC_HERE
		lower_ia->ia_size = lower_size_after_truncate;
		lower_ia->ia_valid |= ATTR_SIZE;
#else
		if (lower_size_after_truncate < lower_size_before_truncate) {
			lower_ia->ia_size = lower_size_after_truncate;
			lower_ia->ia_valid |= ATTR_SIZE;
		} else
			lower_ia->ia_valid &= ~ATTR_SIZE;
	}
#endif  
out:
	ecryptfs_put_lower_file(inode);
	return rc;
}

static int ecryptfs_inode_newsize_ok(struct inode *inode, loff_t offset)
{
	struct ecryptfs_crypt_stat *crypt_stat;
	loff_t lower_oldsize, lower_newsize;

	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	lower_oldsize = upper_size_to_lower_size(crypt_stat,
						 i_size_read(inode));
	lower_newsize = upper_size_to_lower_size(crypt_stat, offset);
	if (lower_newsize > lower_oldsize) {
		 
		return inode_newsize_ok(inode, lower_newsize);
	}

	return 0;
}

int ecryptfs_truncate(struct dentry *dentry, loff_t new_length)
{
	struct iattr ia = { .ia_valid = ATTR_SIZE, .ia_size = new_length };
	struct iattr lower_ia = { .ia_valid = 0 };
	int rc;

	rc = ecryptfs_inode_newsize_ok(dentry->d_inode, new_length);
	if (rc)
		return rc;

	rc = truncate_upper(dentry, &ia, &lower_ia);
	if (!rc && lower_ia.ia_valid & ATTR_SIZE) {
		struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

		mutex_lock(&lower_dentry->d_inode->i_mutex);
		rc = notify_change(lower_dentry, &lower_ia);
		mutex_unlock(&lower_dentry->d_inode->i_mutex);
	}
	return rc;
}

#ifdef MY_ABC_HERE
static int ecryptfs_syno_set_crtime(struct dentry *dentry, struct timespec *time)
{
	int error;
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	error = syno_op_set_crtime(lower_dentry, time);
	if (!error) {
		dentry->d_inode->i_create_time = *time;
	}
	return error;
}
#endif  

#ifdef MY_ABC_HERE
static int ecryptfs_syno_set_archive_bit(struct dentry *dentry, unsigned int arbit)
{
	int error;
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	error = syno_op_set_archive_bit(lower_dentry, arbit);
	if (!error) {
		dentry->d_inode->i_archive_bit = arbit;
	}
	return error;
}
#endif  

#ifdef MY_ABC_HERE
static int ecryptfs_syno_set_archive_ver(struct dentry *dentry, u32 version)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	if (!lower_dentry->d_inode->i_op->syno_set_archive_ver)
		return -EINVAL;
	return lower_dentry->d_inode->i_op->syno_set_archive_ver(lower_dentry, version);
}

static int ecryptfs_syno_get_archive_ver(struct dentry *dentry, u32 *version)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	if (!lower_dentry->d_inode->i_op->syno_get_archive_ver)
		return -EINVAL;
	return lower_dentry->d_inode->i_op->syno_get_archive_ver(lower_dentry, version);
}
#endif  

#ifdef MY_ABC_HERE
static int
ecryptfs_syno_getattr(struct dentry *dentry, struct kstat *st, int flags)
{
	struct inode *lower_inode = NULL;
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

	lower_inode = lower_dentry->d_inode;
	if (lower_inode->i_op->syno_getattr) {
		return lower_inode->i_op->syno_getattr(lower_dentry, st, flags);
	}
	return -EOPNOTSUPP;
}
#endif  

static int
ecryptfs_permission(struct inode *inode, int mask)
{
	return inode_permission(ecryptfs_inode_to_lower(inode), mask);
}

static int ecryptfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int rc = 0;
	struct dentry *lower_dentry;
	struct iattr lower_ia;
	struct inode *inode;
	struct inode *lower_inode;
	struct ecryptfs_crypt_stat *crypt_stat;

	crypt_stat = &ecryptfs_inode_to_private(dentry->d_inode)->crypt_stat;
	if (!(crypt_stat->flags & ECRYPTFS_STRUCT_INITIALIZED))
		ecryptfs_init_crypt_stat(crypt_stat);
	inode = dentry->d_inode;
	lower_inode = ecryptfs_inode_to_lower(inode);
	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	mutex_lock(&crypt_stat->cs_mutex);
	if (S_ISDIR(dentry->d_inode->i_mode))
		crypt_stat->flags &= ~(ECRYPTFS_ENCRYPTED);
	else if (S_ISREG(dentry->d_inode->i_mode)
		 && (!(crypt_stat->flags & ECRYPTFS_POLICY_APPLIED)
		     || !(crypt_stat->flags & ECRYPTFS_KEY_VALID))) {
		struct ecryptfs_mount_crypt_stat *mount_crypt_stat;

		mount_crypt_stat = &ecryptfs_superblock_to_private(
			dentry->d_sb)->mount_crypt_stat;
		rc = ecryptfs_get_lower_file(dentry, inode);
		if (rc) {
			mutex_unlock(&crypt_stat->cs_mutex);
			goto out;
		}
		rc = ecryptfs_read_metadata(dentry);
		ecryptfs_put_lower_file(inode);
		if (rc) {
			if (!(mount_crypt_stat->flags
			      & ECRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED)) {
				rc = -EIO;
				printk(KERN_WARNING "Either the lower file "
				       "is not in a valid eCryptfs format, "
				       "or the key could not be retrieved. "
				       "Plaintext passthrough mode is not "
				       "enabled; returning -EIO\n");
				mutex_unlock(&crypt_stat->cs_mutex);
				goto out;
			}
			rc = 0;
			crypt_stat->flags &= ~(ECRYPTFS_I_SIZE_INITIALIZED
					       | ECRYPTFS_ENCRYPTED);
		}
	}
	mutex_unlock(&crypt_stat->cs_mutex);

	rc = inode_change_ok(inode, ia);
	if (rc)
		goto out;
	if (ia->ia_valid & ATTR_SIZE) {
		rc = ecryptfs_inode_newsize_ok(inode, ia->ia_size);
		if (rc)
			goto out;
	}

	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = ecryptfs_file_to_lower(ia->ia_file);
	if (ia->ia_valid & ATTR_SIZE) {
		rc = truncate_upper(dentry, ia, &lower_ia);
		if (rc < 0)
			goto out;
	}

	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = notify_change(lower_dentry, &lower_ia);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	fsstack_copy_attr_all(inode, lower_inode);
	return rc;
}

static int ecryptfs_getattr_link(struct vfsmount *mnt, struct dentry *dentry,
				 struct kstat *stat)
{
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	int rc = 0;

	mount_crypt_stat = &ecryptfs_superblock_to_private(
						dentry->d_sb)->mount_crypt_stat;
	generic_fillattr(dentry->d_inode, stat);
	if (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES) {
		char *target;
		size_t targetsiz;

		rc = ecryptfs_readlink_lower(dentry, &target, &targetsiz);
		if (!rc) {
			kfree(target);
			stat->size = targetsiz;
		}
	}
	return rc;
}

static int ecryptfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			    struct kstat *stat)
{
	struct kstat lower_stat;
	int rc;

	rc = vfs_getattr(ecryptfs_dentry_to_lower_path(dentry), &lower_stat);
	if (!rc) {
		fsstack_copy_attr_all(dentry->d_inode,
				      ecryptfs_inode_to_lower(dentry->d_inode));
		generic_fillattr(dentry->d_inode, stat);
		stat->blocks = lower_stat.blocks;
	}
	return rc;
}

int
ecryptfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		  size_t size, int flags)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->setxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	rc = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (!rc && dentry->d_inode)
		fsstack_copy_attr_all(dentry->d_inode, lower_dentry->d_inode);
out:
	return rc;
}

ssize_t
ecryptfs_getxattr_lower(struct dentry *lower_dentry, const char *name,
			void *value, size_t size)
{
	int rc = 0;

	if (!lower_dentry->d_inode->i_op->getxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->getxattr(lower_dentry, name, value,
						   size);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

static ssize_t
ecryptfs_getxattr(struct dentry *dentry, const char *name, void *value,
		  size_t size)
{
	return ecryptfs_getxattr_lower(ecryptfs_dentry_to_lower(dentry), name,
				       value, size);
}

static ssize_t
ecryptfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->listxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->listxattr(lower_dentry, list, size);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

static int ecryptfs_removexattr(struct dentry *dentry, const char *name)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->removexattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->removexattr(lower_dentry, name);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

const struct inode_operations ecryptfs_symlink_iops = {
#ifdef MY_ABC_HERE
	.syno_getattr = ecryptfs_syno_getattr,
#endif
#ifdef MY_ABC_HERE
	.syno_set_crtime = ecryptfs_syno_set_crtime,
#endif
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = ecryptfs_syno_set_archive_bit,
#endif
#ifdef MY_ABC_HERE
	.syno_get_archive_ver = ecryptfs_syno_get_archive_ver,
	.syno_set_archive_ver = ecryptfs_syno_set_archive_ver,
#endif
	.readlink = generic_readlink,
	.follow_link = ecryptfs_follow_link,
	.put_link = ecryptfs_put_link,
	.permission = ecryptfs_permission,
	.setattr = ecryptfs_setattr,
	.getattr = ecryptfs_getattr_link,
	.setxattr = ecryptfs_setxattr,
	.getxattr = ecryptfs_getxattr,
	.listxattr = ecryptfs_listxattr,
	.removexattr = ecryptfs_removexattr
};

const struct inode_operations ecryptfs_dir_iops = {
#ifdef MY_ABC_HERE
	.syno_getattr = ecryptfs_syno_getattr,
#endif
#ifdef MY_ABC_HERE
	.syno_set_crtime = ecryptfs_syno_set_crtime,
#endif
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = ecryptfs_syno_set_archive_bit,
#endif
#ifdef MY_ABC_HERE
	.syno_get_archive_ver = ecryptfs_syno_get_archive_ver,
	.syno_set_archive_ver = ecryptfs_syno_set_archive_ver,
#endif
	.create = ecryptfs_create,
	.lookup = ecryptfs_lookup,
	.link = ecryptfs_link,
	.unlink = ecryptfs_unlink,
	.symlink = ecryptfs_symlink,
	.mkdir = ecryptfs_mkdir,
	.rmdir = ecryptfs_rmdir,
	.mknod = ecryptfs_mknod,
	.rename = ecryptfs_rename,
	.permission = ecryptfs_permission,
	.setattr = ecryptfs_setattr,
	.setxattr = ecryptfs_setxattr,
	.getxattr = ecryptfs_getxattr,
	.listxattr = ecryptfs_listxattr,
	.removexattr = ecryptfs_removexattr
};

const struct inode_operations ecryptfs_main_iops = {
#ifdef MY_ABC_HERE
	.syno_getattr = ecryptfs_syno_getattr,
#endif
#ifdef MY_ABC_HERE
	.syno_set_crtime = ecryptfs_syno_set_crtime,
#endif
#ifdef MY_ABC_HERE
	.syno_set_archive_bit = ecryptfs_syno_set_archive_bit,
#endif
#ifdef MY_ABC_HERE
	.syno_get_archive_ver = ecryptfs_syno_get_archive_ver,
	.syno_set_archive_ver = ecryptfs_syno_set_archive_ver,
#endif
	.permission = ecryptfs_permission,
	.setattr = ecryptfs_setattr,
	.getattr = ecryptfs_getattr,
	.setxattr = ecryptfs_setxattr,
	.getxattr = ecryptfs_getxattr,
	.listxattr = ecryptfs_listxattr,
	.removexattr = ecryptfs_removexattr
};
