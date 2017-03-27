#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/slab.h>

#ifdef MY_ABC_HERE
#include "../synoacl_int.h"
#endif  

#ifdef MY_ABC_HERE
#include "../ntfs/time.h"
#include "../ntfs/endian.h"
#endif  

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
#include <linux/xattr.h>
#endif  

static bool fuse_use_readdirplus(struct inode *dir, struct file *filp)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_inode *fi = get_fuse_inode(dir);

	if (!fc->do_readdirplus)
		return false;
	if (!fc->readdirplus_auto)
		return true;
	if (test_and_clear_bit(FUSE_I_ADVISE_RDPLUS, &fi->state))
		return true;
	if (filp->f_pos == 0)
		return true;
	return false;
}

static void fuse_advise_use_readdirplus(struct inode *dir)
{
	struct fuse_inode *fi = get_fuse_inode(dir);

	set_bit(FUSE_I_ADVISE_RDPLUS, &fi->state);
}

#if BITS_PER_LONG >= 64
static inline void fuse_dentry_settime(struct dentry *entry, u64 time)
{
	entry->d_time = time;
}

static inline u64 fuse_dentry_time(struct dentry *entry)
{
	return entry->d_time;
}
#else
 
static void fuse_dentry_settime(struct dentry *entry, u64 time)
{
	entry->d_time = time;
	entry->d_fsdata = (void *) (unsigned long) (time >> 32);
}

static u64 fuse_dentry_time(struct dentry *entry)
{
	return (u64) entry->d_time +
		((u64) (unsigned long) entry->d_fsdata << 32);
}
#endif

static u64 time_to_jiffies(unsigned long sec, unsigned long nsec)
{
	if (sec || nsec) {
		struct timespec ts = {sec, nsec};
		return get_jiffies_64() + timespec_to_jiffies(&ts);
	} else
		return 0;
}

static void fuse_change_entry_timeout(struct dentry *entry,
				      struct fuse_entry_out *o)
{
	fuse_dentry_settime(entry,
		time_to_jiffies(o->entry_valid, o->entry_valid_nsec));
}

static u64 attr_timeout(struct fuse_attr_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

static u64 entry_attr_timeout(struct fuse_entry_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

void fuse_invalidate_attr(struct inode *inode)
{
	get_fuse_inode(inode)->i_time = 0;
}

void fuse_invalidate_entry_cache(struct dentry *entry)
{
	fuse_dentry_settime(entry, 0);
}

static void fuse_invalidate_entry(struct dentry *entry)
{
	d_invalidate(entry);
	fuse_invalidate_entry_cache(entry);
}

#ifdef MY_ABC_HERE
static void fuse_lookup_init(struct fuse_conn *fc, struct fuse_req *req,
			     u64 nodeid, struct qstr *name,
			     struct fuse_entry_out *outarg,
			     struct fuse_synostat *synostat,
			     int syno_stat_flags, int is_glusterfs)
#else
static void fuse_lookup_init(struct fuse_conn *fc, struct fuse_req *req,
			     u64 nodeid, struct qstr *name,
			     struct fuse_entry_out *outarg)
#endif  
{
	memset(outarg, 0, sizeof(struct fuse_entry_out));
	req->in.h.opcode = FUSE_LOOKUP;
	req->in.h.nodeid = nodeid;
#ifdef MY_ABC_HERE
	if (is_glusterfs) {
		req->in.numargs = 2;
		req->in.args[1].size = sizeof(syno_stat_flags);
		req->in.args[1].value = &syno_stat_flags;
	} else
#endif  
	req->in.numargs = 1;
	req->in.args[0].size = name->len + 1;
	req->in.args[0].value = name->name;
#ifdef MY_ABC_HERE
	if (synostat && is_glusterfs) {
		req->out.numargs = 2;
		req->out.argvar = 1;
		req->out.args[1].size = FUSE_SYNOSTAT_SIZE;
		req->out.args[1].value = synostat;
	} else
#endif  
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(struct fuse_entry_out);
	req->out.args[0].value = outarg;
}

u64 fuse_get_attr_version(struct fuse_conn *fc)
{
	u64 curr_version;

	spin_lock(&fc->lock);
	curr_version = fc->attr_version;
	spin_unlock(&fc->lock);

	return curr_version;
}

static int fuse_dentry_revalidate(struct dentry *entry, unsigned int flags)
{
	struct inode *inode;
	struct dentry *parent;
	struct fuse_conn *fc;

	inode = ACCESS_ONCE(entry->d_inode);
	if (inode && is_bad_inode(inode))
		return 0;
	else if (fuse_dentry_time(entry) < get_jiffies_64()) {
		int err;
		struct fuse_entry_out outarg;
		struct fuse_req *req;
		struct fuse_forget_link *forget;
		u64 attr_version;

		if (!inode)
			return 0;

		if (flags & LOOKUP_RCU)
			return -ECHILD;

		fc = get_fuse_conn(inode);
		req = fuse_get_req_nopages(fc);
		if (IS_ERR(req))
			return 0;

		forget = fuse_alloc_forget();
		if (!forget) {
			fuse_put_request(fc, req);
			return 0;
		}

		attr_version = fuse_get_attr_version(fc);

		parent = dget_parent(entry);
#ifdef MY_ABC_HERE
		fuse_lookup_init(fc, req, get_node_id(parent->d_inode),
				 &entry->d_name, &outarg, NULL, 0, IS_GLUSTER_FS(inode));
#else
		fuse_lookup_init(fc, req, get_node_id(parent->d_inode),
				 &entry->d_name, &outarg);
#endif  
		fuse_request_send(fc, req);
		dput(parent);
		err = req->out.h.error;
		fuse_put_request(fc, req);
		 
		if (!err && !outarg.nodeid)
			err = -ENOENT;
		if (!err) {
			struct fuse_inode *fi = get_fuse_inode(inode);
			if (outarg.nodeid != get_node_id(inode)) {
				fuse_queue_forget(fc, forget, outarg.nodeid, 1);
				return 0;
			}
			spin_lock(&fc->lock);
			fi->nlookup++;
			spin_unlock(&fc->lock);
		}
		kfree(forget);
		if (err || (outarg.attr.mode ^ inode->i_mode) & S_IFMT)
			return 0;

		fuse_change_attributes(inode, &outarg.attr,
				       entry_attr_timeout(&outarg),
				       attr_version);
		fuse_change_entry_timeout(entry, &outarg);
	} else if (inode) {
		fc = get_fuse_conn(inode);
		if (fc->readdirplus_auto) {
			parent = dget_parent(entry);
			fuse_advise_use_readdirplus(parent->d_inode);
			dput(parent);
		}
	}
	return 1;
}

static int invalid_nodeid(u64 nodeid)
{
	return !nodeid || nodeid == FUSE_ROOT_ID;
}

const struct dentry_operations fuse_dentry_operations = {
	.d_revalidate	= fuse_dentry_revalidate,
};

int fuse_valid_type(int m)
{
	return S_ISREG(m) || S_ISDIR(m) || S_ISLNK(m) || S_ISCHR(m) ||
		S_ISBLK(m) || S_ISFIFO(m) || S_ISSOCK(m);
}

static struct dentry *fuse_d_add_directory(struct dentry *entry,
					   struct inode *inode)
{
	struct dentry *alias = d_find_alias(inode);
	if (alias && !(alias->d_flags & DCACHE_DISCONNECTED)) {
		 
		fuse_invalidate_entry(alias);
		dput(alias);
		if (!hlist_empty(&inode->i_dentry))
			return ERR_PTR(-EBUSY);
	} else {
		dput(alias);
	}
	return d_splice_alias(inode, entry);
}

#ifdef MY_ABC_HERE
int fuse_lookup_name(struct super_block *sb, u64 nodeid, struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode,
		     struct fuse_synostat *synostat, int syno_stat_flags)
#else
int fuse_lookup_name(struct super_block *sb, u64 nodeid, struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode)
#endif  
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	struct fuse_req *req;
	struct fuse_forget_link *forget;
	u64 attr_version;
	int err;
#ifdef MY_ABC_HERE
	char *result_name = NULL;
	int result_name_len = 0;
	int caseless = IS_GLUSTER_FS_SB(sb) && (syno_stat_flags & SYNOST_IS_CASELESS);
	char *new_dname = NULL;
	const char *ext_dname = NULL;
#endif  

	*inode = NULL;
	err = -ENAMETOOLONG;
	if (name->len > FUSE_NAME_MAX)
		goto out;

	req = fuse_get_req_nopages(fc);
	err = PTR_ERR(req);
	if (IS_ERR(req))
		goto out;

	forget = fuse_alloc_forget();
	err = -ENOMEM;
	if (!forget) {
		fuse_put_request(fc, req);
		goto out;
	}

	attr_version = fuse_get_attr_version(fc);

#ifdef MY_ABC_HERE
	if (caseless && synostat) {
		result_name = synostat->name;
		synostat->name_len = SYNO_FUSE_ENTRY_NAME_LEN + 1;
	}
	fuse_lookup_init(fc, req, nodeid, name, outarg, synostat, syno_stat_flags, IS_GLUSTER_FS_SB(sb));
	fuse_request_send(fc, req);
	if (caseless && synostat) {
		result_name_len = req->out.args[1].size - sizeof(*synostat);
		result_name[result_name_len] = '\0';
	}
#else
	fuse_lookup_init(fc, req, nodeid, name, outarg);
	fuse_request_send(fc, req);
#endif  
	err = req->out.h.error;
	fuse_put_request(fc, req);
	 
	if (err || !outarg->nodeid)
		goto out_put_forget;

	err = -EIO;
	if (!outarg->nodeid)
		goto out_put_forget;
	if (!fuse_valid_type(outarg->attr.mode))
		goto out_put_forget;

	*inode = fuse_iget(sb, outarg->nodeid, outarg->generation,
			   &outarg->attr, entry_attr_timeout(outarg),
			   attr_version);
#ifdef MY_ABC_HERE
	if (caseless && synostat && dentry_string_cmp(name->name, result_name, result_name_len)) {
		if (result_name_len > (DNAME_INLINE_LEN - 1) && result_name_len > name->len) {
			new_dname = kmalloc(result_name_len + 1, GFP_KERNEL);
			if (!new_dname) {
				return -1;
			}
			if (name->len > (DNAME_INLINE_LEN -1)) {
				ext_dname = name->name;
			}
			memcpy((unsigned char*)new_dname, result_name, result_name_len);
			new_dname[result_name_len] = 0;

			name->len = result_name_len;
			name->name = new_dname;

			if (ext_dname) {
				kfree(ext_dname);
			}
		} else {
			memcpy((unsigned char *)name->name, result_name, result_name_len);
			((char*)name->name)[result_name_len] = 0;
			name->len = result_name_len;
		}
	}
#endif  
	err = -ENOMEM;
	if (!*inode) {
		fuse_queue_forget(fc, forget, outarg->nodeid, 1);
		goto out;
	}
	err = 0;

 out_put_forget:
	kfree(forget);
 out:
	return err;
}

static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry,
				  unsigned int flags)
{
	int err;
	struct fuse_entry_out outarg;
#ifdef MY_ABC_HERE
	struct fuse_synostat *synostat = NULL;
#endif  
	struct inode *inode;
	struct dentry *newent;
	struct fuse_conn *fc = get_fuse_conn(dir);
	bool outarg_valid = true;

#ifdef MY_ABC_HERE
	if ((flags & LOOKUP_CASELESS_COMPARE) && IS_GLUSTER_FS(dir)) {
		synostat = kmalloc(FUSE_SYNOSTAT_SIZE, GFP_KERNEL);
		memset(synostat, 0, FUSE_SYNOSTAT_SIZE);
	}
	err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &entry->d_name,
			       &outarg, &inode, synostat, (flags & LOOKUP_CASELESS_COMPARE) ? SYNOST_IS_CASELESS : 0);
	kfree(synostat);
#else
	err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &entry->d_name,
			       &outarg, &inode);
#endif  
	if (err == -ENOENT) {
		outarg_valid = false;
		err = 0;
	}
	if (err)
		goto out_err;

	err = -EIO;
	if (inode && get_node_id(inode) == FUSE_ROOT_ID)
		goto out_iput;

	if (inode && S_ISDIR(inode->i_mode)) {
		mutex_lock(&fc->inst_mutex);
		newent = fuse_d_add_directory(entry, inode);
		mutex_unlock(&fc->inst_mutex);
		err = PTR_ERR(newent);
		if (IS_ERR(newent))
			goto out_iput;
	} else {
		newent = d_splice_alias(inode, entry);
	}

	entry = newent ? newent : entry;
	if (outarg_valid)
		fuse_change_entry_timeout(entry, &outarg);
	else
		fuse_invalidate_entry_cache(entry);

	fuse_advise_use_readdirplus(dir);
	return newent;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

static int fuse_create_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened)
{
	int err;
	struct inode *inode;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req;
	struct fuse_forget_link *forget;
	struct fuse_create_in inarg;
	struct fuse_open_out outopen;
	struct fuse_entry_out outentry;
	struct fuse_file *ff;

	BUG_ON((mode & S_IFMT) != S_IFREG);

	forget = fuse_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out_err;

	req = fuse_get_req_nopages(fc);
	err = PTR_ERR(req);
	if (IS_ERR(req))
		goto out_put_forget_req;

	err = -ENOMEM;
	ff = fuse_file_alloc(fc);
	if (!ff)
		goto out_put_request;

	if (!fc->dont_mask)
		mode &= ~current_umask();

	flags &= ~O_NOCTTY;
	memset(&inarg, 0, sizeof(inarg));
	memset(&outentry, 0, sizeof(outentry));
	inarg.flags = flags;
	inarg.mode = mode;
	inarg.umask = current_umask();
	req->in.h.opcode = FUSE_CREATE;
	req->in.h.nodeid = get_node_id(dir);
	req->in.numargs = 2;
	req->in.args[0].size = fc->minor < 12 ? sizeof(struct fuse_open_in) :
						sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	req->out.numargs = 2;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outentry);
	req->out.args[0].value = &outentry;
	req->out.args[1].size = sizeof(outopen);
	req->out.args[1].value = &outopen;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	if (err)
		goto out_free_ff;

	err = -EIO;
	if (!S_ISREG(outentry.attr.mode) || invalid_nodeid(outentry.nodeid))
		goto out_free_ff;

	fuse_put_request(fc, req);
	ff->fh = outopen.fh;
	ff->nodeid = outentry.nodeid;
	ff->open_flags = outopen.open_flags;
	inode = fuse_iget(dir->i_sb, outentry.nodeid, outentry.generation,
			  &outentry.attr, entry_attr_timeout(&outentry), 0);
	if (!inode) {
		flags &= ~(O_CREAT | O_EXCL | O_TRUNC);
		fuse_sync_release(ff, flags);
		fuse_queue_forget(fc, forget, outentry.nodeid, 1);
		err = -ENOMEM;
		goto out_err;
	}
	kfree(forget);
	d_instantiate(entry, inode);
	fuse_change_entry_timeout(entry, &outentry);
	fuse_invalidate_attr(dir);
	err = finish_open(file, entry, generic_file_open, opened);
	if (err) {
		fuse_sync_release(ff, flags);
	} else {
		file->private_data = fuse_file_get(ff);
		fuse_finish_open(inode, file);
	}
	return err;

out_free_ff:
	fuse_file_free(ff);
out_put_request:
	fuse_put_request(fc, req);
out_put_forget_req:
	kfree(forget);
out_err:
	return err;
}

static int fuse_mknod(struct inode *, struct dentry *, umode_t, dev_t);
static int fuse_atomic_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned flags,
			    umode_t mode, int *opened)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct dentry *res = NULL;

	if (d_unhashed(entry)) {
		res = fuse_lookup(dir, entry, 0);
		if (IS_ERR(res))
			return PTR_ERR(res);

		if (res)
			entry = res;
	}

	if (!(flags & O_CREAT) || entry->d_inode)
		goto no_open;

	*opened |= FILE_CREATED;

	if (fc->no_create)
		goto mknod;

	err = fuse_create_open(dir, entry, file, flags, mode, opened);
	if (err == -ENOSYS) {
		fc->no_create = 1;
		goto mknod;
	}
out_dput:
	dput(res);
	return err;

mknod:
	err = fuse_mknod(dir, entry, mode, 0);
	if (err)
		goto out_dput;
no_open:
	return finish_no_open(file, res);
}

static int create_new_entry(struct fuse_conn *fc, struct fuse_req *req,
			    struct inode *dir, struct dentry *entry,
			    umode_t mode)
{
	struct fuse_entry_out outarg;
	struct inode *inode;
	int err;
	struct fuse_forget_link *forget;

	forget = fuse_alloc_forget();
	if (!forget) {
		fuse_put_request(fc, req);
		return -ENOMEM;
	}

	memset(&outarg, 0, sizeof(outarg));
	req->in.h.nodeid = get_node_id(dir);
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err)
		goto out_put_forget_req;

	err = -EIO;
	if (invalid_nodeid(outarg.nodeid))
		goto out_put_forget_req;

	if ((outarg.attr.mode ^ mode) & S_IFMT)
		goto out_put_forget_req;

	inode = fuse_iget(dir->i_sb, outarg.nodeid, outarg.generation,
			  &outarg.attr, entry_attr_timeout(&outarg), 0);
	if (!inode) {
		fuse_queue_forget(fc, forget, outarg.nodeid, 1);
		return -ENOMEM;
	}
	kfree(forget);

	if (S_ISDIR(inode->i_mode)) {
		struct dentry *alias;
		mutex_lock(&fc->inst_mutex);
		alias = d_find_alias(inode);
		if (alias) {
			 
			mutex_unlock(&fc->inst_mutex);
			dput(alias);
			iput(inode);
			return -EBUSY;
		}
		d_instantiate(entry, inode);
		mutex_unlock(&fc->inst_mutex);
	} else
		d_instantiate(entry, inode);

	fuse_change_entry_timeout(entry, &outarg);
	fuse_invalidate_attr(dir);
	return 0;

 out_put_forget_req:
	kfree(forget);
	return err;
}

static int fuse_mknod(struct inode *dir, struct dentry *entry, umode_t mode,
		      dev_t rdev)
{
	struct fuse_mknod_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (!fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	inarg.umask = current_umask();
	req->in.h.opcode = FUSE_MKNOD;
	req->in.numargs = 2;
	req->in.args[0].size = fc->minor < 12 ? FUSE_COMPAT_MKNOD_IN_SIZE :
						sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, req, dir, entry, mode);
}

static int fuse_create(struct inode *dir, struct dentry *entry, umode_t mode,
		       bool excl)
{
	return fuse_mknod(dir, entry, mode, 0);
}

static int fuse_mkdir(struct inode *dir, struct dentry *entry, umode_t mode)
{
	struct fuse_mkdir_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (!fc->dont_mask)
		mode &= ~current_umask();

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.umask = current_umask();
	req->in.h.opcode = FUSE_MKDIR;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, req, dir, entry, S_IFDIR);
}

static int fuse_symlink(struct inode *dir, struct dentry *entry,
			const char *link)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	unsigned len = strlen(link) + 1;
	struct fuse_req *req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.opcode = FUSE_SYMLINK;
	req->in.numargs = 2;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	req->in.args[1].size = len;
	req->in.args[1].value = link;
	return create_new_entry(fc, req, dir, entry, S_IFLNK);
}

static int fuse_unlink(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.opcode = FUSE_UNLINK;
	req->in.h.nodeid = get_node_id(dir);
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		struct inode *inode = entry->d_inode;
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		 
		if (inode->i_nlink > 0)
			drop_nlink(inode);
		spin_unlock(&fc->lock);
		fuse_invalidate_attr(inode);
		fuse_invalidate_attr(dir);
		fuse_invalidate_entry_cache(entry);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rmdir(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.opcode = FUSE_RMDIR;
	req->in.h.nodeid = get_node_id(dir);
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		clear_nlink(entry->d_inode);
		fuse_invalidate_attr(dir);
		fuse_invalidate_entry_cache(entry);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rename(struct inode *olddir, struct dentry *oldent,
		       struct inode *newdir, struct dentry *newent)
{
	int err;
	struct fuse_rename_in inarg;
	struct fuse_conn *fc = get_fuse_conn(olddir);
	struct fuse_req *req = fuse_get_req_nopages(fc);

	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.newdir = get_node_id(newdir);
	req->in.h.opcode = FUSE_RENAME;
	req->in.h.nodeid = get_node_id(olddir);
	req->in.numargs = 3;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = oldent->d_name.len + 1;
	req->in.args[1].value = oldent->d_name.name;
	req->in.args[2].size = newent->d_name.len + 1;
	req->in.args[2].value = newent->d_name.name;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		 
		fuse_invalidate_attr(oldent->d_inode);

		fuse_invalidate_attr(olddir);
		if (olddir != newdir)
			fuse_invalidate_attr(newdir);

		if (newent->d_inode) {
			fuse_invalidate_attr(newent->d_inode);
			fuse_invalidate_entry_cache(newent);
		}
	} else if (err == -EINTR) {
		 
		fuse_invalidate_entry(oldent);
		if (newent->d_inode)
			fuse_invalidate_entry(newent);
	}

	return err;
}

static int fuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	int err;
	struct fuse_link_in inarg;
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.oldnodeid = get_node_id(inode);
	req->in.h.opcode = FUSE_LINK;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = newent->d_name.len + 1;
	req->in.args[1].value = newent->d_name.name;
	err = create_new_entry(fc, req, newdir, newent, inode->i_mode);
	 
	if (!err) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		inc_nlink(inode);
		spin_unlock(&fc->lock);
		fuse_invalidate_attr(inode);
	} else if (err == -EINTR) {
		fuse_invalidate_attr(inode);
	}
	return err;
}

static void fuse_fillattr(struct inode *inode, struct fuse_attr *attr,
			  struct kstat *stat)
{
	unsigned int blkbits;

	stat->dev = inode->i_sb->s_dev;
	stat->ino = attr->ino;
	stat->mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	stat->nlink = attr->nlink;
	stat->uid = make_kuid(&init_user_ns, attr->uid);
	stat->gid = make_kgid(&init_user_ns, attr->gid);
	stat->rdev = inode->i_rdev;
	stat->atime.tv_sec = attr->atime;
	stat->atime.tv_nsec = attr->atimensec;
	stat->mtime.tv_sec = attr->mtime;
	stat->mtime.tv_nsec = attr->mtimensec;
	stat->ctime.tv_sec = attr->ctime;
	stat->ctime.tv_nsec = attr->ctimensec;
	stat->size = attr->size;
	stat->blocks = attr->blocks;

	if (attr->blksize != 0)
		blkbits = ilog2(attr->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;

	stat->blksize = 1 << blkbits;
}

static int fuse_do_getattr(struct inode *inode, struct kstat *stat,
			   struct file *file)
{
	int err;
	struct fuse_getattr_in inarg;
	struct fuse_attr_out outarg;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	u64 attr_version;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	attr_version = fuse_get_attr_version(fc);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	 
	if (file && S_ISREG(inode->i_mode)) {
		struct fuse_file *ff = file->private_data;

		inarg.getattr_flags |= FUSE_GETATTR_FH;
		inarg.fh = ff->fh;
	}
	req->in.h.opcode = FUSE_GETATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ATTR_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
			make_bad_inode(inode);
			err = -EIO;
		} else {
			fuse_change_attributes(inode, &outarg.attr,
					       attr_timeout(&outarg),
					       attr_version);
			if (stat)
				fuse_fillattr(inode, &outarg.attr, stat);
		}
	}
	return err;
}

int fuse_update_attributes(struct inode *inode, struct kstat *stat,
			   struct file *file, bool *refreshed)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;
	bool r;

	if (fi->i_time < get_jiffies_64()) {
		r = true;
		err = fuse_do_getattr(inode, stat, file);
	} else {
		r = false;
		err = 0;
		if (stat) {
			generic_fillattr(inode, stat);
			stat->mode = fi->orig_i_mode;
			stat->ino = fi->orig_ino;
		}
	}

	if (refreshed != NULL)
		*refreshed = r;

	return err;
}

int fuse_reverse_inval_entry(struct super_block *sb, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name)
{
	int err = -ENOTDIR;
	struct inode *parent;
	struct dentry *dir;
	struct dentry *entry;

	parent = ilookup5(sb, parent_nodeid, fuse_inode_eq, &parent_nodeid);
	if (!parent)
		return -ENOENT;

	mutex_lock(&parent->i_mutex);
	if (!S_ISDIR(parent->i_mode))
		goto unlock;

	err = -ENOENT;
	dir = d_find_alias(parent);
	if (!dir)
		goto unlock;

	entry = d_lookup(dir, name);
	dput(dir);
	if (!entry)
		goto unlock;

	fuse_invalidate_attr(parent);
	fuse_invalidate_entry(entry);

	if (child_nodeid != 0 && entry->d_inode) {
		mutex_lock(&entry->d_inode->i_mutex);
		if (get_node_id(entry->d_inode) != child_nodeid) {
			err = -ENOENT;
			goto badentry;
		}
		if (d_mountpoint(entry)) {
			err = -EBUSY;
			goto badentry;
		}
		if (S_ISDIR(entry->d_inode->i_mode)) {
			shrink_dcache_parent(entry);
			if (!simple_empty(entry)) {
				err = -ENOTEMPTY;
				goto badentry;
			}
			entry->d_inode->i_flags |= S_DEAD;
		}
		dont_mount(entry);
		clear_nlink(entry->d_inode);
		err = 0;
 badentry:
		mutex_unlock(&entry->d_inode->i_mutex);
		if (!err)
			d_delete(entry);
	} else {
		err = 0;
	}
	dput(entry);

 unlock:
	mutex_unlock(&parent->i_mutex);
	iput(parent);
	return err;
}

int fuse_allow_current_process(struct fuse_conn *fc)
{
	const struct cred *cred;

	if (fc->flags & FUSE_ALLOW_OTHER)
		return 1;

	cred = current_cred();
	if (uid_eq(cred->euid, fc->user_id) &&
	    uid_eq(cred->suid, fc->user_id) &&
	    uid_eq(cred->uid,  fc->user_id) &&
	    gid_eq(cred->egid, fc->group_id) &&
	    gid_eq(cred->sgid, fc->group_id) &&
	    gid_eq(cred->gid,  fc->group_id))
		return 1;

	return 0;
}

#ifdef MY_ABC_HERE
static int fuse_access(struct inode *inode, int mask, int syno_acl_access)
#else
static int fuse_access(struct inode *inode, int mask)
#endif  
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_access_in inarg;
	int err;

	if (fc->no_access)
		return 0;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
#ifdef MY_ABC_HERE
	inarg.syno_acl_access = syno_acl_access;
	if (IS_GLUSTER_FS(inode) && syno_acl_access) {
		inarg.mask = mask & SYNO_PERM_FULL_CONTROL;
	} else
#endif  
	inarg.mask = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
	req->in.h.opcode = FUSE_ACCESS;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_access = 1;
		err = 0;
	}
	return err;
}

static int fuse_perm_getattr(struct inode *inode, int mask)
{
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	return fuse_do_getattr(inode, NULL, NULL);
}

static int fuse_permission(struct inode *inode, int mask)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	bool refreshed = false;
	int err = 0;

	if (!fuse_allow_current_process(fc))
		return -EACCES;

	if ((fc->flags & FUSE_DEFAULT_PERMISSIONS) ||
	    ((mask & MAY_EXEC) && S_ISREG(inode->i_mode))) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		if (fi->i_time < get_jiffies_64()) {
			refreshed = true;

			err = fuse_perm_getattr(inode, mask);
			if (err)
				return err;
		}
	}

	if (fc->flags & FUSE_DEFAULT_PERMISSIONS) {
		err = generic_permission(inode, mask);

		if (err == -EACCES && !refreshed) {
			err = fuse_perm_getattr(inode, mask);
			if (!err)
				err = generic_permission(inode, mask);
		}

	} else if (mask & (MAY_ACCESS | MAY_CHDIR)) {
		if (mask & MAY_NOT_BLOCK)
			return -ECHILD;

#ifdef MY_ABC_HERE
		err = fuse_access(inode, mask, 0);
#else
		err = fuse_access(inode, mask);
#endif  
	} else if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode)) {
#ifdef MY_ABC_HERE
		if (IS_GLUSTER_FS(inode)) {
			return fuse_access(inode, mask, 0);
		}
#endif  
		if (!(inode->i_mode & S_IXUGO)) {
			if (refreshed)
				return -EACCES;

			err = fuse_perm_getattr(inode, mask);
			if (!err && !(inode->i_mode & S_IXUGO))
				return -EACCES;
		}
	}
	return err;
}

static int parse_dirfile(char *buf, size_t nbytes, struct file *file,
			 void *dstbuf, filldir_t filldir)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		int over;
		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		over = filldir(dstbuf, dirent->name, dirent->namelen,
			       file->f_pos, dirent->ino, dirent->type);
		if (over)
			break;

		buf += reclen;
		nbytes -= reclen;
		file->f_pos = dirent->off;
	}

	return 0;
}

static int fuse_direntplus_link(struct file *file,
				struct fuse_direntplus *direntplus,
				u64 attr_version)
{
	int err;
	struct fuse_entry_out *o = &direntplus->entry_out;
	struct fuse_dirent *dirent = &direntplus->dirent;
	struct dentry *parent = file->f_path.dentry;
	struct qstr name = QSTR_INIT(dirent->name, dirent->namelen);
	struct dentry *dentry;
	struct dentry *alias;
	struct inode *dir = parent->d_inode;
	struct fuse_conn *fc;
	struct inode *inode;

	if (!o->nodeid) {
		 
		return 0;
	}

	if (name.name[0] == '.') {
		 
		if (name.len == 1)
			return 0;
		if (name.name[1] == '.' && name.len == 2)
			return 0;
	}

	if (invalid_nodeid(o->nodeid))
		return -EIO;
	if (!fuse_valid_type(o->attr.mode))
		return -EIO;

	fc = get_fuse_conn(dir);

	name.hash = full_name_hash(name.name, name.len);
	dentry = d_lookup(parent, &name);
	if (dentry) {
		inode = dentry->d_inode;
		if (!inode) {
			d_drop(dentry);
		} else if (get_node_id(inode) != o->nodeid ||
			   ((o->attr.mode ^ inode->i_mode) & S_IFMT)) {
			err = d_invalidate(dentry);
			if (err)
				goto out;
		} else if (is_bad_inode(inode)) {
			err = -EIO;
			goto out;
		} else {
			struct fuse_inode *fi;
			fi = get_fuse_inode(inode);
			spin_lock(&fc->lock);
			fi->nlookup++;
			spin_unlock(&fc->lock);

			goto found;
		}
		dput(dentry);
		dentry = NULL;
	}

	dentry = d_alloc(parent, &name);
	err = -ENOMEM;
	if (!dentry)
		goto out;

	inode = fuse_iget(dir->i_sb, o->nodeid, o->generation,
			  &o->attr, entry_attr_timeout(o), attr_version);
	if (!inode)
		goto out;

	if (S_ISDIR(inode->i_mode)) {
		mutex_lock(&fc->inst_mutex);
		alias = fuse_d_add_directory(dentry, inode);
		mutex_unlock(&fc->inst_mutex);
		err = PTR_ERR(alias);
		if (IS_ERR(alias)) {
			iput(inode);
			goto out;
		}
	} else {
		alias = d_splice_alias(inode, dentry);
	}

	if (alias) {
		dput(dentry);
		dentry = alias;
	}

found:
	fuse_change_attributes(inode, &o->attr, entry_attr_timeout(o),
			       attr_version);

	fuse_change_entry_timeout(dentry, o);

	err = 0;
out:
	if (dentry)
		dput(dentry);
	return err;
}

static int parse_dirplusfile(char *buf, size_t nbytes, struct file *file,
			     void *dstbuf, filldir_t filldir, u64 attr_version)
{
	struct fuse_direntplus *direntplus;
	struct fuse_dirent *dirent;
	size_t reclen;
	int over = 0;
	int ret;

	while (nbytes >= FUSE_NAME_OFFSET_DIRENTPLUS) {
		direntplus = (struct fuse_direntplus *) buf;
		dirent = &direntplus->dirent;
		reclen = FUSE_DIRENTPLUS_SIZE(direntplus);

		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;
		if (memchr(dirent->name, '/', dirent->namelen) != NULL)
			return -EIO;

		if (!over) {
			 
			over = filldir(dstbuf, dirent->name, dirent->namelen,
				       file->f_pos, dirent->ino,
				       dirent->type);
			file->f_pos = dirent->off;
		}

		buf += reclen;
		nbytes -= reclen;

		ret = fuse_direntplus_link(file, direntplus, attr_version);
		if (ret)
			fuse_force_forget(file, direntplus->entry_out.nodeid);
	}

	return 0;
}

static int fuse_readdir(struct file *file, void *dstbuf, filldir_t filldir)
{
	int plus, err;
	size_t nbytes;
	struct page *page;
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	u64 attr_version = 0;

	if (is_bad_inode(inode))
		return -EIO;

	req = fuse_get_req(fc, 1);
	if (IS_ERR(req))
		return PTR_ERR(req);

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		fuse_put_request(fc, req);
		return -ENOMEM;
	}

	plus = fuse_use_readdirplus(inode, file);
	req->out.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	req->page_descs[0].length = PAGE_SIZE;
	if (plus) {
		attr_version = fuse_get_attr_version(fc);
		fuse_read_fill(req, file, file->f_pos, PAGE_SIZE,
			       FUSE_READDIRPLUS);
	} else {
		fuse_read_fill(req, file, file->f_pos, PAGE_SIZE,
			       FUSE_READDIR);
	}
	fuse_request_send(fc, req);
	nbytes = req->out.args[0].size;
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		if (plus) {
			err = parse_dirplusfile(page_address(page), nbytes,
						file, dstbuf, filldir,
						attr_version);
		} else {
			err = parse_dirfile(page_address(page), nbytes, file,
					    dstbuf, filldir);
		}
	}

	__free_page(page);
	fuse_invalidate_attr(inode);  
	return err;
}

static char *read_link(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_req_nopages(fc);
	char *link;

	if (IS_ERR(req))
		return ERR_CAST(req);

	link = (char *) __get_free_page(GFP_KERNEL);
	if (!link) {
		link = ERR_PTR(-ENOMEM);
		goto out;
	}
	req->in.h.opcode = FUSE_READLINK;
	req->in.h.nodeid = get_node_id(inode);
	req->out.argvar = 1;
	req->out.numargs = 1;
	req->out.args[0].size = PAGE_SIZE - 1;
	req->out.args[0].value = link;
	fuse_request_send(fc, req);
	if (req->out.h.error) {
		free_page((unsigned long) link);
		link = ERR_PTR(req->out.h.error);
	} else
		link[req->out.args[0].size] = '\0';
 out:
	fuse_put_request(fc, req);
	fuse_invalidate_attr(inode);  
	return link;
}

static void free_link(char *link)
{
	if (!IS_ERR(link))
		free_page((unsigned long) link);
}

static void *fuse_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, read_link(dentry));
	return NULL;
}

static void fuse_put_link(struct dentry *dentry, struct nameidata *nd, void *c)
{
	free_link(nd_get_link(nd));
}

static int fuse_dir_open(struct inode *inode, struct file *file)
{
	return fuse_open_common(inode, file, true);
}

static int fuse_dir_release(struct inode *inode, struct file *file)
{
	fuse_release_common(file, FUSE_RELEASEDIR);

	return 0;
}

static int fuse_dir_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	return fuse_fsync_common(file, start, end, datasync, 1);
}

static long fuse_dir_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct fuse_conn *fc = get_fuse_conn(file->f_mapping->host);

	if (fc->minor < 18)
		return -ENOTTY;

	return fuse_ioctl_common(file, cmd, arg, FUSE_IOCTL_DIR);
}

static long fuse_dir_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct fuse_conn *fc = get_fuse_conn(file->f_mapping->host);

	if (fc->minor < 18)
		return -ENOTTY;

	return fuse_ioctl_common(file, cmd, arg,
				 FUSE_IOCTL_COMPAT | FUSE_IOCTL_DIR);
}

static bool update_mtime(unsigned ivalid)
{
	 
	if (ivalid & ATTR_MTIME_SET)
		return true;

	if ((ivalid & ATTR_SIZE) && (ivalid & (ATTR_OPEN | ATTR_FILE)))
		return false;

	return true;
}

static void iattr_to_fattr(struct iattr *iattr, struct fuse_setattr_in *arg)
{
	unsigned ivalid = iattr->ia_valid;

	if (ivalid & ATTR_MODE)
		arg->valid |= FATTR_MODE,   arg->mode = iattr->ia_mode;
	if (ivalid & ATTR_UID)
		arg->valid |= FATTR_UID,    arg->uid = from_kuid(&init_user_ns, iattr->ia_uid);
	if (ivalid & ATTR_GID)
		arg->valid |= FATTR_GID,    arg->gid = from_kgid(&init_user_ns, iattr->ia_gid);
	if (ivalid & ATTR_SIZE)
		arg->valid |= FATTR_SIZE,   arg->size = iattr->ia_size;
	if (ivalid & ATTR_ATIME) {
		arg->valid |= FATTR_ATIME;
		arg->atime = iattr->ia_atime.tv_sec;
		arg->atimensec = iattr->ia_atime.tv_nsec;
		if (!(ivalid & ATTR_ATIME_SET))
			arg->valid |= FATTR_ATIME_NOW;
	}
	if ((ivalid & ATTR_MTIME) && update_mtime(ivalid)) {
		arg->valid |= FATTR_MTIME;
		arg->mtime = iattr->ia_mtime.tv_sec;
		arg->mtimensec = iattr->ia_mtime.tv_nsec;
		if (!(ivalid & ATTR_MTIME_SET))
			arg->valid |= FATTR_MTIME_NOW;
	}
}

void fuse_set_nowrite(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	BUG_ON(!mutex_is_locked(&inode->i_mutex));

	spin_lock(&fc->lock);
	BUG_ON(fi->writectr < 0);
	fi->writectr += FUSE_NOWRITE;
	spin_unlock(&fc->lock);
	wait_event(fi->page_waitq, fi->writectr == FUSE_NOWRITE);
}

static void __fuse_release_nowrite(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	BUG_ON(fi->writectr != FUSE_NOWRITE);
	fi->writectr = 0;
	fuse_flush_writepages(inode);
}

void fuse_release_nowrite(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);

	spin_lock(&fc->lock);
	__fuse_release_nowrite(inode);
	spin_unlock(&fc->lock);
}

int fuse_do_setattr(struct inode *inode, struct iattr *attr,
		    struct file *file)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req;
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	bool is_truncate = false;
	loff_t oldsize;
	int err;

	if (!(fc->flags & FUSE_DEFAULT_PERMISSIONS))
		attr->ia_valid |= ATTR_FORCE;

	err = inode_change_ok(inode, attr);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_OPEN) {
		if (fc->atomic_o_trunc)
			return 0;
		file = NULL;
	}

	if (attr->ia_valid & ATTR_SIZE)
		is_truncate = true;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (is_truncate) {
		fuse_set_nowrite(inode);
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	}

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	iattr_to_fattr(attr, &inarg);
	if (file) {
		struct fuse_file *ff = file->private_data;
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	if (attr->ia_valid & ATTR_SIZE) {
		 
		inarg.valid |= FATTR_LOCKOWNER;
		inarg.lock_owner = fuse_lock_owner_id(fc, current->files);
	}
	req->in.h.opcode = FUSE_SETATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ATTR_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err) {
		if (err == -EINTR)
			fuse_invalidate_attr(inode);
		goto error;
	}

	if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
		make_bad_inode(inode);
		err = -EIO;
		goto error;
	}

	spin_lock(&fc->lock);
	fuse_change_attributes_common(inode, &outarg.attr,
				      attr_timeout(&outarg));
	oldsize = inode->i_size;
	i_size_write(inode, outarg.attr.size);

	if (is_truncate) {
		 
		__fuse_release_nowrite(inode);
	}
	spin_unlock(&fc->lock);

	if (S_ISREG(inode->i_mode) && oldsize != outarg.attr.size) {
		truncate_pagecache(inode, oldsize, outarg.attr.size);
		invalidate_inode_pages2(inode->i_mapping);
	}

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	return 0;

error:
	if (is_truncate)
		fuse_release_nowrite(inode);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	return err;
}

static int fuse_setattr(struct dentry *entry, struct iattr *attr)
{
	struct inode *inode = entry->d_inode;

	if (!fuse_allow_current_process(get_fuse_conn(inode)))
		return -EACCES;

	if (attr->ia_valid & ATTR_FILE)
		return fuse_do_setattr(inode, attr, attr->ia_file);
	else
		return fuse_do_setattr(inode, attr, NULL);
}

static int fuse_getattr(struct vfsmount *mnt, struct dentry *entry,
			struct kstat *stat)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (!fuse_allow_current_process(fc))
		return -EACCES;

	return fuse_update_attributes(inode, stat, NULL, NULL);
}

#ifdef MY_ABC_HERE
int fuse_setxattr(struct dentry *entry, const char *name,
			 const void *value, size_t size, int flags)
#else
static int fuse_setxattr(struct dentry *entry, const char *name,
			 const void *value, size_t size, int flags)
#endif  
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_setxattr_in inarg;
	int err;

	if (fc->no_setxattr)
		return -EOPNOTSUPP;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	inarg.flags = flags;
	req->in.h.opcode = FUSE_SETXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 3;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = strlen(name) + 1;
	req->in.args[1].value = name;
	req->in.args[2].size = size;
	req->in.args[2].value = value;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_setxattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err)
		fuse_invalidate_attr(inode);
	return err;
}

#ifdef MY_ABC_HERE
ssize_t fuse_getxattr(struct dentry *entry, const char *name,
			     void *value, size_t size)
#else
static ssize_t fuse_getxattr(struct dentry *entry, const char *name,
			     void *value, size_t size)
#endif  
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (fc->no_getxattr)
		return -EOPNOTSUPP;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_GETXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = strlen(name) + 1;
	req->in.args[1].value = name;
	 
	req->out.numargs = 1;
	if (size) {
		req->out.argvar = 1;
		req->out.args[0].size = size;
		req->out.args[0].value = value;
	} else {
		req->out.args[0].size = sizeof(outarg);
		req->out.args[0].value = &outarg;
	}
	fuse_request_send(fc, req);
	ret = req->out.h.error;
	if (!ret)
		ret = size ? req->out.args[0].size : outarg.size;
	else {
		if (ret == -ENOSYS) {
			fc->no_getxattr = 1;
			ret = -EOPNOTSUPP;
		}
	}
	fuse_put_request(fc, req);
	return ret;
}

static ssize_t fuse_listxattr(struct dentry *entry, char *list, size_t size)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (!fuse_allow_current_process(fc))
		return -EACCES;

	if (fc->no_listxattr)
		return -EOPNOTSUPP;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_LISTXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	 
	req->out.numargs = 1;
	if (size) {
		req->out.argvar = 1;
		req->out.args[0].size = size;
		req->out.args[0].value = list;
	} else {
		req->out.args[0].size = sizeof(outarg);
		req->out.args[0].value = &outarg;
	}
	fuse_request_send(fc, req);
	ret = req->out.h.error;
	if (!ret)
		ret = size ? req->out.args[0].size : outarg.size;
	else {
		if (ret == -ENOSYS) {
			fc->no_listxattr = 1;
			ret = -EOPNOTSUPP;
		}
	}
	fuse_put_request(fc, req);
	return ret;
}

static int fuse_removexattr(struct dentry *entry, const char *name)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	int err;

	if (fc->no_removexattr)
		return -EOPNOTSUPP;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.opcode = FUSE_REMOVEXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = strlen(name) + 1;
	req->in.args[0].value = name;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_removexattr = 1;
		err = -EOPNOTSUPP;
	}
	if (!err)
		fuse_invalidate_attr(inode);
	return err;
}

#if defined(MY_ABC_HERE) || defined(MY_ABC_HERE)
#define SZ_FS_NTFS	"ntfs"
#define IS_NTFS_FS(inode) (inode->i_sb->s_subtype && !strcmp(SZ_FS_NTFS, inode->i_sb->s_subtype))
#endif  
#ifdef MY_ABC_HERE
#define XATTR_NTFS_CREATE_TIME "ntfs_crtime"
#endif  
#ifdef MY_ABC_HERE
static int fuse_syno_glusterfs_getattr(struct dentry *dentry, struct kstat *stat, int stat_flag)
{
	int err = 0;
	struct inode *dir;
	struct fuse_entry_out outarg;
	struct fuse_synostat *synostat = NULL;
	struct inode *inode;
	struct qstr name;

	dir = dentry->d_parent->d_inode;

	if (stat_flag & (SYNOST_ALL | SYNOST_IS_CASELESS)) {
		synostat = kmalloc(FUSE_SYNOSTAT_SIZE, GFP_KERNEL);
		memset(synostat, 0, FUSE_SYNOSTAT_SIZE);
	}
	if (get_node_id(dentry->d_inode) == FUSE_ROOT_ID) {
		name.name = ".";
		name.len = 1;
		err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &name,
				       &outarg, &inode, synostat, stat_flag);
	} else {
		err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &dentry->d_name,
				       &outarg, &inode, synostat, stat_flag);
	}
	if (err)
		goto out;

	if (stat_flag & SYNOST_ARCHIVE_BIT) {
		stat->syno_archive_bit = synostat->archive_bit;
	}
	if (stat_flag & SYNOST_CREATE_TIME) {
		stat->syno_create_time.tv_sec = synostat->create_time_sec;
		stat->syno_create_time.tv_nsec = synostat->create_time_nsec;
	}
	if (stat_flag & SYNOST_ARCHIVE_VER) {
		stat->syno_archive_version = synostat->archive_version;
	}
out:
	kfree (synostat);
	iput(inode);
	return err;
}

static int fuse_syno_ntfs_getattr(struct dentry *dentry, struct kstat *stat, int stat_flag)
{
#ifdef MY_ABC_HERE
	int size = 0;
	sle64 time_le = 0;
	s64 time_s = 0;

	size = fuse_getxattr(dentry, XATTR_SYSTEM_PREFIX XATTR_NTFS_CREATE_TIME, &time_s, sizeof(time_s));
	if (size == sizeof(time_s)) {
		time_le = cpu_to_sle64(time_s);
		stat->syno_create_time = ntfs2utc(time_le);
	} else {
		memset(&stat->syno_create_time, 0, sizeof(stat->syno_create_time));
	}
#endif  
#ifdef MY_ABC_HERE
	stat->syno_archive_bit = dentry->d_inode->i_archive_bit;
#endif  
#ifdef MY_ABC_HERE
	stat->syno_archive_version = dentry->d_inode->i_archive_version;
#endif  
	return 0;
}

static int fuse_syno_getattr(struct dentry *dentry, struct kstat *stat, int stat_flag)
{
	if (!dentry->d_parent || !dentry->d_parent->d_inode) {
		printk(KERN_WARNING"fuse syno getattr null entry\n");
		return -EINVAL;
	}

	if (IS_GLUSTER_FS(dentry->d_inode)) {
		return fuse_syno_glusterfs_getattr(dentry, stat, stat_flag);
	} else if (IS_NTFS_FS(dentry->d_inode)) {
		return fuse_syno_ntfs_getattr(dentry, stat, stat_flag);
	}

#ifdef MY_ABC_HERE
	stat->syno_create_time = dentry->d_inode->i_create_time;
#endif  
#ifdef MY_ABC_HERE
	stat->syno_archive_bit = dentry->d_inode->i_archive_bit;
#endif  
#ifdef MY_ABC_HERE
	stat->syno_archive_version = dentry->d_inode->i_archive_version;
#endif  
	return 0;
}
#endif  

#ifdef MY_ABC_HERE
static int fuse_syno_set_archive_version(struct dentry *dentry, u32 archive_version)
{
	struct syno_xattr_archive_version value;

	value.v_magic = cpu_to_le16(0x2552);
	value.v_struct_version = cpu_to_le16(1);
	value.v_archive_version = cpu_to_le32(archive_version);

	return fuse_setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_ARCHIVE_VERSION_GLUSTER, &value, sizeof(value), 0);
}
#endif  

#ifdef MY_ABC_HERE
static int fuse_syno_set_glusterfs_create_time(struct dentry *dentry, struct timespec* time)
{
	struct syno_gf_xattr_crtime time_le;

	time_le.sec = cpu_to_le64(time->tv_sec);
	time_le.nsec = cpu_to_le32(time->tv_nsec);

	return fuse_setxattr(dentry, XATTR_SYNO_PREFIX XATTR_SYNO_CREATE_TIME, &time_le, sizeof(time_le), 0);
}

static int fuse_syno_set_ntfs_create_time(struct dentry *dentry, struct timespec* time)
{
	sle64 time_le;
	s64 time_s;

	time_le = utc2ntfs(*time);
	time_s = sle64_to_cpu(time_le);

	return fuse_setxattr(dentry, XATTR_SYSTEM_PREFIX XATTR_NTFS_CREATE_TIME, &time_s, sizeof(time_s), 0);
}

static int fuse_syno_set_create_time(struct dentry *dentry, struct timespec* time)
{
	struct inode *inode = dentry->d_inode;

	if (IS_GLUSTER_FS(inode)) {
		return fuse_syno_set_glusterfs_create_time(dentry, time);
	} else if (IS_NTFS_FS(inode)) {
		return fuse_syno_set_ntfs_create_time(dentry, time);
	}
	return -EOPNOTSUPP;
}
#endif  

#ifdef MY_ABC_HERE
static int fuse_syno_get_archive_bit(struct dentry *entry, unsigned int *archive_bit)
{
	int err;
	struct inode *inode = entry->d_inode;
	struct kstat stat;

	if (!IS_GLUSTER_FS(inode)) {
		*archive_bit = inode->i_archive_bit;
		return 0;
	}

	memset (&stat, 0, sizeof(stat));
	err = fuse_syno_getattr(entry, &stat, SYNOST_ARCHIVE_BIT);
	*archive_bit = stat.syno_archive_bit;

	return err;
}

static int fuse_syno_set_archive_bit(struct dentry *dentry, unsigned int arbit)
{
	int err;
	struct inode *inode = dentry->d_inode;
	__le32 arbit_le32 = cpu_to_le32(arbit);

	if (!IS_GLUSTER_FS(inode)) {
		inode->i_archive_bit = arbit;
		inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty_sync(inode);
		return 0;
	}

	err = fuse_setxattr(dentry, XATTR_SYNO_PREFIX""XATTR_SYNO_ARCHIVE_BIT, &arbit_le32, sizeof(arbit_le32), 0);
	inode->i_archive_bit = arbit;
	return err;
}
#endif  

#ifdef MY_ABC_HERE
static int fuse_syno_acl_sys_get_perm(struct dentry *dentry, int *allow_out)
{
	__le32 allow_le32 = 0;
	int error;

	if (!IS_GLUSTER_FS(dentry->d_inode)) {
		return -EOPNOTSUPP;
	}

	error = fuse_getxattr(dentry, SYNO_ACL_XATTR_PERM, &allow_le32, sizeof(allow_le32));
	if (error >= 0) {
		error = 0;
		*allow_out = le32_to_cpu(allow_le32);
	}

	return error;
}

static int fuse_syno_acl_sys_is_support(struct dentry *dentry, int tag)
{
	struct inode *inode = dentry->d_inode;
	uint32_t archive_bit = 0;
	int error;

	if (!IS_GLUSTER_FS(inode)) {
		return -EOPNOTSUPP;
	}

	if (SYNO_KERNEL_IS_FS_SUPPORT == tag) {
		return 1;
	} else if (SYNO_KERNEL_IS_FILE_SUPPORT == tag) {
		error = inode->i_op->syno_get_archive_bit(dentry, &archive_bit);
		if (0 == error) {
			return !!(archive_bit & S2_SYNO_ACL_SUPPORT);
		}
	} else {
		return 0;
	}
	return error;
}

static int fuse_syno_acl_sys_check_perm(struct dentry *dentry, int mask)
{
	if (!IS_GLUSTER_FS(dentry->d_inode)) {
		return -EOPNOTSUPP;
	}
	return fuse_access(dentry->d_inode, mask, 1);
}

static int fuse_syno_acl_xattr_get(struct dentry *dentry, int cmd, void *value, size_t size)
{
	if (IS_GLUSTER_FS(dentry->d_inode)) {
		if (SYNO_ACL_INHERITED == cmd)
			return fuse_getxattr(dentry, SYNO_ACL_XATTR_INHERIT, value, size);
		else if (SYNO_ACL_PSEUDO_INHERIT_ONLY == cmd)
			return fuse_getxattr(dentry, SYNO_ACL_XATTR_PSEUDO_INHERIT_ONLY, value, size);
		else
			return -EOPNOTSUPP;
	}
	return synoacl_mod_get_acl_xattr(dentry, cmd, value, size);
}

static int fuse_syno_bypass_is_synoacl(struct dentry *dentry, int cmd, int reterror)
{
	if (IS_GLUSTER_FS(dentry->d_inode)) {
		return 0;
	}
	if (cmd == BYPASS_SYNOACL_SYNOARCHIVE_OVERWRITE) {
		if (inode_owner_or_capable(dentry->d_inode)) {
			return 0;
		}
	}
	return reterror;
}

static int fuse_syno_archive_bit_change_ok(struct dentry *dentry, unsigned int cmd, int tag, int mask)
{
	if (IS_GLUSTER_FS(dentry->d_inode)) {
		return 0;
	}

	if ((NEED_INODE_ACL_SUPPORT | NEED_FS_ACL_SUPPORT) & tag) {
		return -EOPNOTSUPP;
	}

	return 0;
}
#endif  

static const struct inode_operations fuse_dir_inode_operations = {
	.lookup		= fuse_lookup,
	.mkdir		= fuse_mkdir,
	.symlink	= fuse_symlink,
	.unlink		= fuse_unlink,
	.rmdir		= fuse_rmdir,
	.rename		= fuse_rename,
	.link		= fuse_link,
	.setattr	= fuse_setattr,
	.create		= fuse_create,
	.atomic_open	= fuse_atomic_open,
	.mknod		= fuse_mknod,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
#ifdef MY_ABC_HERE
	.syno_getattr	= fuse_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_ver	= fuse_syno_set_archive_version,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime	= fuse_syno_set_create_time,
#endif  
#ifdef MY_ABC_HERE
	.syno_get_archive_bit	= fuse_syno_get_archive_bit,
	.syno_set_archive_bit	= fuse_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_acl_sys_get_perm	= fuse_syno_acl_sys_get_perm,
	.syno_acl_sys_is_support	= fuse_syno_acl_sys_is_support,
	.syno_acl_sys_check_perm	= fuse_syno_acl_sys_check_perm,
	.syno_acl_xattr_get	= fuse_syno_acl_xattr_get,
	.syno_bypass_is_synoacl = fuse_syno_bypass_is_synoacl,
	.syno_arbit_chg_ok = fuse_syno_archive_bit_change_ok,
#endif  
};

static const struct file_operations fuse_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= fuse_readdir,
	.open		= fuse_dir_open,
	.release	= fuse_dir_release,
	.fsync		= fuse_dir_fsync,
	.unlocked_ioctl	= fuse_dir_ioctl,
	.compat_ioctl	= fuse_dir_compat_ioctl,
};

static const struct inode_operations fuse_common_inode_operations = {
	.setattr	= fuse_setattr,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
#ifdef MY_ABC_HERE
	.syno_getattr	= fuse_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_ver	= fuse_syno_set_archive_version,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime	= fuse_syno_set_create_time,
#endif  
#ifdef MY_ABC_HERE
	.syno_get_archive_bit	= fuse_syno_get_archive_bit,
	.syno_set_archive_bit	= fuse_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_acl_sys_get_perm	= fuse_syno_acl_sys_get_perm,
	.syno_acl_sys_is_support	= fuse_syno_acl_sys_is_support,
	.syno_acl_sys_check_perm	= fuse_syno_acl_sys_check_perm,
	.syno_acl_xattr_get	= fuse_syno_acl_xattr_get,
	.syno_bypass_is_synoacl = fuse_syno_bypass_is_synoacl,
	.syno_arbit_chg_ok = fuse_syno_archive_bit_change_ok,
#endif  
};

static const struct inode_operations fuse_symlink_inode_operations = {
	.setattr	= fuse_setattr,
	.follow_link	= fuse_follow_link,
	.put_link	= fuse_put_link,
	.readlink	= generic_readlink,
	.getattr	= fuse_getattr,
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
#ifdef MY_ABC_HERE
	.syno_getattr	= fuse_syno_getattr,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_archive_ver	= fuse_syno_set_archive_version,
#endif  
#ifdef MY_ABC_HERE
	.syno_set_crtime	= fuse_syno_set_create_time,
#endif  
#ifdef MY_ABC_HERE
	.syno_get_archive_bit	= fuse_syno_get_archive_bit,
	.syno_set_archive_bit	= fuse_syno_set_archive_bit,
#endif  
#ifdef MY_ABC_HERE
	.syno_acl_sys_get_perm	= fuse_syno_acl_sys_get_perm,
	.syno_acl_sys_is_support	= fuse_syno_acl_sys_is_support,
	.syno_acl_sys_check_perm	= fuse_syno_acl_sys_check_perm,
	.syno_acl_xattr_get	= fuse_syno_acl_xattr_get,
	.syno_bypass_is_synoacl = fuse_syno_bypass_is_synoacl,
	.syno_arbit_chg_ok = fuse_syno_archive_bit_change_ok,
#endif  
};

void fuse_init_common(struct inode *inode)
{
	inode->i_op = &fuse_common_inode_operations;
}

void fuse_init_dir(struct inode *inode)
{
	inode->i_op = &fuse_dir_inode_operations;
	inode->i_fop = &fuse_dir_operations;
}

void fuse_init_symlink(struct inode *inode)
{
	inode->i_op = &fuse_symlink_inode_operations;
}
