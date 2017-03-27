#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/evm.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fsnotify.h>
#include <linux/audit.h>
#include <linux/vmalloc.h>
#include <linux/posix_acl_xattr.h>

#include <asm/uaccess.h>

#ifdef MY_ABC_HERE
#include "synoacl_int.h"
#include <linux/syno_acl_xattr_ds.h>
#endif  
 
#ifdef MY_ABC_HERE
static int
xattr_permission(struct dentry *dentry, const char *name, int mask)
#else
static int
xattr_permission(struct inode *inode, const char *name, int mask)
#endif  
{
#ifdef MY_ABC_HERE
	struct inode *inode = dentry->d_inode;
	 
	if (!strcmp(name, SYNO_ACL_XATTR_ACCESS)) {
		if (inode->i_op->syno_bypass_is_synoacl) {
			 
			return inode->i_op->syno_bypass_is_synoacl(dentry,
					        BYPASS_SYNOACL_SYNOACL_XATTR, -EOPNOTSUPP);
		} else if (MAY_WRITE == mask || MAY_WRITE_PERMISSION == mask) {
			return synoacl_check_xattr_perm(name, dentry, MAY_WRITE_PERMISSION);
		} else if (MAY_READ == mask || MAY_READ_PERMISSION == mask) {
			return synoacl_check_xattr_perm(name, dentry, MAY_READ_PERMISSION);
		} else {
			return -EPERM;
		}
	}

	if (MAY_READ == mask) {
		if (!strcmp(name, SYNO_ACL_XATTR_INHERIT)) {
			if (inode->i_op->syno_bypass_is_synoacl) {
				 
				return inode->i_op->syno_bypass_is_synoacl(dentry,
						        BYPASS_SYNOACL_SYNOACL_XATTR, -EOPNOTSUPP);
			} else if (!IS_SYNOACL(dentry)) {
				return -EOPNOTSUPP;
			}
			return synoacl_op_perm(dentry, MAY_READ_PERMISSION);
		}
		if (!strcmp(name, SYNO_ACL_XATTR_PSEUDO_INHERIT_ONLY)) {
			if (inode->i_op->syno_bypass_is_synoacl) {
				 
				return inode->i_op->syno_bypass_is_synoacl(dentry,
						        BYPASS_SYNOACL_SYNOACL_XATTR, -EOPNOTSUPP);
			}
			return synoacl_op_perm(dentry, MAY_READ_PERMISSION);
		}
	}

	if (IS_SYNOACL(dentry) &&
	    (!strncmp(name, SYNO_XATTR_EA_PREFIX, SYNO_XATTR_EA_PREFIX_LEN) ||
	     !strncmp(name, SYNO_XATTR_NETATALK_PREFIX, SYNO_XATTR_NETATALK_PREFIX_LEN))) {
		if (MAY_READ & mask) {
			mask |= MAY_READ_ATTR;
		}
		if (MAY_WRITE & mask) {
			mask |= MAY_WRITE_ATTR;
		}
		return synoacl_op_perm(dentry, mask);
	}
#endif  
	 
	if (mask & MAY_WRITE) {
		if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
			return -EPERM;
	}

	if (!strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN) ||
	    !strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return 0;

	if (!strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN)) {
		if (!capable(CAP_SYS_ADMIN))
			return (mask & MAY_WRITE) ? -EPERM : -ENODATA;
		return 0;
	}

	if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN)) {
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			return (mask & MAY_WRITE) ? -EPERM : -ENODATA;
		if (S_ISDIR(inode->i_mode) && (inode->i_mode & S_ISVTX) &&
		    (mask & MAY_WRITE) && !inode_owner_or_capable(inode))
			return -EPERM;
	}

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(dentry)) {
		 
		return synoacl_op_perm(dentry, mask);
	} else
#endif  
	return inode_permission(inode, mask);
}

int __vfs_setxattr_noperm(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	int error = -EOPNOTSUPP;
	int issec = !strncmp(name, XATTR_SECURITY_PREFIX,
				   XATTR_SECURITY_PREFIX_LEN);

	if (issec)
		inode->i_flags &= ~S_NOSEC;
	if (inode->i_op->setxattr) {
		error = inode->i_op->setxattr(dentry, name, value, size, flags);
		if (!error) {
			fsnotify_xattr(dentry);
			security_inode_post_setxattr(dentry, name, value,
						     size, flags);
		}
	} else if (issec) {
		const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;
		error = security_inode_setsecurity(inode, suffix, value,
						   size, flags);
		if (!error)
			fsnotify_xattr(dentry);
	}

	return error;
}

int
vfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	int error;

#ifdef MY_ABC_HERE
	error = xattr_permission(dentry, name, MAY_WRITE);
#else
	error = xattr_permission(inode, name, MAY_WRITE);
#endif  
	if (error)
		return error;

	mutex_lock(&inode->i_mutex);
	error = security_inode_setxattr(dentry, name, value, size, flags);
	if (error)
		goto out;

	error = __vfs_setxattr_noperm(dentry, name, value, size, flags);

out:
	mutex_unlock(&inode->i_mutex);
	return error;
}
EXPORT_SYMBOL_GPL(vfs_setxattr);
#ifdef MY_ABC_HERE
int
vfs_setxattr_nolock(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int error;
	error = xattr_permission(dentry, name, MAY_WRITE);
	if (error) {
		goto out;
	}
	error = security_inode_setxattr(dentry, name, value, size, flags);
	if (error) {
		goto out;
	}
	error = __vfs_setxattr_noperm(dentry, name, value, size, flags);
out:
	return error;
}
EXPORT_SYMBOL(vfs_setxattr_nolock);
#endif  

ssize_t
xattr_getsecurity(struct inode *inode, const char *name, void *value,
			size_t size)
{
	void *buffer = NULL;
	ssize_t len;

	if (!value || !size) {
		len = security_inode_getsecurity(inode, name, &buffer, false);
		goto out_noalloc;
	}

	len = security_inode_getsecurity(inode, name, &buffer, true);
	if (len < 0)
		return len;
	if (size < len) {
		len = -ERANGE;
		goto out;
	}
	memcpy(value, buffer, len);
out:
	security_release_secctx(buffer, len);
out_noalloc:
	return len;
}
EXPORT_SYMBOL_GPL(xattr_getsecurity);

ssize_t
vfs_getxattr_alloc(struct dentry *dentry, const char *name, char **xattr_value,
		   size_t xattr_size, gfp_t flags)
{
	struct inode *inode = dentry->d_inode;
	char *value = *xattr_value;
	int error;

#ifdef MY_ABC_HERE
	error = xattr_permission(dentry, name, MAY_READ);
#else
	error = xattr_permission(inode, name, MAY_READ);
#endif  
	if (error)
		return error;

	if (!inode->i_op->getxattr)
		return -EOPNOTSUPP;

	error = inode->i_op->getxattr(dentry, name, NULL, 0);
	if (error < 0)
		return error;

	if (!value || (error > xattr_size)) {
		value = krealloc(*xattr_value, error + 1, flags);
		if (!value)
			return -ENOMEM;
		memset(value, 0, error + 1);
	}

	error = inode->i_op->getxattr(dentry, name, value, error);
	*xattr_value = value;
	return error;
}

int vfs_xattr_cmp(struct dentry *dentry, const char *xattr_name,
		  const char *value, size_t size, gfp_t flags)
{
	char *xattr_value = NULL;
	int rc;

	rc = vfs_getxattr_alloc(dentry, xattr_name, &xattr_value, 0, flags);
	if (rc < 0)
		return rc;

	if ((rc != size) || (memcmp(xattr_value, value, rc) != 0))
		rc = -EINVAL;
	else
		rc = 0;
	kfree(xattr_value);
	return rc;
}

ssize_t
vfs_getxattr(struct dentry *dentry, const char *name, void *value, size_t size)
{
	struct inode *inode = dentry->d_inode;
	int error;

#ifdef MY_ABC_HERE
	error = xattr_permission(dentry, name, MAY_READ);
#else
	error = xattr_permission(inode, name, MAY_READ);
#endif  
	if (error)
		return error;

	error = security_inode_getxattr(dentry, name);
	if (error)
		return error;
#ifdef MY_ABC_HERE
	if (name && (!strcmp(name, SYNO_ACL_XATTR_INHERIT) || !strcmp(name, SYNO_ACL_XATTR_PSEUDO_INHERIT_ONLY))) {
		if (!strcmp(name, SYNO_ACL_XATTR_INHERIT)) {
			return synoacl_op_xattr_get(dentry, SYNO_ACL_INHERITED, value, size);
		} else if (!strcmp(name, SYNO_ACL_XATTR_PSEUDO_INHERIT_ONLY)) {
			 
			return synoacl_op_xattr_get(dentry, SYNO_ACL_PSEUDO_INHERIT_ONLY, value, size);
		}
	}
#endif  
	if (!strncmp(name, XATTR_SECURITY_PREFIX,
				XATTR_SECURITY_PREFIX_LEN)) {
		const char *suffix = name + XATTR_SECURITY_PREFIX_LEN;
		int ret = xattr_getsecurity(inode, suffix, value, size);
		 
		if (ret == -EOPNOTSUPP)
			goto nolsm;
		return ret;
	}
nolsm:
	if (inode->i_op->getxattr)
		error = inode->i_op->getxattr(dentry, name, value, size);
	else
		error = -EOPNOTSUPP;

	return error;
}
EXPORT_SYMBOL_GPL(vfs_getxattr);

ssize_t
vfs_listxattr(struct dentry *d, char *list, size_t size)
{
	ssize_t error;

	error = security_inode_listxattr(d);
	if (error)
		return error;
	error = -EOPNOTSUPP;
	if (d->d_inode->i_op->listxattr) {
		error = d->d_inode->i_op->listxattr(d, list, size);
	} else {
		error = security_inode_listsecurity(d->d_inode, list, size);
		if (size && error > size)
			error = -ERANGE;
	}
	return error;
}
EXPORT_SYMBOL_GPL(vfs_listxattr);

int
vfs_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = dentry->d_inode;
	int error;

	if (!inode->i_op->removexattr)
		return -EOPNOTSUPP;

#ifdef MY_ABC_HERE
	error = xattr_permission(dentry, name, MAY_WRITE);
#else
	error = xattr_permission(inode, name, MAY_WRITE);
#endif  
	if (error)
		return error;

	mutex_lock(&inode->i_mutex);
	error = security_inode_removexattr(dentry, name);
	if (error) {
		mutex_unlock(&inode->i_mutex);
		return error;
	}

	error = inode->i_op->removexattr(dentry, name);
	mutex_unlock(&inode->i_mutex);

	if (!error) {
		fsnotify_xattr(dentry);
		evm_inode_post_removexattr(dentry, name);
	}
	return error;
}
EXPORT_SYMBOL_GPL(vfs_removexattr);

static long
setxattr(struct dentry *d, const char __user *name, const void __user *value,
	 size_t size, int flags)
{
	int error;
	void *kvalue = NULL;
	void *vvalue = NULL;	 
	char kname[XATTR_NAME_MAX + 1];

	if (flags & ~(XATTR_CREATE|XATTR_REPLACE))
		return -EINVAL;

	error = strncpy_from_user(kname, name, sizeof(kname));
	if (error == 0 || error == sizeof(kname))
		error = -ERANGE;
	if (error < 0)
		return error;

	if (size) {
		if (size > XATTR_SIZE_MAX)
			return -E2BIG;
		kvalue = kmalloc(size, GFP_KERNEL | __GFP_NOWARN);
		if (!kvalue) {
			vvalue = vmalloc(size);
			if (!vvalue)
				return -ENOMEM;
			kvalue = vvalue;
		}
		if (copy_from_user(kvalue, value, size)) {
			error = -EFAULT;
			goto out;
		}
		if ((strcmp(kname, XATTR_NAME_POSIX_ACL_ACCESS) == 0) ||
		    (strcmp(kname, XATTR_NAME_POSIX_ACL_DEFAULT) == 0))
			posix_acl_fix_xattr_from_user(kvalue, size);
	}

	error = vfs_setxattr(d, kname, kvalue, size, flags);
out:
	if (vvalue)
		vfree(vvalue);
	else
		kfree(kvalue);
	return error;
}

SYSCALL_DEFINE5(setxattr, const char __user *, pathname,
		const char __user *, name, const void __user *, value,
		size_t, size, int, flags)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = mnt_want_write(path.mnt);
	if (!error) {
		error = setxattr(path.dentry, name, value, size, flags);
		mnt_drop_write(path.mnt);
	}
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE5(lsetxattr, const char __user *, pathname,
		const char __user *, name, const void __user *, value,
		size_t, size, int, flags)
{
	struct path path;
	int error;
	unsigned int lookup_flags = 0;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = mnt_want_write(path.mnt);
	if (!error) {
		error = setxattr(path.dentry, name, value, size, flags);
		mnt_drop_write(path.mnt);
	}
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE5(fsetxattr, int, fd, const char __user *, name,
		const void __user *,value, size_t, size, int, flags)
{
	struct fd f = fdget(fd);
	struct dentry *dentry;
	int error = -EBADF;

	if (!f.file)
		return error;
	dentry = f.file->f_path.dentry;
	audit_inode(NULL, dentry, 0);
	error = mnt_want_write_file(f.file);
	if (!error) {
		error = setxattr(dentry, name, value, size, flags);
		mnt_drop_write_file(f.file);
	}
	fdput(f);
	return error;
}

static ssize_t
getxattr(struct dentry *d, const char __user *name, void __user *value,
	 size_t size)
{
	ssize_t error;
	void *kvalue = NULL;
	void *vvalue = NULL;
	char kname[XATTR_NAME_MAX + 1];

	error = strncpy_from_user(kname, name, sizeof(kname));
	if (error == 0 || error == sizeof(kname))
		error = -ERANGE;
	if (error < 0)
		return error;

	if (size) {
		if (size > XATTR_SIZE_MAX)
			size = XATTR_SIZE_MAX;
		kvalue = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);
		if (!kvalue) {
			vvalue = vmalloc(size);
			if (!vvalue)
				return -ENOMEM;
			kvalue = vvalue;
		}
	}

	error = vfs_getxattr(d, kname, kvalue, size);
	if (error > 0) {
		if ((strcmp(kname, XATTR_NAME_POSIX_ACL_ACCESS) == 0) ||
		    (strcmp(kname, XATTR_NAME_POSIX_ACL_DEFAULT) == 0))
			posix_acl_fix_xattr_to_user(kvalue, size);
		if (size && copy_to_user(value, kvalue, error))
			error = -EFAULT;
	} else if (error == -ERANGE && size >= XATTR_SIZE_MAX) {
		 
		error = -E2BIG;
	}
	if (vvalue)
		vfree(vvalue);
	else
		kfree(kvalue);
	return error;
}

SYSCALL_DEFINE4(getxattr, const char __user *, pathname,
		const char __user *, name, void __user *, value, size_t, size)
{
	struct path path;
	ssize_t error;
	unsigned int lookup_flags = LOOKUP_FOLLOW;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = getxattr(path.dentry, name, value, size);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE4(lgetxattr, const char __user *, pathname,
		const char __user *, name, void __user *, value, size_t, size)
{
	struct path path;
	ssize_t error;
	unsigned int lookup_flags = 0;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = getxattr(path.dentry, name, value, size);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE4(fgetxattr, int, fd, const char __user *, name,
		void __user *, value, size_t, size)
{
	struct fd f = fdget(fd);
	ssize_t error = -EBADF;

	if (!f.file)
		return error;
	audit_inode(NULL, f.file->f_path.dentry, 0);
	error = getxattr(f.file->f_path.dentry, name, value, size);
	fdput(f);
	return error;
}

static ssize_t
listxattr(struct dentry *d, char __user *list, size_t size)
{
	ssize_t error;
	char *klist = NULL;
	char *vlist = NULL;	 

	if (size) {
		if (size > XATTR_LIST_MAX)
			size = XATTR_LIST_MAX;
		klist = kmalloc(size, __GFP_NOWARN | GFP_KERNEL);
		if (!klist) {
			vlist = vmalloc(size);
			if (!vlist)
				return -ENOMEM;
			klist = vlist;
		}
	}

	error = vfs_listxattr(d, klist, size);
	if (error > 0) {
		if (size && copy_to_user(list, klist, error))
			error = -EFAULT;
	} else if (error == -ERANGE && size >= XATTR_LIST_MAX) {
		 
		error = -E2BIG;
	}
	if (vlist)
		vfree(vlist);
	else
		kfree(klist);
	return error;
}

SYSCALL_DEFINE3(listxattr, const char __user *, pathname, char __user *, list,
		size_t, size)
{
	struct path path;
	ssize_t error;
	unsigned int lookup_flags = LOOKUP_FOLLOW;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = listxattr(path.dentry, list, size);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE3(llistxattr, const char __user *, pathname, char __user *, list,
		size_t, size)
{
	struct path path;
	ssize_t error;
	unsigned int lookup_flags = 0;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = listxattr(path.dentry, list, size);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE3(flistxattr, int, fd, char __user *, list, size_t, size)
{
	struct fd f = fdget(fd);
	ssize_t error = -EBADF;

	if (!f.file)
		return error;
	audit_inode(NULL, f.file->f_path.dentry, 0);
	error = listxattr(f.file->f_path.dentry, list, size);
	fdput(f);
	return error;
}

static long
removexattr(struct dentry *d, const char __user *name)
{
	int error;
	char kname[XATTR_NAME_MAX + 1];

	error = strncpy_from_user(kname, name, sizeof(kname));
	if (error == 0 || error == sizeof(kname))
		error = -ERANGE;
	if (error < 0)
		return error;

	return vfs_removexattr(d, kname);
}

SYSCALL_DEFINE2(removexattr, const char __user *, pathname,
		const char __user *, name)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = mnt_want_write(path.mnt);
	if (!error) {
		error = removexattr(path.dentry, name);
		mnt_drop_write(path.mnt);
	}
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE2(lremovexattr, const char __user *, pathname,
		const char __user *, name)
{
	struct path path;
	int error;
	unsigned int lookup_flags = 0;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (error)
		return error;
	error = mnt_want_write(path.mnt);
	if (!error) {
		error = removexattr(path.dentry, name);
		mnt_drop_write(path.mnt);
	}
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE2(fremovexattr, int, fd, const char __user *, name)
{
	struct fd f = fdget(fd);
	struct dentry *dentry;
	int error = -EBADF;

	if (!f.file)
		return error;
	dentry = f.file->f_path.dentry;
	audit_inode(NULL, dentry, 0);
	error = mnt_want_write_file(f.file);
	if (!error) {
		error = removexattr(dentry, name);
		mnt_drop_write_file(f.file);
	}
	fdput(f);
	return error;
}

static const char *
strcmp_prefix(const char *a, const char *a_prefix)
{
	while (*a_prefix && *a == *a_prefix) {
		a++;
		a_prefix++;
	}
	return *a_prefix ? NULL : a;
}

#define for_each_xattr_handler(handlers, handler)		\
		for ((handler) = *(handlers)++;			\
			(handler) != NULL;			\
			(handler) = *(handlers)++)

static const struct xattr_handler *
xattr_resolve_name(const struct xattr_handler **handlers, const char **name)
{
	const struct xattr_handler *handler;

	if (!*name)
		return NULL;

	for_each_xattr_handler(handlers, handler) {
		const char *n = strcmp_prefix(*name, handler->prefix);
		if (n) {
			*name = n;
			break;
		}
	}
	return handler;
}

ssize_t
generic_getxattr(struct dentry *dentry, const char *name, void *buffer, size_t size)
{
	const struct xattr_handler *handler;

	handler = xattr_resolve_name(dentry->d_sb->s_xattr, &name);
	if (!handler)
		return -EOPNOTSUPP;
	return handler->get(dentry, name, buffer, size, handler->flags);
}

ssize_t
generic_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	const struct xattr_handler *handler, **handlers = dentry->d_sb->s_xattr;
	unsigned int size = 0;

	if (!buffer) {
		for_each_xattr_handler(handlers, handler) {
			size += handler->list(dentry, NULL, 0, NULL, 0,
					      handler->flags);
		}
	} else {
		char *buf = buffer;

		for_each_xattr_handler(handlers, handler) {
			size = handler->list(dentry, buf, buffer_size,
					     NULL, 0, handler->flags);
			if (size > buffer_size)
				return -ERANGE;
			buf += size;
			buffer_size -= size;
		}
		size = buf - buffer;
	}
	return size;
}

int
generic_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
	const struct xattr_handler *handler;

	if (size == 0)
		value = "";   
	handler = xattr_resolve_name(dentry->d_sb->s_xattr, &name);
	if (!handler)
		return -EOPNOTSUPP;
	return handler->set(dentry, name, value, size, flags, handler->flags);
}

int
generic_removexattr(struct dentry *dentry, const char *name)
{
	const struct xattr_handler *handler;

	handler = xattr_resolve_name(dentry->d_sb->s_xattr, &name);
	if (!handler)
		return -EOPNOTSUPP;
	return handler->set(dentry, name, NULL, 0,
			    XATTR_REPLACE, handler->flags);
}

EXPORT_SYMBOL(generic_getxattr);
EXPORT_SYMBOL(generic_listxattr);
EXPORT_SYMBOL(generic_setxattr);
EXPORT_SYMBOL(generic_removexattr);

struct simple_xattr *simple_xattr_alloc(const void *value, size_t size)
{
	struct simple_xattr *new_xattr;
	size_t len;

	len = sizeof(*new_xattr) + size;
	if (len <= sizeof(*new_xattr))
		return NULL;

	new_xattr = kmalloc(len, GFP_KERNEL);
	if (!new_xattr)
		return NULL;

	new_xattr->size = size;
	memcpy(new_xattr->value, value, size);
	return new_xattr;
}

int simple_xattr_get(struct simple_xattrs *xattrs, const char *name,
		     void *buffer, size_t size)
{
	struct simple_xattr *xattr;
	int ret = -ENODATA;

	spin_lock(&xattrs->lock);
	list_for_each_entry(xattr, &xattrs->head, list) {
		if (strcmp(name, xattr->name))
			continue;

		ret = xattr->size;
		if (buffer) {
			if (size < xattr->size)
				ret = -ERANGE;
			else
				memcpy(buffer, xattr->value, xattr->size);
		}
		break;
	}
	spin_unlock(&xattrs->lock);
	return ret;
}

static int __simple_xattr_set(struct simple_xattrs *xattrs, const char *name,
			      const void *value, size_t size, int flags)
{
	struct simple_xattr *xattr;
	struct simple_xattr *new_xattr = NULL;
	int err = 0;

	if (value) {
		new_xattr = simple_xattr_alloc(value, size);
		if (!new_xattr)
			return -ENOMEM;

		new_xattr->name = kstrdup(name, GFP_KERNEL);
		if (!new_xattr->name) {
			kfree(new_xattr);
			return -ENOMEM;
		}
	}

	spin_lock(&xattrs->lock);
	list_for_each_entry(xattr, &xattrs->head, list) {
		if (!strcmp(name, xattr->name)) {
			if (flags & XATTR_CREATE) {
				xattr = new_xattr;
				err = -EEXIST;
			} else if (new_xattr) {
				list_replace(&xattr->list, &new_xattr->list);
			} else {
				list_del(&xattr->list);
			}
			goto out;
		}
	}
	if (flags & XATTR_REPLACE) {
		xattr = new_xattr;
		err = -ENODATA;
	} else {
		list_add(&new_xattr->list, &xattrs->head);
		xattr = NULL;
	}
out:
	spin_unlock(&xattrs->lock);
	if (xattr) {
		kfree(xattr->name);
		kfree(xattr);
	}
	return err;

}

int simple_xattr_set(struct simple_xattrs *xattrs, const char *name,
		     const void *value, size_t size, int flags)
{
	if (size == 0)
		value = "";  
	return __simple_xattr_set(xattrs, name, value, size, flags);
}

int simple_xattr_remove(struct simple_xattrs *xattrs, const char *name)
{
	return __simple_xattr_set(xattrs, name, NULL, 0, XATTR_REPLACE);
}

static bool xattr_is_trusted(const char *name)
{
	return !strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN);
}

ssize_t simple_xattr_list(struct simple_xattrs *xattrs, char *buffer,
			  size_t size)
{
	bool trusted = capable(CAP_SYS_ADMIN);
	struct simple_xattr *xattr;
	size_t used = 0;

	spin_lock(&xattrs->lock);
	list_for_each_entry(xattr, &xattrs->head, list) {
		size_t len;

		if (!trusted && xattr_is_trusted(xattr->name))
			continue;

		len = strlen(xattr->name) + 1;
		used += len;
		if (buffer) {
			if (size < used) {
				used = -ERANGE;
				break;
			}
			memcpy(buffer, xattr->name, len);
			buffer += len;
		}
	}
	spin_unlock(&xattrs->lock);

	return used;
}

void simple_xattr_list_add(struct simple_xattrs *xattrs,
			   struct simple_xattr *new_xattr)
{
	spin_lock(&xattrs->lock);
	list_add(&new_xattr->list, &xattrs->head);
	spin_unlock(&xattrs->lock);
}
