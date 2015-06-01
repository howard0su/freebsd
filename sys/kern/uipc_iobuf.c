/*-
 * Copyright (c) 2015 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/file.h>
#include <sys/iobuf.h>
#include <sys/malloc.h>

static MALLOC_DEFINE(M_IOBUF, "iobuf", "I/O buffer pool file descriptor");
static struct unrhdr *iobuf_ino_unr;
static dev_t iobuf_dev_ino;

static fo_ioctl_t iobuf_ioctl;
static fo_stat_t iobuf_stat;
static fo_close_t iobuf_close;
static fo_fill_kinfo iobuf_fill_kinfo;
static fo_mmap iobuf_mmap;

static struct fileops iobuf_ops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = iobuf_ioctl,
	.fo_poll = invfo_poll,
	.fo_kqfilter = invfo_kqfilter,
	.fo_stat = iobuf_stat,
	.fo_close = iobuf_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = iobuf_fill_kinfo,
	.fo_mmap = iobuf_mmap,
	.fo_flags = DFLAG_PASSABLE
};

static void
iobuf_init(void *arg __unused)
{

	iobuf_ino_unr = new_unrhdr(1, INT32_MAX, NULL);
	KASSERT(iobuf_ino_unr != NULL, ("I/O buf fake inodes not initialized"));
	iobuf_dev_ino = devfs_alloc_cdp_inode();
	KASSERT(iobuf_dev_ino > 0, ("I/O buf dev inode not initialized"));
}

int
sys_iobuf_create(struct thread *td, struct iobuf_create_args *uap)
{
	size_t total_size;
	struct file *fp;
	struct iobuf_pool *ip;
	int error, fd, ino;

	total_size = uap->number * uap->size;
	if (total_size / uap->number != uap->size)
		return (EINVAL);

	error = falloc(td, &fp, &fd, O_CLOEXEC);
	if (error)
		return (error);

	ip = malloc(sizeof(*ip), M_IOBUF, M_WAITOK | M_ZERO);
	ip->ip_size = total_size;
	ip->ip_nbufs = uap->number;
	ip->ip_bufsize = uap->size;
	ip->ip_nfreebuf = uap->number;
	ip->ip_uid = td->td_ucred->cr_uid;
	ip->ip_gid = td->td_ucred->cr_gid;
	ip->ip_object = vm_pager_allocate(OBJT_DEFAULT, NULL, ip->ip_size,
	    VM_PROT_DEFAULT, 0, td->td_ucred);
	ip->ip_object->pg_color = 0;
	VM_OBJECT_WLOCK(ip->ip_object);
	vm_object_clear_flag(ip->ip_object, OBJ_ONEMAPPING);
	vm_object_set_flag(ip->ip_object, OBJ_COLORED | OBJ_NOSPLIT);
	VM_OBJECT_WUNLOCK(ip->ip_object);
	vfs_timestamp(&ip->ip_birthtime);
	ip->ip_atime = ip->ip_mtime = ip->ip_ctime = ip->ip_birthtime;
	ino = alloc_unr(shm_ino_unr);
	if (ino == -1)
		ip->ip_ino = 0;
	else
		ip->ip_ino = ino;
	finit(fp, FFLAGS(O_RDWR), DTYPE_IOBUF, ip, &iobuf_ops);

	td->td_retval[0] = fd;
	fdrop(fp, td);

	return (0);
}

static int
iobuf_ioctl(struct file *fp, u_long com, void *data, struct ucred *active_cred,
    struct thread *td)
{
	return (ENOTTY);
}

static int
iobuf_stat(struct file *fp, struct stat *sb, struct ucred *active_cred,
    struct thread *td)
{
	struct iobuf_pool *ip;

	ip = fp->f_data;

	bzero(sb, sizeof(*sb));
	sb->st_blksize = ip->ip_bufsize;
	sb->st_size = ip->ip_size;
	sb->st_blocks = ip->ip_nbufs;
	sb->st_atim = ip->ip_atime;
	sb->st_ctim = ip->ip_ctime;
	sb->st_mtim = ip->ip_mtime;
	sb->st_birthtim = ip->ip_birthtime;
	sb->st_mode = S_IFREG | S_IRUSR | S_IWUSR;
	sb->st_uid = ip->ip_uid;
	sb->st_gid = ip->ip_gid;
	sb->st_dev = iobuf_dev_ino;
	sb->st_ino = ip->ip_ino;

	return (0);
}

static int
iobuf_close(struct file *fp, struct thread *td)
{
	struct iobuf_pool *ip;

	ip = fp->f_data;
	fp->f_data = NULL;
	vm_object_deallocate(ip->ip_object);
	free(ip, M_IOBUF);

	return (0);
}

static int
iobuf_mmap(struct file *fp, vm_map_t map, vm_offset_t *addr, vm_size_t objsize,
    vm_prot_t prot, vm_prot_t cap_maxprot, int flags,
    vm_ooffset_t foff, struct thread *td)
{
	struct iobuf_pool *ip;
	vm_prot_t maxprot;

	ip = fp->f_data;

	/* Don't permit private mappings. */
	if (flags & MAP_PRIVATE)
		return (EINVAL);

	maxprot = VM_PROT_READ | VM_PROT_WRITE;
	maxprot &= cap_maxprot;

	if (foff >= ip->ip_size ||
	    foff + objsize > round_page(ip->ip_size))
		return (EINVAL);

	vfs_timestamp(&ip->ip_atime);
	vm_object_reference(&ip->ip_object);

	error = vm_mmap_object(map, addr, objsize, prot, maxprot, flags,
	    ip->ip_object, foff, FALSE, td);
	if (error != 0)
		vm_object_deallocate(ip->ip_object);
	return (0);
}

static int
iobuf_fill_kinfo(struct file *fp, struct kinfo_file *kif, struct filedesc *fdp)
{
	struct iobuf_pool *ip;

	/* XXX: TODO */
	kif->kf_type = KF_TYPE_UNKNOWN;
	ip = fp->f_data;

	kif->kf_un.kf_file.kf_file_mode = S_IFREG | S_IRUSR | S_IWUSR;
	kif->kf_un.kf_file.kf_file_size = ip->ip_size;

	return (0);
}

