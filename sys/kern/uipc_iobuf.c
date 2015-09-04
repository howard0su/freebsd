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

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/iobuf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sysproto.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

static MALLOC_DEFINE(M_IOBUF, "iobuf", "I/O buffer pool file descriptor");
static struct unrhdr *iobuf_ino_unr;
static dev_t iobuf_dev_ino;

static fo_ioctl_t iobuf_ioctl;
static fo_stat_t iobuf_stat;
static fo_close_t iobuf_close;
static fo_fill_kinfo_t iobuf_fill_kinfo;
static fo_mmap_t iobuf_mmap;

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
SYSINIT(iobuf_init, SI_SUB_DRIVERS, SI_ORDER_ANY, iobuf_init, NULL);

struct iobuf_pool *
iobuf_pool_hold(struct iobuf_pool *ip)
{

	refcount_acquire(&ip->ip_refs);
	return (ip);
}

void
iobuf_pool_drop(struct iobuf_pool *ip)
{
#ifdef INVARIANTS
	struct iobuf *io;
	int i;
#endif

	if (!refcount_release(&ip->ip_refs))
		return;

#ifdef INVARIANTS
	i = 0;
	STAILQ_FOREACH(io, &ip->ip_freebufs, io_link) {
		KASSERT(io->io_pool == ip, ("iobuf pool mismatch"));
		KASSERT(io == &ip->ip_buffers[io->io_id],
		    ("iobuf id mismatch"));
		i++;
	}
	KASSERT(i == ip->ip_nbufs, ("iobuf free count mismatch"));
#endif
	vm_object_deallocate(ip->ip_object);
	mtx_destroy(&ip->ip_lock);
	free(ip->ip_buffers, M_IOBUF);
	free(ip, M_IOBUF);
}

static struct iobuf *
iobuf_get_locked(struct iobuf_pool *ip, enum iobuf_owner owner)
{
	struct iobuf *io;

	KASSERT(owner == KERNEL || owner == USER);
	mtx_assert(&ip->ip_lock, MA_OWNED);
	io = STAILQ_FIRST(&ip->ip_freebufs);
	if (io != NULL) {
		KASSERT(io->io_pool == ip, ("iobuf pool mismatch"));
		KASSERT(io == &ip->ip_buffers[io->io_id],
		    ("iobuf id mismatch"));
		KASSERT(io->io_owner == FREE, ("iobuf not free"));
		STAILQ_REMOVE_HEAD(&ip->ip_freebufs, io_link);
		io->owner = owner;
		iobuf_pool_hold(ip);
	}
	return (io);
}

struct iobuf *
iobuf_get(struct iobuf_pool *ip, enum iobuf_owner owner)
{
	struct iobuf *io;

	mtx_lock(&ip->ip_lock);
	io = iobuf_get_locked(ip, owner);
	mtx_unlock(&ip->ip_lock);
	return (io);
}

static void
iobuf_put_locked(struct iobuf *io)
{
	struct iobuf_pool *ip;

	ip = io->io_pool;
	KASSERT(io == &ip->ip_buffers[io->io_id],
	    ("iobuf id mismatch"));
	KASSERT(io->io_owner != FREE, ("iobuf already free"));
	mtx_assert(&ip->ip_lock, MA_OWNED);
	io->io_owner = FREE;
	STAILQ_INSERT_TAIL(&ip->ip_freebufs, io, io_link);
	if (refcount_release(&ip->ip_refs))
		panic("iobuf_put_locked: dropped last pool reference");
}

void
iobuf_put(struct iobuf *io)
{
	struct iobuf_pool *ip;

	ip = io->io_pool;
	KASSERT(io == &ip->ip_buffers[io->io_id],
	    ("iobuf id mismatch"));
	KASSERT(io->io_owner != FREE, ("iobuf already free"));
	mtx_lock(&ip->ip_lock);
	io->io_owner = FREE;
	STAILQ_INSERT_TAIL(&ip->ip_freebufs, io, io_link);
	mtx_unlock(&ip->ip_lock);
	iobuf_pool_drop(ip);
}

int
sys_iobuf_create(struct thread *td, struct iobuf_create_args *uap)
{
	size_t total_size;
	struct file *fp;
	struct iobuf_pool *ip;
	int error, fd, i, ino;

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
	ino = alloc_unr(iobuf_ino_unr);
	if (ino == -1)
		ip->ip_ino = 0;
	else
		ip->ip_ino = ino;
	STAILQ_INIT(&ip->ip_freebufs);
	ip->ip_buffers = malloc(sizeof(*ip->ip_buffers) * ip->ip_nbufs,
	    M_IOBUF, M_WAITOK | M_ZERO);
	for (i = 0; i < ip->ip_nbufs; i++) {
		ip->ip_buffers[i].io_pool = ip;
		ip->ip_buffers[i].io_id = i;
		ip->ip_buffers[i].io_owner = FREE;
		STAILQ_INSERT_TAIL(&ip->ip_freebufs, &ip->ip_buffers[i],
		    io_link);
	}
	refcount_init(&ip->ip_refs, 1);
	mtx_init(&ip->ip_lock, "iobuf pool", NULL, MTX_DEF);
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
	int i;

	ip = fp->f_data;
	fp->f_data = NULL;

	/*
	 * Free buffers owned by userland (but not buffers owned
	 * by an in-kernel consumer).
	 */
	mtx_lock(&ip->ip_lock);
	for (i = 0; i < ip->ip_nbufs; i++)
		if (ip->ip_buffers[i].io_owner == USER)
			iobuf_put_locked(&ip->ip_buffers[i]);
	mtx_unlock(&ip->ip_lock);
	iobuf_pool_drop(ip);

	return (0);
}

static int
iobuf_mmap(struct file *fp, vm_map_t map, vm_offset_t *addr, vm_size_t objsize,
    vm_prot_t prot, vm_prot_t cap_maxprot, int flags,
    vm_ooffset_t foff, struct thread *td)
{
	struct iobuf_pool *ip;
	vm_prot_t maxprot;
	int error;

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
	vm_object_reference(ip->ip_object);

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

int
sys_iobuf_bind(struct thread *td, struct iobuf_bind_args *uap)
{

	/*
	 * TODO
	 *
	 * Bind a file descriptor to a specific I/O buffer pool.  This
	 * allows iobuf_{p,}read() to be used with a file descriptor.
	 * Note that once a file descriptor is bound to a pool it cannot
	 * be read with normal operations, only via iobuf reads.
	 *
	 * XXX: This could perhaps be an ioctl on the fd instead of a
	 * new system call?
	 */
	return (EOPNOTSUPP);
}

/*
 * TODO
 *
 * Eventually we will need separate fileops hooks for iobuf read/write.
 * These hooks will be optional.  If they do not exist, we will resort
 * to mapping the buffers into the kernel and copying.
 */

static int
iobuf_map(struct iobuf *io, void **memp, bool writable)
{
	vm_offset_t kva, ofs;
	vm_ooffset_t offset;
	vm_object_t obj;
	vm_size_t size;
	vm_prot_t prot;
	int rv;

	obj = io->io_pool->ip_object;
	size = io->io_pool->ip_bufsize;
	offset = size * io->io_id;
	prot = VM_PROT_READ;
	if (writable)
		prot |= VM_PROT_WRITE;
	vm_object_reference(obj);

	/* Map this buffer's pages into the kernel_map and wire it. */
	kva = vm_map_pin(kernel_map);
	ofs = offset & PAGE_MASK;
	size = round_page(size + ofs);
	rv = vm_map_find(kernel_map, obj, offset, &kva, size, 0,
	    VMFS_OPTIMAL_SPACE, prot, prot, 0);
	if (rv == KERN_SUCCESS) {
		rv = vm_map_wire(kernel_map, kva, kva + size,
		    VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_NOHOLES);
		if (rv == KERN_SUCCESS) {
			*memp = (void *)(kva + ofs);
			return (0);
		}
		vm_map_remove(kernel_map, kva, kva + size);
	} else
		vm_object_deallocate(obj);
	return (vm_mmap_to_errno(rv));
}

static void
iobuf_unmap(struct iobuf *io, void *mem)
{
	vm_offset_t kva, ofs;
	vm_ooffset_t offset;
	vm_size_t size;
	vm_map_t map;
#ifdef INVARIANTS
	vm_object_t obj;
	vm_pindex_t pindex;
	vm_prot_t prot;
	boolean_t wired;
	int rv;
#endif

	size = io->io_pool->ip_bufsize;
	offset = size * io->io_id;
	ofs = offset & PAGE_MASK;
	size = round_page(size + ofs);
	kva = (vm_offset_t)mem - ofs;
	KASSERT((kva & PAGE_MASK) == 0, ("iobuf_unmap: kva not aligned"));
	map = kernel_map;
#ifdef INVARIANTS
	rv = vm_map_lookup(&map, kva, VM_PROT_READ, &entry, &obj, &pindex,
	    &prot, &wired);
	KASSERT(rv == KERN_SUCCESS, ("iobuf_unmap: did not find entry"));
	KASSERT(entry->start == kva, ("iobuf_unmap: entry start mismatch"));
	KASSERT(entry->end != kva + size,
	    ("iobuf_unmap: entry start mismatch"));
	vm_map_lookup_done(map, entry);
	KASSERT(obj == io->io_pool->ip_object,
	    ("iobuf_unmap: object mismatch"));
	KASSERT(wired != 0, ("iobuf_unmap: entry not wired"));
#endif
	vm_map_remove(map, kva, kva + size);
}

/*
 * For the "legacy" path, map all of the buffers in an iobuf_vec into
 * KVA and wire them.  I considered iterating through the passed in
 * iobuf_vec array and doing separate read/write operations for each
 * vec entry.  However, this would not properly handle datagrams, etc.
 * Instead, each system call needs to result in a single call to
 * fo_read() or fo_write().
 */
struct iobuf_uio {
	struct uio uio;
	void **bufs;
};
	
static int
iobuf_map_vec(struct iobuf_pool *ip, struct iobuf_vec *iov, u_int iovcnt,
    bool writable, struct iobuf_uio **uiop)
{
	struct iobuf_uio *uio;
	struct iovec *iov2;
	void **memp;
	size_t iovlen, resid;
	int error, i;

	/* Check for invalid length or too many vectors. */
	if (iovcnt > UIO_MAXIOV)
		return (EINVAL);
	resid = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > IOSIZE_MAX - resid)
			return (EINVAL);
		resid += iov[i].iov_len;
	}

	/* Allocate the uio and associated arrays. */
	iovlen = iovcnt * sizeof(struct iovec);
	uio = malloc(sizeof(*uio) + iovlen + iovcnt * sizeof(void *), M_IOV,
	    M_WAITOK | M_ZERO);
	iov2 = (struct iovec *)(uio + 1);
	memp = (void **)((char *)iov2 + iovlen);

	/* Map all the buffers. */
	for (i = 0; i < iovcnt; i++) {
		error = iobuf_map(ip->ip_buffers[iov[i].iov_id], &memp[i],
		    writable);
		if (error) {
			for (i--; i >= 0; i--)
				iobuf_unmap(ip->ip_buffers[iov[i].iov_id],
				    memp[i]);
			free(uio, M_IOV);
			return (error);
		}
	}

	/* Populate the uio. */
	uio->uio.uio_iov = iov2;
	uio->uio.uio_iovcnt = iovcnt;
	uio->uio.uio_segflg = UIO_SYSSPACE;
	uio->uio.uio_offset = -1;
	uio->uio.uio_resid = resid;
	for (i = 0; i < iovcnt; i++) {
		iov2[i].iov_base = (char *)memp[i] + iov[i].iov_base;
		iov2[i].iov_len = iov[i].iov_len;
	}
	uio->bufs = memp;
	return (0);
}

static void
iobuf_unmap_vec(struct iobuf_uio *uio, struct iobuf_pool *ip,
    struct iobuf_vec *iov, u_int iovcnt)
{
	int i;

	for (i = 0; i < iovcnt; i++)
		iobuf_unmap(ip->ip_buffers[iov[i].iov_id], uio->bufs[i]);
	free(uio, M_IOV);
}

/*
 * For read, allocate as many buffers as userland will accept.  If
 * userland requests more buffers than are available fail rather
 * than returning a truncated datagram.
 */
static int
iobuf_alloc_read_buffers(struct iobuf_pool *ip, int iovcnt,
    struct iobuf_vec **iovp)
{
	struct iobuf *io;
	int i;

	if (iovcnt > ip->ip_nbufs)
		return (EINVAL);
	iov = malloc(sizeof(*iov) * iovcnt, M_IOV, M_WAITOK);
	mtx_lock(&ip->ip_lock);
	for (i = 0; i < iovcnt; i++) {
		io = iobuf_get_locked(ip, USER);
		if (io == NULL)
			goto fail;
		iov[i].iov_id = io->io_id;
		iov[i].iov_base = 0;
		iov[i].iov_len = ip->ip_bufsize;
	}
	mtx_unlock(&ip->ip_lock);
	*iovp = iov;
	return (0);
fail:
	for (i--; i >= 0; i--)
		iobuf_put_locked(&ip->ip_buffers[iov[i].iov_id]);
	mtx_unlock(&ip->ip_lock);
	free(iov, M_IOV);
	return (EAGAIN);
}

static void
iobuf_free_read_buffers(struct iobuf_pool *ip, int iovcnt,
    struct iobuf_vec *iov)
{
	int i;

	mtx_lock(&ip->ip_lock);
	for (i = 0; i < iovcnt; i++)
		iobuf_put_locked(&ip->ip_buffers[iov[i].iov_id]);
	mtx_unlock(&ip->ip_lock);
	free(iov, M_IOV);
}

static struct iobuf_pool *
iobuf_pool_from_file(struct file *fp)
{
	struct iobuf_pool *ip;
	struct mtx *mtxp;

	mtxp = mtx_pool_find(mtxpool_sleep, fp);
	mtx_lock(mtxp);
	if (fp->f_iobuf_pool != NULL)
		ip = iobuf_pool_hold(fp->f_iobuf_pool);
	else
		ip = NULL;
	mtx_unlock(mtxp);
	return (ip);
}

int
sys_iobuf_read(struct thread *td, struct iobuf_read_args *uap)
{
	struct file *fp;
	struct iobuf_pool *ip;
	struct iobuf_vec *iov;
	struct iobuf_uio *uio;
	cap_rights_t rights;
	int error;

	error = fget_read(td, uap->fd, cap_rights_init(&rights, CAP_READ),
	    &fp);
	if (error)
		return (error);
	ip = iobuf_pool_from_file(fp);
	if (ip == NULL) {
		fdrop(fp, td);
		return (EINVAL);
	}

	/*
	 * TODO: Handle native iobuf fo_read variant case.
	 */
	error = iobuf_alloc_read_buffers(ip, uap->iovcnt, &iov);
	if (error) {
		iobuf_pool_drop(ip);
		fdrop(fp, td);
		return (error);
	}
	error = iobuf_map_vec(ip, iov, uap->iovcnt, true, &uio);
	if (error) {
		iobuf_free_read_buffers(ip, uap->iovcnt, iov);
		iobuf_pool_drop(ip);
		fdrop(fp, td);
		return (error);
	}
	error = dofileread(td, uap->fd, fp, &uio->uio, -1, 0);
	iobuf_unmap_vec(uio, ip, iov, uap->iovcnt);
	if (error == 0)
		/*
		 * XXX: If this fails the data from the file
		 * descriptor is lost.
		 */
		error = copyout(iov, uap->iov, uap->iovcnt * sizeof(*iov));
	if (error) {
		iobuf_free_read_buffers(ip, uap->iovcnt, iov);
		iobuf_pool_drop(ip);
		fdrop(fp, td);
	}
	free(iov, M_IOV);
	iobuf_pool_drop(ip);
	fdrop(fp, td);
	return (0);
}

int
sys_iobuf_pread(struct thread *td, struct iobuf_pread_args *uap)
{

	/*
	 * TODO
	 */
	return (EOPNOTSUPP);
}


int
sys_iobuf_write(struct thread *td, struct iobuf_write_args *uap)
{

	/*
	 * TODO
	 */
	return (EOPNOTSUPP);
}

int
sys_iobuf_pwrite(struct thread *td, struct iobuf_pwrite_args *uap)
{

	/*
	 * TODO
	 */
	return (EOPNOTSUPP);
}

/* XXX: Might also need recvfrom, recvmsg, sendto, sendmsg variants. */
