use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
};

const PRIVATE_FILE_MODE: libc::mode_t = 0o600;

pub(super) struct Directory {
    fd: OwnedFd,
}

pub(super) struct SourceIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
    size: libc::off_t,
    modified_seconds: libc::time_t,
    modified_nanoseconds: libc::c_long,
    changed_seconds: libc::time_t,
    changed_nanoseconds: libc::c_long,
    mode: libc::mode_t,
    links: libc::nlink_t,
    owner: libc::uid_t,
}

impl Directory {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let encoded = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: `encoded` is a live NUL-terminated path. The returned descriptor is
        // checked before ownership is transferred to `OwnedFd`.
        let fd = unsafe {
            libc::open(
                encoded.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a newly opened descriptor owned by this function.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { fd })
    }

    pub(super) fn require_absent(&self, leaf: &CStr) -> io::Result<()> {
        let mut metadata = empty_stat();
        // SAFETY: the directory descriptor and C string are live, and `metadata`
        // points to writable storage for the duration of the call.
        let result = unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                leaf.as_ptr(),
                &mut metadata,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(error)
        }
    }

    pub(super) fn create_private(&self, leaf: &CStr) -> io::Result<File> {
        // SAFETY: the directory descriptor and C string are live. `O_EXCL` gives
        // this call unique ownership of any returned descriptor.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                libc::c_uint::from(PRIVATE_FILE_MODE),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a newly opened descriptor owned by this function.
        let file = unsafe { File::from_raw_fd(fd) };
        // SAFETY: `file` owns a valid descriptor and the requested mode contains
        // no group or other permissions.
        if unsafe { libc::fchmod(file.as_raw_fd(), PRIVATE_FILE_MODE) } != 0 {
            return Err(io::Error::last_os_error());
        }
        verify_private_regular(&file, Some(1))?;
        Ok(file)
    }

    pub(super) fn open_readonly(&self, leaf: &CStr) -> io::Result<File> {
        // SAFETY: the directory descriptor and C string are live. The returned
        // descriptor is checked before ownership is transferred to `File`.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a newly opened descriptor owned by this function.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn link_no_replace(&self, source: &CStr, target: &CStr) -> io::Result<()> {
        self.require_absent(target)?;
        // SAFETY: both names are live C strings relative to the same live
        // directory descriptor. No flag permits replacement or symlink following.
        let result = unsafe {
            libc::linkat(
                self.fd.as_raw_fd(),
                source.as_ptr(),
                self.fd.as_raw_fd(),
                target.as_ptr(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn unlink(&self, leaf: &CStr) -> io::Result<()> {
        // SAFETY: `leaf` is a validated single component relative to the retained
        // directory descriptor. `unlinkat` cannot traverse it as a path.
        let result = unsafe { libc::unlinkat(self.fd.as_raw_fd(), leaf.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn sync(&self) -> io::Result<()> {
        // SAFETY: the retained descriptor refers to the opened directory.
        if unsafe { libc::fsync(self.fd.as_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn recheck_path(&self, path: &Path) -> io::Result<()> {
        let reopened = Self::open(path)?;
        let retained = file_stat(self.fd.as_raw_fd())?;
        let current = file_stat(reopened.fd.as_raw_fd())?;
        if retained.st_dev == current.st_dev
            && retained.st_ino == current.st_ino
            && retained.st_mode & libc::S_IFMT == libc::S_IFDIR
            && current.st_mode & libc::S_IFMT == libc::S_IFDIR
            && retained.st_uid == current.st_uid
        {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::InvalidData))
        }
    }
}

pub(super) fn split_path(path: &Path) -> io::Result<(&Path, CString)> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    if Path::new(leaf).components().count() != 1
        || !matches!(
            Path::new(leaf).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let leaf =
        CString::new(leaf.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    Ok((parent, leaf))
}

pub(super) fn private_regular_identity(file: &File) -> io::Result<SourceIdentity> {
    let metadata = file_stat(file.as_raw_fd())?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_nlink != 1
        || metadata.st_uid != effective_uid()
        || metadata.st_mode & 0o077 != 0
    {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    Ok(identity(metadata))
}

pub(super) fn source_identity(file: &File) -> io::Result<SourceIdentity> {
    let metadata = file_stat(file.as_raw_fd())?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG || metadata.st_nlink != 1 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    Ok(identity(metadata))
}

pub(super) fn recheck_identity(file: &File, expected: &SourceIdentity) -> io::Result<()> {
    let current = identity(file_stat(file.as_raw_fd())?);
    if current.device != expected.device
        || current.inode != expected.inode
        || current.size != expected.size
        || current.modified_seconds != expected.modified_seconds
        || current.modified_nanoseconds != expected.modified_nanoseconds
        || current.changed_seconds != expected.changed_seconds
        || current.changed_nanoseconds != expected.changed_nanoseconds
        || current.mode != expected.mode
        || current.links != expected.links
        || current.owner != expected.owner
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(())
}

pub(super) fn file_size(identity: &SourceIdentity) -> io::Result<u64> {
    u64::try_from(identity.size).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

pub(super) fn verify_private_regular(file: &File, links: Option<libc::nlink_t>) -> io::Result<()> {
    let metadata = file_stat(file.as_raw_fd())?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != effective_uid()
        || metadata.st_mode & 0o077 != 0
        || links.is_some_and(|value| metadata.st_nlink != value)
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(())
}

fn file_stat(fd: RawFd) -> io::Result<libc::stat> {
    let mut metadata = empty_stat();
    // SAFETY: `fd` is borrowed from a live owned descriptor and `metadata` points
    // to writable storage for the duration of the call.
    if unsafe { libc::fstat(fd, &mut metadata) } == 0 {
        Ok(metadata)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn empty_stat() -> libc::stat {
    // SAFETY: `libc::stat` is a plain C data structure for which an all-zero
    // value is valid scratch storage before `fstat`/`fstatat` initializes it.
    unsafe { std::mem::zeroed() }
}

pub(super) fn effective_uid() -> libc::uid_t {
    // SAFETY: `geteuid` takes no arguments and has no memory-safety preconditions.
    unsafe { libc::geteuid() }
}

fn identity(metadata: libc::stat) -> SourceIdentity {
    SourceIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        size: metadata.st_size,
        modified_seconds: metadata.st_mtime,
        modified_nanoseconds: metadata.st_mtime_nsec,
        changed_seconds: metadata.st_ctime,
        changed_nanoseconds: metadata.st_ctime_nsec,
        mode: metadata.st_mode,
        links: metadata.st_nlink,
        owner: metadata.st_uid,
    }
}
