//go:build windows

package store

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows, Go's os package ignores POSIX permission bits: mode 0600 on
// os.WriteFile/os.Chmod does not restrict who can read a file. These
// functions therefore enforce a restrictive DACL directly: only the current
// user, SYSTEM, and local Administrators are granted access, and the DACL is
// marked protected so it no longer inherits from the parent directory.
//
// x/sys/windows does not expose the advapi32 ACL builder functions, so the
// DACL buffer is constructed directly (ACL header, then one
// ACCESS_ALLOWED_ACE per principal: header + access mask + inline SID).

const (
	aclHeaderSize = 8
	aceHeaderSize = 4
	aceMaskSize   = 4
	aclRevision   = 2
)

// protectedSIDs lists the principals allowed to access vault files: the
// current user, SYSTEM, and local Administrators (which can always take
// ownership anyway; listing them explicitly matches icacls conventions).
func protectedSIDs() ([]*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, fmt.Errorf("open process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get token user: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("create SYSTEM sid: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("create Administrators sid: %w", err)
	}
	return []*windows.SID{user.User.Sid, system, admins}, nil
}

// restrictFilePermissions replaces the DACL of path with one granting access
// only to the current user, SYSTEM, and Administrators, and protects it from
// inheriting ACEs from the parent directory.
func restrictFilePermissions(path string) error {
	sids, err := protectedSIDs()
	if err != nil {
		return err
	}
	acl, _, err := buildRestrictiveDacl(sids)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return fmt.Errorf("set DACL on %s: %w", path, err)
	}
	return nil
}

// verifyFilePermissions walks the DACL of path and reports an error if any
// access-allowed ACE grants a principal outside the protected set.
func verifyFilePermissions(path string) error {
	sids, err := protectedSIDs()
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read DACL of %s: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s has no DACL; expected a user-restricted DACL", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d of %s: %w", i, path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue // deny ACEs only restrict further; they are safe
		}
		// #nosec G103 -- SID starts inline after the ACE header and mask
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		allowed := false
		for _, p := range sids {
			if windows.EqualSid(sid, p) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%s grants access to an unexpected principal; expected only the current user, SYSTEM and Administrators", path)
		}
	}
	return nil
}

// buildRestrictiveDacl constructs an ACL granting GENERIC_ALL to each SID.
// The returned buffer must stay alive for the duration of the syscall that
// consumes the ACL.
func buildRestrictiveDacl(sids []*windows.SID) (*windows.ACL, []byte, error) {
	size := aclHeaderSize
	for _, sid := range sids {
		size += aceHeaderSize + aceMaskSize + int(sid.Len())
	}
	buf := make([]byte, size) // #nosec G103 -- buffer backed by a Go allocation
	buf[0] = aclRevision
	binary.LittleEndian.PutUint16(buf[2:4], uint16(size))
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(sids)))
	off := aclHeaderSize
	for _, sid := range sids {
		sidLen := int(sid.Len())
		aceSize := aceHeaderSize + aceMaskSize + sidLen
		buf[off] = windows.ACCESS_ALLOWED_ACE_TYPE
		binary.LittleEndian.PutUint16(buf[off+2:off+4], uint16(aceSize))
		binary.LittleEndian.PutUint32(buf[off+4:off+8], uint32(windows.GENERIC_ALL))
		// #nosec G103 -- SID bytes are copied verbatim into the ACE
		sidBytes := unsafe.Slice((*byte)(unsafe.Pointer(sid)), sidLen)
		copy(buf[off+8:], sidBytes)
		off += aceSize
	}
	return (*windows.ACL)(unsafe.Pointer(&buf[0])), buf, nil // #nosec G103 -- pointer into buf, kept alive by the returned slice
}

// syncDir is a no-op on Windows: the rename in writeFileAtomic is
// transactional per file on NTFS and there is no portable directory fsync.
func syncDir(dir string) {}
