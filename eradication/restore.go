//go:build windows

package eradication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// RestoreCase restores quarantined files and supported persistence entries.
// It never overwrites an existing target. Service backups require manual
// review because SCM deletion can stay pending until reboot.
func RestoreCase(root, id string) error {
	if id == "" || filepath.Base(id) != id || strings.ContainsAny(id, `/\:`) {
		return fmt.Errorf("invalid case ID")
	}
	casePath := filepath.Join(root, "eradication", "cases", id+".json")
	b, err := os.ReadFile(casePath)
	if err != nil {
		return err
	}
	var c Case
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.ID != id {
		return fmt.Errorf("case ID mismatch")
	}
	if c.Status == "released" || c.Status == "restored" {
		return nil
	}
	linked := false
	for _, a := range c.Artifacts {
		if a.Status == "linked" {
			linked = true
		}
	}
	if linked {
		if err := releaseLinkedCase(root, &c); err != nil {
			return err
		}
		b, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		return atomicWrite(casePath, b)
	}
	for _, a := range c.Artifacts {
		if a.Status == "quarantined" {
			if err := restoreOwnershipAllowed(root, id, a); err != nil {
				return err
			}
		}
	}
	var failures []error
	for i := range c.Artifacts {
		a := &c.Artifacts[i]
		if a.Status != "quarantined" {
			continue
		}
		if err := restoreArtifact(root, *a); err != nil {
			failures = append(failures, fmt.Errorf("restore %s: %w", a.Path, err))
			continue
		}
		if a.ID != "" {
			record, err := readArtifactRecord(root, a.Path, a.FileID)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			record.Status = "restored"
			if err := writeArtifactRecord(root, record); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		a.Status = "restored"
	}
	// A startup entry must not be re-enabled while its executable or DLL is
	// still absent. Keep the backup and the item status for a later retry.
	if len(failures) == 0 {
		for i := range c.Persistence {
			item := &c.Persistence[i]
			if item.Status != "removed" && item.Status != "delete_requested" {
				continue
			}
			if err := restorePersistence(root, id, *item); err != nil {
				failures = append(failures, fmt.Errorf("restore %s %s: %w", item.Type, item.Name, err))
			} else {
				item.Status = "restored"
			}
		}
	}
	if len(failures) == 0 {
		c.Status = "restored"
	} else {
		c.Status = "partial_restore"
	}
	if b, err := json.MarshalIndent(c, "", "  "); err != nil {
		failures = append(failures, err)
	} else if err := atomicWrite(casePath, b); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func restoreArtifact(root string, a Artifact) error {
	quarantineRoot := filepath.Join(root, "eradication", "quarantine")
	if !beneath(a.QuarantinePath, quarantineRoot) || !inUserAppData(a.Path) {
		return fmt.Errorf("restore path is outside allowed directories")
	}
	if _, err := os.Lstat(a.Path); err == nil {
		return fmt.Errorf("original path is occupied; refusing to claim an unrelated file as restored")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if hash, err := fileSHA256(a.QuarantinePath); err != nil || hash != a.SHA256 {
		return fmt.Errorf("quarantined file hash mismatch: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(a.Path), 0700); err != nil {
		return err
	}
	src, err := os.Open(a.QuarantinePath)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(a.Path), ".restore-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if hash, err := fileSHA256(tmpPath); err != nil || hash != a.SHA256 {
		return fmt.Errorf("restored copy hash mismatch: %v", err)
	}
	source, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(a.Path)
	if err != nil {
		return err
	}
	// Keep the no-overwrite guarantee even if another process creates the
	// original path after the Lstat check above.
	return windows.MoveFileEx(source, target, windows.MOVEFILE_WRITE_THROUGH)
}

func backupWithin(root, id, path string) bool {
	base := filepath.Join(root, "eradication", "backups", id)
	return beneath(path, base)
}

func restorePersistence(root, id string, item PersistenceItem) error {
	switch item.Type {
	case "registry_run":
		for _, loc := range runLocations {
			if locationName(loc) != item.Location {
				continue
			}
			key, _, err := registry.CreateKey(loc.root, loc.name, registry.QUERY_VALUE|registry.SET_VALUE|loc.view)
			if err != nil {
				return err
			}
			defer key.Close()
			if existing, _, err := key.GetStringValue(item.Name); err == nil {
				if existing == item.Evidence {
					return nil
				}
				return fmt.Errorf("Run value already exists with different content")
			}
			if item.ValueType == registry.EXPAND_SZ {
				return key.SetExpandStringValue(item.Name, item.Evidence)
			}
			if item.ValueType != registry.SZ {
				return fmt.Errorf("unsupported registry value type %d", item.ValueType)
			}
			return key.SetStringValue(item.Name, item.Evidence)
		}
		return fmt.Errorf("Run location missing from scanner")
	case "startup_link":
		if !backupWithin(root, id, item.BackupPath) {
			return fmt.Errorf("shortcut backup outside case directory")
		}
		allowed := false
		for _, dir := range startupFolders() {
			if samePath(filepath.Dir(item.Location), dir) {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("shortcut location changed")
		}
		if _, err := os.Lstat(item.Location); err == nil {
			return fmt.Errorf("shortcut path already exists")
		}
		b, err := os.ReadFile(item.BackupPath)
		if err != nil {
			return err
		}
		return atomicWrite(item.Location, b)
	case "task":
		if !backupWithin(root, id, item.BackupPath) {
			return fmt.Errorf("task backup outside case directory")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tool, err := systemTool("schtasks.exe")
		if err != nil {
			return err
		}
		if err := exec.CommandContext(ctx, tool, "/Query", "/TN", item.Name).Run(); err == nil {
			return fmt.Errorf("task already exists")
		}
		out, err := exec.CommandContext(ctx, tool, "/Create", "/TN", item.Name, "/XML", item.BackupPath).CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks create: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	case "service":
		if !backupWithin(root, id, item.BackupPath) {
			return fmt.Errorf("service backup outside case directory")
		}
		return fmt.Errorf("service backup retained at %s; restore requires SCM review", item.BackupPath)
	}
	return fmt.Errorf("unsupported persistence type %s", item.Type)
}
