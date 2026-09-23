//go:build windows

package eradication

import (
	"block-ads/utils"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(os.ExpandEnv(a)), filepath.Clean(os.ExpandEnv(b)))
}

// FileID identifies the on-disk file independent of a replaceable path.
func FileID(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x-%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}

func processPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func contain(hit HitEvent) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, hit.PID)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			// No process currently has this PID. The hit exited before dequeue.
			return true, nil
		}
		return false, fmt.Errorf("open PID %d: %w", hit.PID, err)
	}
	defer windows.CloseHandle(h)
	path, err := processPath(h)
	if err != nil || !samePath(path, hit.Image) {
		return false, fmt.Errorf("PID %d image changed or unavailable: %q: %w", hit.PID, path, err)
	}
	if hit.CreatedHigh != 0 || hit.CreatedLow != 0 {
		var created, exited, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
			return false, err
		}
		if created.HighDateTime != hit.CreatedHigh || created.LowDateTime != hit.CreatedLow {
			return false, fmt.Errorf("PID %d was recycled", hit.PID)
		}
	}
	if event, err := windows.WaitForSingleObject(h, 0); err == nil && event == windows.WAIT_OBJECT_0 {
		return true, nil
	}
	killErr := windows.TerminateProcess(h, 1)
	event, waitErr := windows.WaitForSingleObject(h, 5000)
	if waitErr != nil {
		return false, fmt.Errorf("terminate: %v; wait: %w", killErr, waitErr)
	}
	if event != windows.WAIT_OBJECT_0 {
		return false, fmt.Errorf("terminate: %v; process exit not observed within 5s", killErr)
	}
	return true, nil
}

func loadedModules(pid uint32) ([]string, error) {
	return moduleSnapshot(pid, 3)
}

func moduleSnapshot(pid uint32, attempts int) ([]string, error) {
	var snap windows.Handle
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		snap, err = windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BAD_LENGTH) {
			return nil, err
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	entry := windows.ModuleEntry32{Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{}))}
	if err := windows.Module32First(snap, &entry); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var paths []string
	for {
		path := windows.UTF16ToString(entry.ExePath[:])
		if path != "" {
			key := strings.ToLower(filepath.Clean(path))
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				paths = append(paths, path)
			}
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ModuleEntry32{}))
		if err := windows.Module32Next(snap, &entry); err != nil {
			break
		}
	}
	return paths, nil
}

// CaptureModules preserves a best-effort module list before the original kill.
func CaptureModules(pid uint32) ([]string, error) {
	return moduleSnapshot(pid, 1)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func signer(path string) string {
	s, _ := utils.GetSignName(path)
	return strings.TrimSpace(s)
}

func beneath(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, os.ErrNotExist) {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
		if parentErr != nil {
			return false
		}
		resolved = filepath.Join(parent, filepath.Base(path))
	} else if err != nil {
		return false
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(base, resolved)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

func inUserAppData(path string) bool {
	for _, root := range []string{os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA"), filepath.Join(os.Getenv("USERPROFILE"), "AppData")} {
		if beneath(path, root) {
			return true
		}
	}
	return false
}

func collectEvidence(hit HitEvent, modules []string) []Artifact {
	items := make([]Artifact, 0, len(modules)+1)
	exe := Artifact{Path: hit.Image, Kind: "exe", Signer: signer(hit.Image), Confidence: "REVIEW", Evidence: "matched " + hit.RuleKind + ":" + hit.Rule, Status: "pending"}
	exe.FileID = hit.FileID
	if hash, err := fileSHA256(hit.Image); err == nil {
		exe.SHA256 = hash
	} else {
		exe.Error = err.Error()
	}
	if currentID, err := FileID(hit.Image); err == nil && hit.FileID != "" && currentID == hit.FileID && exe.SHA256 != "" && inUserAppData(hit.Image) {
		exe.Confidence = "HIGH"
	} else if hit.FileID == "" {
		exe.Evidence += "; file identity unavailable at detection"
	} else {
		exe.Evidence += "; file identity changed or unavailable"
	}
	items = append(items, exe)
	for _, path := range modules {
		if samePath(path, hit.Image) || !strings.EqualFold(filepath.Ext(path), ".dll") {
			continue
		}
		a := Artifact{Path: path, Kind: "dll", Confidence: "LOW", Evidence: "loaded by matched PID", Status: "pending"}
		a.FileID = hit.ModuleIDs[strings.ToLower(filepath.Clean(path))]
		if !samePath(filepath.Dir(path), filepath.Dir(hit.Image)) || !inUserAppData(path) {
			items = append(items, a)
			continue
		}
		a.Signer = signer(path)
		if strings.Contains(strings.ToLower(a.Signer), "microsoft") {
			items = append(items, a)
			continue
		}
		if !((exe.Signer != "" && a.Signer != "" && strings.EqualFold(exe.Signer, a.Signer)) || (hit.RuleKind == "folder" && a.Signer == "")) {
			a.Confidence = "MEDIUM"
			items = append(items, a)
			continue
		}
		if usedByOtherProcess(path, hit.PID) {
			a.Confidence = "MEDIUM"
			a.Evidence += "; also loaded elsewhere"
			items = append(items, a)
			continue
		}
		if expectedID := hit.ModuleIDs[strings.ToLower(filepath.Clean(path))]; expectedID == "" {
			a.Confidence = "MEDIUM"
			a.Evidence += "; file identity unavailable at detection"
			items = append(items, a)
			continue
		} else if currentID, err := FileID(path); err != nil || currentID != expectedID {
			a.Confidence = "MEDIUM"
			a.Evidence += "; file identity changed"
			items = append(items, a)
			continue
		}
		if hash, err := fileSHA256(path); err == nil {
			a.SHA256 = hash
			a.Confidence = "HIGH"
			a.Evidence += "; same directory and signer/rule; no other loader observed"
		} else {
			a.Error = err.Error()
		}
		items = append(items, a)
	}
	return items
}

func usedByOtherProcess(path string, hitPID uint32) bool {
	for _, pid := range utils.Listpid() {
		if pid == hitPID || pid == 0 || pid == 4 {
			continue
		}
		mods, err := moduleSnapshot(pid, 1)
		if err != nil {
			continue
		}
		for _, mod := range mods {
			if samePath(mod, path) {
				return true
			}
		}
	}
	return false
}

type quarantineMetadata struct {
	CaseID       string    `json:"case_id"`
	OriginalPath string    `json:"original_path"`
	SHA256       string    `json:"sha256"`
	Signer       string    `json:"signer,omitempty"`
	Rule         string    `json:"rule"`
	PID          uint32    `json:"pid"`
	Quarantined  time.Time `json:"quarantined_at"`
}

func (m *Manager) quarantine(caseID string, hit HitEvent, a Artifact) (string, error) {
	if a.SHA256 == "" || !inUserAppData(a.Path) {
		return "", fmt.Errorf("artifact is outside verified user AppData or lacks hash")
	}
	fi, err := os.Lstat(a.Path)
	if err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("source is not a regular file: %v", err)
	}
	if currentID, err := FileID(a.Path); err != nil || a.FileID == "" || currentID != a.FileID {
		return "", fmt.Errorf("source file identity changed: %v", err)
	}
	dir := filepath.Join(m.root, "eradication", "quarantine")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	ext := strings.ToLower(filepath.Ext(a.Path))
	target := filepath.Join(dir, a.SHA256+ext)
	tmp, err := os.CreateTemp(dir, ".artifact-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	src, err := os.Open(a.Path)
	if err != nil {
		tmp.Close()
		return "", err
	}
	_, copyErr := io.Copy(tmp, src)
	src.Close()
	if copyErr != nil {
		tmp.Close()
		return "", copyErr
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	copyHash, err := fileSHA256(tmpPath)
	if err != nil || copyHash != a.SHA256 {
		return "", fmt.Errorf("quarantine copy hash mismatch: %v", err)
	}
	if existingHash, err := fileSHA256(target); err == nil {
		if existingHash != a.SHA256 {
			return "", fmt.Errorf("quarantine hash collision at %s", target)
		}
		if fi, err := os.Lstat(target); err != nil || !fi.Mode().IsRegular() || !beneath(target, dir) {
			return "", fmt.Errorf("existing quarantine target is not a regular local file: %v", err)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(tmpPath, target); err != nil {
			return "", err
		}
	} else {
		return "", err
	}
	meta := quarantineMetadata{CaseID: caseID, OriginalPath: a.Path, SHA256: a.SHA256, Signer: a.Signer, Rule: hit.RuleKind + ":" + hit.Rule, PID: hit.PID, Quarantined: time.Now()}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", err
	}
	if err := atomicWrite(filepath.Join(dir, caseID+"-"+a.SHA256+ext+".json"), b); err != nil {
		return "", err
	}
	current, err := os.Lstat(a.Path)
	if err != nil || !os.SameFile(fi, current) {
		return "", fmt.Errorf("source changed before removal: %v", err)
	}
	if currentID, err := FileID(a.Path); err != nil || currentID != a.FileID {
		return "", fmt.Errorf("source file identity changed before removal: %v", err)
	}
	currentHash, err := fileSHA256(a.Path)
	if err != nil || currentHash != a.SHA256 {
		return "", fmt.Errorf("source hash changed before removal: %v", err)
	}
	if err := os.Remove(a.Path); err != nil {
		return "", err
	}
	if _, err := os.Lstat(a.Path); !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("source still present after removal: %v", err)
	}
	return target, nil
}
