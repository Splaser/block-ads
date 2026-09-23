//go:build windows

package eradication

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestSubmitKeepsEveryHit(t *testing.T) {
	m := &Manager{}
	m.queueReady = sync.NewCond(&m.queueMu)
	for pid := uint32(1); pid <= 1000; pid++ {
		m.Submit(HitEvent{PID: pid})
	}
	for pid := uint32(1); pid <= 1000; pid++ {
		hit, ok := m.next()
		if !ok || hit.PID != pid {
			t.Fatalf("hit %d = %+v, %v", pid, hit, ok)
		}
	}
}

func TestExactTargetRequiresKnownArtifactPath(t *testing.T) {
	exe := `C:\Users\Alice\AppData\Roaming\Bad App\bad.exe`
	dll := `C:\Users\Alice\AppData\Roaming\Bad App\payload.dll`
	targets := []persistenceTarget{{path: exe, kind: "exe"}, {path: dll, kind: "dll"}}
	for _, tc := range []struct {
		command string
		want    string
	}{
		{`"C:\Users\Alice\AppData\Roaming\Bad App\bad.exe" --update`, exe},
		{`rundll32.exe "C:\Users\Alice\AppData\Roaming\Bad App\payload.dll",Entry`, dll},
		{`"C:\Users\Alice\AppData\Roaming\Bad App\benign.exe" --update`, ""},
		{`"C:\Users\Alice\AppData\Roaming\Bad App\bad.exe.backup"`, ""},
		{`notepad.exe "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, ""},
		{`cmd.exe /c echo "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, ""},
		{`cmd.exe /c "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe},
		{`powershell.exe -Command Write-Host "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, ""},
		{`powershell.exe -File "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe},
	} {
		got, ok := exactTarget(tc.command, targets)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("exactTarget(%q) = %q, %v; want %q", tc.command, got, ok, tc.want)
		}
	}
}

func TestTaskTargetUTF16(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Task")
	command := `C:\Users\Alice\AppData\Roaming\Bad App\bad.exe`
	xmlText := `<?xml version="1.0" encoding="UTF-16"?><Task><Actions><Exec><Command>` + command + `</Command><Arguments>--update</Arguments></Exec></Actions></Task>`
	words := utf16.Encode([]rune(xmlText))
	b := []byte{0xff, 0xfe}
	for _, w := range words {
		b = append(b, byte(w), byte(w>>8))
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	got, _, err := taskTarget(path, []persistenceTarget{{path: command, kind: "exe"}})
	if err != nil || !strings.EqualFold(got, command) {
		t.Fatalf("taskTarget = %q, %v", got, err)
	}
}

func TestTaskTargetWrappedActions(t *testing.T) {
	t.Setenv("BLOCK_ADS_TEST_APPDATA", `C:\Users\Alice\AppData\Roaming`)
	target := `C:\Users\Alice\AppData\Roaming\Bad App\bad.exe`
	targets := []persistenceTarget{{path: target, kind: "exe"}}
	for _, tc := range []struct {
		name, command, arguments string
		want                     bool
	}{
		{"direct with arguments", target, `--update --silent`, true},
		{"cmd wrapper", `C:\Windows\System32\cmd.exe`, `/c "` + target + `" --update`, true},
		{"powershell file", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `-NoProfile -File "` + target + `" --update`, true},
		{"environment variable", `%BLOCK_ADS_TEST_APPDATA%\Bad App\bad.exe`, `--update`, true},
		{"path only in unrelated argument", `C:\Windows\System32\notepad.exe`, `"` + target + `"`, false},
		{"cmd echo", `C:\Windows\System32\cmd.exe`, `/c echo "` + target + `"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "Task")
			xmlText := fmt.Sprintf(`<Task><Actions><Exec><Command>%s</Command><Arguments>%s</Arguments></Exec></Actions></Task>`, tc.command, tc.arguments)
			if err := os.WriteFile(path, []byte(xmlText), 0600); err != nil {
				t.Fatal(err)
			}
			got, _, err := taskTarget(path, targets)
			if err != nil || (got != "") != tc.want {
				t.Fatalf("taskTarget = %q, %v; want match %v", got, err, tc.want)
			}
		})
	}
}

func TestShortcutMetadataAndWrapper(t *testing.T) {
	target := `C:\Users\Alice\AppData\Roaming\Bad App\bad.exe`
	link, err := parseShortcutDetails([]byte(`{"target":"C:\\Windows\\System32\\cmd.exe","arguments":"/c \"C:\\Users\\Alice\\AppData\\Roaming\\Bad App\\bad.exe\" --update","working_directory":"C:\\Users\\Alice\\AppData\\Roaming\\Bad App"}`))
	if err != nil {
		t.Fatal(err)
	}
	if link.WorkingDirectory == "" || link.Arguments == "" {
		t.Fatalf("shortcut metadata incomplete: %+v", link)
	}
	if got, ok := shortcutMatchedTarget(link, []persistenceTarget{{path: target, kind: "exe"}}); !ok || got != target {
		t.Fatalf("shortcut target = %q, %v", got, ok)
	}
}

func TestContainRefusesMissingOrRecycledIdentity(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	id, err := FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	pid := uint32(os.Getpid())
	if ok, err := contain(HitEvent{PID: pid, Image: path, FileID: id}); ok || err == nil {
		t.Fatalf("missing creation time accepted: %v, %v", ok, err)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	if ok, err := contain(HitEvent{PID: pid, Image: path, FileID: id, CreatedHigh: created.HighDateTime, CreatedLow: created.LowDateTime + 1}); ok || err == nil {
		t.Fatalf("recycled PID accepted: %v, %v", ok, err)
	}
	if ok, err := contain(HitEvent{PID: pid, Image: path + ".other", FileID: id, CreatedHigh: created.HighDateTime, CreatedLow: created.LowDateTime}); ok || err == nil {
		t.Fatalf("changed image path accepted: %v, %v", ok, err)
	}
	if ok, err := contain(HitEvent{PID: pid, Image: path, FileID: id + "-other", CreatedHigh: created.HighDateTime, CreatedLow: created.LowDateTime}); ok || err == nil {
		t.Fatalf("changed file identity accepted: %v, %v", ok, err)
	}
}

func TestPendingCaseIsNotCompleted(t *testing.T) {
	base := Case{ProcessExit: "verified", Artifacts: []Artifact{{Status: "quarantined"}}}
	if got := caseStatus(base); got != "pending_verification" {
		t.Fatal(got)
	}
	base.Artifacts[0].Status = "pending"
	if got := caseStatus(base); got != "pending" {
		t.Fatal(got)
	}
	base.Artifacts[0].Status = "quarantined"
	base.Persistence = []PersistenceItem{{Type: "service", Status: "experimental_review"}}
	if got := caseStatus(base); got != "review" {
		t.Fatal(got)
	}
}

func TestServiceDeletionIsDisabled(t *testing.T) {
	item := PersistenceItem{Type: "service", Name: "Example", Target: `C:\Users\Alice\AppData\Roaming\Bad\bad.exe`, Confidence: "HIGH"}
	if err := removePersistence(&item); err == nil {
		t.Fatal("service deletion must require a future explicit design")
	}
}

func TestQuarantineAndRestoreCase(t *testing.T) {
	root := t.TempDir()
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	original := filepath.Join(appData, "BadApp", "bad.exe")
	if err := os.MkdirAll(filepath.Dir(original), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("sample executable content")
	if err := os.WriteFile(original, content, 0600); err != nil {
		t.Fatal(err)
	}
	hash, err := fileSHA256(original)
	if err != nil {
		t.Fatal(err)
	}
	fileID, err := FileID(original)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{root: root}
	hit := HitEvent{PID: 1234, Image: original, FileID: fileID, RuleKind: "folder", Rule: "BadApp"}
	a := Artifact{Path: original, Kind: "exe", FileID: fileID, SHA256: hash, Confidence: "HIGH"}
	caseID := newCaseID(hit)
	quarantined, err := m.quarantine(caseID, hit, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(original); !os.IsNotExist(err) {
		t.Fatalf("original remains after quarantine: %v", err)
	}
	a.QuarantinePath, a.Status = quarantined, "quarantined"
	if !artifactQuarantined([]Artifact{a}, original) {
		t.Fatal("verified quarantine was not recognized")
	}
	if _, err := m.quarantine(newCaseID(hit), hit, a); err == nil {
		t.Fatal("second case must not claim the already removed original")
	}
	if err := m.saveCase(Case{ID: caseID, Hit: hit, Artifacts: []Artifact{a}}); err != nil {
		t.Fatal(err)
	}
	if err := RestoreCase(root, caseID); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(original)
	if err != nil || string(got) != string(content) {
		t.Fatalf("restored file = %q, %v", got, err)
	}
}

func TestLockedArtifactRemainsPending(t *testing.T) {
	root := t.TempDir()
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	path := filepath.Join(appData, "BadApp", "locked.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("locked-content"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	m := &Manager{root: root}
	hit := HitEvent{PID: 42, Image: path, FileID: id, RuleKind: "folder", Rule: "BadApp"}
	a := Artifact{Path: path, Kind: "exe", FileID: id, SHA256: hash, Confidence: "HIGH", Status: "pending"}
	if _, err := m.quarantine(newCaseID(hit), hit, a); err == nil {
		t.Fatal("locked file was reported as quarantined")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("locked original disappeared: %v", err)
	}
	if got := caseStatus(Case{ProcessExit: "verified", Artifacts: []Artifact{a}}); got != "pending" {
		t.Fatalf("case status = %q", got)
	}
}

func TestShortcutRestorePreservesOriginalBytes(t *testing.T) {
	root := t.TempDir()
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	linkPath := filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup`, "Example.lnk")
	backup := filepath.Join(root, "eradication", "backups", "case-1", "shortcut.bin")
	if err := os.MkdirAll(filepath.Dir(linkPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(backup), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte{0x4c, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}
	if err := os.WriteFile(backup, data, 0600); err != nil {
		t.Fatal(err)
	}
	item := PersistenceItem{Type: "startup_link", Location: linkPath, BackupPath: backup}
	if err := restorePersistence(root, "case-1", item); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(linkPath)
	if err != nil || string(got) != string(data) {
		t.Fatalf("shortcut bytes changed: %x, %v", got, err)
	}
}

func TestChangedFileIdentityIsNotQuarantined(t *testing.T) {
	root := t.TempDir()
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	path := filepath.Join(appData, "BadApp", "bad.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	oldID, err := FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	oldHash, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	items := collectEvidence(HitEvent{Image: path, FileID: oldID, RuleKind: "folder", Rule: "BadApp"}, nil)
	if len(items) != 1 || items[0].Confidence == "HIGH" {
		t.Fatalf("replacement received automatic-delete confidence: %+v", items)
	}
	if artifactStillMatches([]Artifact{{Path: path, FileID: oldID, SHA256: oldHash, Confidence: "HIGH"}}, path) {
		t.Fatal("replaced artifact still authorized persistence deletion")
	}
}
