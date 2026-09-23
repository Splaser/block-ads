//go:build windows

package tests

import (
	"block-ads/eradication"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestPersistenceCommandMatching(t *testing.T) {
	exe := `C:\Users\Alice\AppData\Roaming\Bad App\bad.exe`
	dll := `C:\Users\Alice\AppData\Roaming\Bad App\payload.dll`
	for _, tc := range []struct {
		command, target, kind string
		want                  bool
	}{
		{`"C:\Users\Alice\AppData\Roaming\Bad App\bad.exe" --update`, exe, "exe", true},
		{`rundll32.exe "C:\Users\Alice\AppData\Roaming\Bad App\payload.dll",Entry`, dll, "dll", true},
		{`notepad.exe "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe, "exe", false},
		{`cmd.exe /c echo "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe, "exe", false},
		{`cmd.exe /c "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe, "exe", true},
		{`powershell.exe -Command Write-Host "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe, "exe", false},
		{`powershell.exe -File "C:\Users\Alice\AppData\Roaming\Bad App\bad.exe"`, exe, "exe", true},
		{`"C:\Users\Alice\AppData\Roaming\Bad App\bad.exe.backup"`, exe, "exe", false},
	} {
		if got := eradication.MatchPersistenceCommand(tc.command, tc.target, tc.kind); got != tc.want {
			t.Errorf("match %q = %v, want %v", tc.command, got, tc.want)
		}
	}
}

func TestTaskActionMatchingAndUTF16(t *testing.T) {
	t.Setenv("BLOCK_ADS_TEST_APPDATA", `C:\Users\Alice\AppData\Roaming`)
	target := `C:\Users\Alice\AppData\Roaming\Bad App\bad.exe`
	for _, tc := range []struct {
		command, arguments string
		want               bool
	}{
		{target, `--update`, true},
		{`C:\Windows\System32\cmd.exe`, `/c "` + target + `" --update`, true},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `-NoProfile -File "` + target + `"`, true},
		{`%BLOCK_ADS_TEST_APPDATA%\Bad App\bad.exe`, `--update`, true},
		{`C:\Windows\System32\cmd.exe`, `/c echo "` + target + `"`, false},
	} {
		path := filepath.Join(testRoot(t), "Task")
		definition := fmt.Sprintf(`<Task><Actions><Exec><Command>%s</Command><Arguments>%s</Arguments></Exec></Actions></Task>`, tc.command, tc.arguments)
		words := utf16.Encode([]rune(`<?xml version="1.0" encoding="UTF-16"?>` + definition))
		b := []byte{0xff, 0xfe}
		for _, word := range words {
			b = append(b, byte(word), byte(word>>8))
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := eradication.MatchTaskFile(path, target, "exe")
		if err != nil || got != tc.want {
			t.Fatalf("task match for %q %q = %v, %v; want %v", tc.command, tc.arguments, got, err, tc.want)
		}
	}
}

func TestQuarantineRestoreRoundTrip(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	t.Setenv("USERPROFILE", root)
	path := filepath.Join(appData, "Bad", "sample.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("safe test payload")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(eradication.HitEvent{ID: "round-trip", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || len(cases[0].Artifacts) == 0 || cases[0].Artifacts[0].Status != "quarantined" {
		t.Fatalf("quarantine failed: %+v", cases)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("original still present: %v", err)
	}
	if err := eradication.RestoreCase(root, cases[0].ID); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(content) {
		t.Fatalf("restore changed content: %q, %v", got, err)
	}
	if err := eradication.RestoreCase(root, cases[0].ID); err != nil {
		t.Fatalf("repeat restore failed: %v", err)
	}
	if after := readCases(t, root)[0]; after.Status != "restored" {
		t.Fatalf("restore status = %q", after.Status)
	}
}

func TestFileIdentityReplacementIsReview(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	path := filepath.Join(appData, "Bad", "sample.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(eradication.HitEvent{ID: "old-file", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || len(cases[0].Artifacts) == 0 || cases[0].Artifacts[0].Confidence == "HIGH" {
		t.Fatalf("replacement authorized: %+v", cases)
	}
	if got, err := os.ReadFile(path); err != nil || !strings.EqualFold(string(got), "replacement") {
		t.Fatalf("replacement changed: %q, %v", got, err)
	}
}

func TestLockedArtifactStaysPending(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	path := filepath.Join(appData, "Bad", "locked.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("locked"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := eradication.FileID(path)
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	manager := eradication.NewManager(root, 1, 1)
	manager.Submit(eradication.HitEvent{ID: "locked", PID: 0xfffffffe, CreatedLow: 1, Image: path, FileID: id, RuleKind: "folder", Rule: "Bad"})
	manager.Close()
	cases := readCases(t, root)
	if len(cases) != 1 || cases[0].Status != "pending" || len(cases[0].Artifacts) == 0 || cases[0].Artifacts[0].Status != "pending" {
		t.Fatalf("locked file counted as success: %+v", cases)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("locked original missing: %v", err)
	}
}

func TestShortcutBackupRestoresExactBytes(t *testing.T) {
	root := testRoot(t)
	appData := filepath.Join(root, "AppData", "Roaming")
	t.Setenv("APPDATA", appData)
	link := filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup`, "sample.lnk")
	backup := filepath.Join(root, "eradication", "backups", "shortcut-case", "link.bin")
	if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(backup), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte{0x4c, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03}
	if err := os.WriteFile(backup, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := eradication.Case{ID: "shortcut-case", Persistence: []eradication.PersistenceItem{{Type: "startup_link", Location: link, BackupPath: backup, Status: "removed"}}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	casePath := filepath.Join(root, "eradication", "cases", c.ID+".json")
	if err := os.MkdirAll(filepath.Dir(casePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(casePath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := eradication.RestoreCase(root, c.ID); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(link)
	if err != nil || string(got) != string(data) {
		t.Fatalf("shortcut bytes changed: %x, %v", got, err)
	}
}
