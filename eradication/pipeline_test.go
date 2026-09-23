//go:build windows

package eradication

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"
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
