//go:build windows

package eradication

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// OperationEntry records an action independently of the final case status.
// Intent is durable before the external change; result is a separate file so
// an interrupted action remains visible after a crash.
type OperationEntry struct {
	ID                  string    `json:"id"`
	CaseID              string    `json:"case_id"`
	OwnerCaseID         string    `json:"owner_case_id,omitempty"`
	ArtifactID          string    `json:"artifact_id,omitempty"`
	PersistenceID       string    `json:"persistence_id,omitempty"`
	PersistenceType     string    `json:"persistence_type,omitempty"`
	PersistenceLocation string    `json:"persistence_location,omitempty"`
	BackupPath          string    `json:"backup_path,omitempty"`
	ExpectedValue       string    `json:"expected_value,omitempty"`
	ValueType           uint32    `json:"value_type,omitempty"`
	ExpectedHash        string    `json:"expected_sha256,omitempty"`
	PreviousHash        string    `json:"previous_sha256,omitempty"`
	ExpectedFileID      string    `json:"expected_file_id,omitempty"`
	QuarantinePath      string    `json:"quarantine_path,omitempty"`
	RelatedPath         string    `json:"related_path,omitempty"`
	Action              string    `json:"action"`
	Target              string    `json:"target"`
	Precondition        string    `json:"precondition,omitempty"`
	Phase               string    `json:"phase"`
	Error               string    `json:"error,omitempty"`
	At                  time.Time `json:"at"`
}

// OperationObserver receives a durable intent, a finished external action,
// and a durable result in order. It is useful for progress reporting and
// controlled crash testing. It must not mutate the entry.
type OperationObserver func(OperationEntry, string)

func journalPath(root string, entry OperationEntry) string {
	return filepath.Join(root, "eradication", "journal", entry.CaseID, entry.ID+"-"+entry.Phase+".json")
}

func writeOperation(root string, entry OperationEntry) error {
	if entry.CaseID == "" || filepath.Base(entry.CaseID) != entry.CaseID || strings.ContainsAny(entry.CaseID, `/\:`) {
		return fmt.Errorf("invalid operation case ID")
	}
	if entry.ID == "" || entry.Phase != "intent" && entry.Phase != "committed" && entry.Phase != "failed" {
		return fmt.Errorf("invalid operation entry")
	}
	path := journalPath(root, entry)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, b)
}

func runJournaled(root string, entry OperationEntry, observer OperationObserver, perform func() error) error {
	entry.ID = newCaseID(HitEvent{})
	entry.Phase = "intent"
	entry.At = time.Now()
	if err := writeOperation(root, entry); err != nil {
		return fmt.Errorf("write %s intent: %w", entry.Action, err)
	}
	if observer != nil {
		observer(entry, "after_intent")
	}
	actionErr := perform()
	if observer != nil {
		observer(entry, "after_action")
	}
	entry.At = time.Now()
	if actionErr == nil {
		entry.Phase = "committed"
	} else {
		entry.Phase = "failed"
		entry.Error = actionErr.Error()
	}
	if err := writeOperation(root, entry); err != nil {
		return errors.Join(actionErr, fmt.Errorf("write %s result: %w", entry.Action, err))
	}
	if observer != nil {
		observer(entry, "after_result")
	}
	return actionErr
}

// UnfinishedOperations reports intents without a committed or failed result.
// The caller must inspect external state before retrying or rolling back.
func UnfinishedOperations(root string) ([]OperationEntry, error) {
	dir := filepath.Join(root, "eradication", "journal")
	intents := map[string]OperationEntry{}
	results := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var operation OperationEntry
		if err := json.Unmarshal(b, &operation); err != nil {
			return fmt.Errorf("read operation %s: %w", path, err)
		}
		key := operation.CaseID + "\x00" + operation.ID
		switch operation.Phase {
		case "intent":
			intents[key] = operation
		case "committed", "failed":
			results[key] = true
		default:
			return fmt.Errorf("invalid operation phase in %s", path)
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	unfinished := []OperationEntry{}
	for key, entry := range intents {
		if !results[key] {
			unfinished = append(unfinished, entry)
		}
	}
	sort.Slice(unfinished, func(i, j int) bool {
		if unfinished[i].At.Equal(unfinished[j].At) {
			return unfinished[i].ID < unfinished[j].ID
		}
		return unfinished[i].At.Before(unfinished[j].At)
	})
	return unfinished, nil
}
