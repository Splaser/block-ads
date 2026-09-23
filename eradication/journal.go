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
	ID            string    `json:"id"`
	CaseID        string    `json:"case_id"`
	ArtifactID    string    `json:"artifact_id,omitempty"`
	PersistenceID string    `json:"persistence_id,omitempty"`
	Action        string    `json:"action"`
	Target        string    `json:"target"`
	Precondition  string    `json:"precondition,omitempty"`
	Phase         string    `json:"phase"`
	Error         string    `json:"error,omitempty"`
	At            time.Time `json:"at"`
}

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

func runJournaled(root, caseID, artifactID, persistenceID, action, target, precondition string, perform func() error) error {
	entry := OperationEntry{
		ID: newCaseID(HitEvent{}), CaseID: caseID,
		ArtifactID: artifactID, PersistenceID: persistenceID,
		Action: action, Target: target, Precondition: precondition,
		Phase: "intent", At: time.Now(),
	}
	if err := writeOperation(root, entry); err != nil {
		return fmt.Errorf("write %s intent: %w", action, err)
	}
	actionErr := perform()
	entry.At = time.Now()
	if actionErr == nil {
		entry.Phase = "committed"
	} else {
		entry.Phase = "failed"
		entry.Error = actionErr.Error()
	}
	if err := writeOperation(root, entry); err != nil {
		return errors.Join(actionErr, fmt.Errorf("write %s result: %w", action, err))
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
