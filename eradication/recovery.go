//go:build windows

package eradication

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RecoveryFinding is a read-only interpretation of an operation whose result
// record is missing. Observing the expected bytes does not prove which process
// placed them there, so this audit never commits or repeats an action.
type RecoveryFinding struct {
	Operation   OperationEntry `json:"operation"`
	Disposition string         `json:"disposition"`
	Evidence    string         `json:"evidence"`
}

func InspectRecovery(root string) ([]RecoveryFinding, error) {
	unfinished, err := UnfinishedOperations(root)
	if err != nil {
		return nil, err
	}
	findings := make([]RecoveryFinding, 0, len(unfinished))
	for _, operation := range unfinished {
		finding := RecoveryFinding{Operation: operation, Disposition: "manual_review", Evidence: "external state has not been verified"}
		switch operation.Action {
		case "delete_original", "restore_file":
			finding.Disposition, finding.Evidence = inspectFileOperation(root, operation)
		case "quarantine_copy", "quarantine_hash_verify", "quarantine_publish":
			finding.Disposition, finding.Evidence = inspectQuarantinePreparation(root, operation)
		case "record_ownership", "restore_ownership":
			finding.Disposition, finding.Evidence = inspectOwnershipOperation(root, operation)
		case "remove_persistence":
			finding.Disposition, finding.Evidence = inspectPersistenceRemoval(root, operation)
		}
		findings = append(findings, finding)
	}
	caseFindings, err := inspectCaseCommitGaps(root, findings)
	if err != nil {
		return nil, err
	}
	findings = append(findings, caseFindings...)
	return findings, nil
}

func inspectPersistenceRemoval(root string, operation OperationEntry) (string, string) {
	if operation.PersistenceID != PersistenceID(operation.PersistenceType, operation.PersistenceLocation, operation.Target) || operation.RelatedPath == "" {
		return "manual_review", "intent lacks persistence identity or artifact association"
	}
	switch operation.PersistenceType {
	case "startup_link", "task":
		if operation.ExpectedHash == "" || !backupWithin(root, operation.CaseID, operation.BackupPath) {
			return "manual_review", "persistence backup is missing or outside the case"
		}
		if hash, err := fileSHA256(operation.BackupPath); err != nil || hash != operation.ExpectedHash {
			return "conflict", fmt.Sprintf("persistence backup hash differs from intent: %v", err)
		}
		info, err := os.Lstat(operation.PersistenceLocation)
		if errors.Is(err, os.ErrNotExist) {
			return "observed_uncommitted", "persistence entry is absent but deletion result was not committed"
		}
		if err != nil || !info.Mode().IsRegular() {
			return "conflict", fmt.Sprintf("persistence entry is unreadable or not regular: %v", err)
		}
		if hash, err := fileSHA256(operation.PersistenceLocation); err != nil || hash != operation.ExpectedHash {
			return "conflict", fmt.Sprintf("persistence entry differs from its backup: %v", err)
		}
		return "not_observed", "persistence entry still matches its verified backup"
	case "registry_run":
		for _, loc := range runLocations {
			if locationName(loc) != operation.PersistenceLocation {
				continue
			}
			key, err := registry.OpenKey(loc.root, loc.name, registry.QUERY_VALUE|loc.view)
			if errors.Is(err, registry.ErrNotExist) {
				return "observed_uncommitted", "Run location is absent"
			}
			if err != nil {
				return "conflict", fmt.Sprintf("Run location cannot be read: %v", err)
			}
			value, valueType, err := key.GetStringValue(operation.Target)
			key.Close()
			if errors.Is(err, registry.ErrNotExist) {
				return "observed_uncommitted", "Run value is absent but deletion result was not committed"
			}
			if err != nil || value != operation.ExpectedValue || valueType != operation.ValueType {
				return "conflict", fmt.Sprintf("Run value differs from intent: %v", err)
			}
			return "not_observed", "Run value still matches the intent"
		}
		return "manual_review", "Run location is not recognized"
	}
	return "manual_review", "persistence type has no read-only recovery check"
}

func inspectQuarantinePreparation(root string, operation OperationEntry) (string, string) {
	if operation.ExpectedHash == "" || operation.ExpectedFileID == "" || operation.QuarantinePath == "" || operation.ArtifactID != ArtifactID(operation.Target, operation.ExpectedFileID, operation.ExpectedHash) {
		return "manual_review", "intent lacks a complete artifact identity"
	}
	if !beneath(operation.QuarantinePath, filepath.Join(root, "eradication", "quarantine")) {
		return "conflict", "quarantine path is outside the case store"
	}
	info, err := os.Lstat(operation.QuarantinePath)
	if errors.Is(err, os.ErrNotExist) {
		if operation.Action == "quarantine_hash_verify" {
			return "conflict", "copy disappeared before hash verification was committed"
		}
		return "not_observed", "quarantine copy or published target is absent"
	}
	if err != nil || !info.Mode().IsRegular() {
		return "conflict", fmt.Sprintf("quarantine path is unreadable or not regular: %v", err)
	}
	hash, err := fileSHA256(operation.QuarantinePath)
	if err != nil || hash != operation.ExpectedHash {
		return "conflict", fmt.Sprintf("quarantine bytes differ from intent: %v", err)
	}
	if operation.Action == "quarantine_hash_verify" {
		return "manual_review", "copy hash matches, but the verification result was not committed"
	}
	return "observed_uncommitted", "quarantine bytes match, but the operation result was not committed"
}

func inspectCaseCommitGaps(root string, existing []RecoveryFinding) ([]RecoveryFinding, error) {
	casesDir := filepath.Join(root, "eradication", "cases")
	entries, err := os.ReadDir(casesDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, finding := range existing {
		seen[finding.Operation.CaseID+"\x00"+strings.ToLower(filepath.Clean(finding.Operation.Target))] = true
	}
	findings := []RecoveryFinding{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "-plan.json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), "-plan.json")
		if _, err := os.Stat(filepath.Join(casesDir, id+".json")); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		b, err := os.ReadFile(filepath.Join(casesDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var plan Case
		if err := json.Unmarshal(b, &plan); err != nil || plan.ID != id {
			return nil, fmt.Errorf("invalid recovery case plan %s: %v", id, err)
		}
		for _, artifact := range plan.Artifacts {
			key := id + "\x00" + strings.ToLower(filepath.Clean(artifact.Path))
			if artifact.Path == "" || seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, RecoveryFinding{
				Operation:   OperationEntry{CaseID: id, Action: "case_commit", Target: artifact.Path, ArtifactID: ArtifactID(artifact.Path, artifact.FileID, artifact.SHA256)},
				Disposition: "manual_review", Evidence: "case plan exists but final case is missing; reconcile artifact and journal before further remediation",
			})
		}
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), "-plan.json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(casesDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var c Case
		if err := json.Unmarshal(b, &c); err != nil || c.ID+".json" != entry.Name() {
			return nil, fmt.Errorf("invalid recovery case %s: %v", entry.Name(), err)
		}
		if c.Status == "restored" || c.Status == "released" {
			continue
		}
		journalDir := filepath.Join(root, "eradication", "journal", c.ID)
		operations, err := os.ReadDir(journalDir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, file := range operations {
			if file.IsDir() || !strings.HasSuffix(file.Name(), "-committed.json") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(journalDir, file.Name()))
			if err != nil {
				return nil, err
			}
			var operation OperationEntry
			if err := json.Unmarshal(b, &operation); err != nil {
				return nil, err
			}
			if operation.Action != "restore_file" || operation.CaseID != c.ID {
				continue
			}
			for _, artifact := range c.Artifacts {
				key := c.ID + "\x00" + strings.ToLower(filepath.Clean(operation.Target))
				if samePath(artifact.Path, operation.Target) && artifact.Status != "restored" && !seen[key] {
					seen[key] = true
					findings = append(findings, RecoveryFinding{Operation: operation, Disposition: "manual_review", Evidence: "restore_file committed but case artifact state was not committed"})
				}
			}
		}
	}
	return findings, nil
}

func inspectFileOperation(root string, operation OperationEntry) (string, string) {
	if operation.ExpectedHash == "" || operation.ExpectedFileID == "" || operation.QuarantinePath == "" || operation.ArtifactID != ArtifactID(operation.Target, operation.ExpectedFileID, operation.ExpectedHash) {
		return "manual_review", "intent lacks a complete artifact identity"
	}
	quarantineRoot := filepath.Join(root, "eradication", "quarantine")
	if !beneath(operation.QuarantinePath, quarantineRoot) {
		return "conflict", "quarantine path is outside the case store"
	}
	if info, err := os.Lstat(operation.QuarantinePath); err != nil || !info.Mode().IsRegular() {
		return "conflict", fmt.Sprintf("quarantine copy missing or not regular: %v", err)
	}
	if hash, err := fileSHA256(operation.QuarantinePath); err != nil || hash != operation.ExpectedHash {
		return "conflict", fmt.Sprintf("quarantine copy hash mismatch: %v", err)
	}
	info, err := os.Lstat(operation.Target)
	if errors.Is(err, os.ErrNotExist) {
		if operation.Action == "delete_original" {
			return "observed_uncommitted", "original is absent and quarantine hash matches; ownership and case still need review"
		}
		return "not_observed", "restore target is absent and quarantine hash matches"
	}
	if err != nil || !info.Mode().IsRegular() {
		return "conflict", fmt.Sprintf("original path is unreadable or not regular: %v", err)
	}
	hash, err := fileSHA256(operation.Target)
	if err != nil || hash != operation.ExpectedHash {
		return "conflict", fmt.Sprintf("original path hash differs from intent: %v", err)
	}
	if operation.Action == "restore_file" {
		return "observed_uncommitted", "target hash matches, but its provenance and ownership remain unconfirmed"
	}
	fileID, err := FileID(operation.Target)
	if err != nil || fileID != operation.ExpectedFileID {
		return "conflict", fmt.Sprintf("original file identity differs from intent: %v", err)
	}
	return "not_observed", "original file identity and hash still match the delete intent"
}

func inspectOwnershipOperation(root string, operation OperationEntry) (string, string) {
	if operation.ExpectedHash == "" || operation.ExpectedFileID == "" || operation.ArtifactID != ArtifactID(operation.Target, operation.ExpectedFileID, operation.ExpectedHash) {
		return "manual_review", "intent lacks a complete artifact identity"
	}
	record, err := readArtifactRecord(root, operation.Target, operation.ExpectedFileID)
	if errors.Is(err, os.ErrNotExist) && operation.Action == "record_ownership" {
		return "not_observed", "ownership record is absent"
	}
	if err != nil {
		return "conflict", fmt.Sprintf("ownership record unavailable: %v", err)
	}
	if record.ID != operation.ArtifactID || record.OwnerCaseID != operation.CaseID || record.QuarantinePath != operation.QuarantinePath {
		return "conflict", "ownership record does not match the intent"
	}
	if operation.Action == "record_ownership" && record.Status == "quarantined" || operation.Action == "restore_ownership" && record.Status == "restored" {
		return "observed_uncommitted", "ownership record contains the expected state, but the operation result is missing"
	}
	if operation.Action == "restore_ownership" && record.Status == "quarantined" {
		return "not_observed", "ownership record remains quarantined"
	}
	return "conflict", "ownership record state differs from the intent"
}
