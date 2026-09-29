//go:build windows

package eradication

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		case "record_ownership", "restore_ownership":
			finding.Disposition, finding.Evidence = inspectOwnershipOperation(root, operation)
		}
		findings = append(findings, finding)
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
