// Package host: checkpoints and rewind.
//
// A checkpoint is a named snapshot of the agent's working directory plus
// the transcript position when it was taken. Rewind restores the files to
// that snapshot so handing control to an expert is safe to try: anything
// they break can be undone.
//
// Two snapshot strategies:
//   - git workdirs: `git stash create` mints a commit object of the tracked
//     changes without touching the working tree or index (stash create
//     ignores untracked files, so those are copied to a temp sidecar dir).
//     Restore checks the tracked files out of that commit, `git clean -fd`s
//     anything created after the checkpoint, then brings the sidecar
//     untracked files back. Ignored files are left alone. Before every
//     restore the current state is auto-checkpointed, so a rewind is
//     itself reversible.
//   - plain directories: the tree is copied to a snapshot dir outside the
//     workdir; restore copies it back and deletes files that did not
//     exist at snapshot time (from a manifest).
//
// Checkpoints are session-scoped: they live in memory and in temp dirs,
// and die with the host.
package host

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Checkpoint is one named snapshot.
type Checkpoint struct {
	Label           string
	CreatedAt       time.Time
	TranscriptBytes int64  // PTY output bytes seen when taken
	Kind            string // "git" or "files"
	Ref             string // git commit hash, or snapshot dir path
	manifest        []string
	untrackedDir    string // git kind: sidecar dir with untracked files
	baseHead        string // git kind: HEAD at checkpoint time
}

var labelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// sanitizeLabel rejects empty labels and path trickery.
func sanitizeLabel(label string) (string, error) {
	if !labelRe.MatchString(label) {
		return "", fmt.Errorf("host: bad checkpoint label %q (use letters, digits, - _)", label)
	}
	return label, nil
}

// CheckpointManager snapshots and restores one working directory.
type CheckpointManager struct {
	workDir string
	useGit  bool

	mu      sync.Mutex
	byLabel map[string]*Checkpoint
}

// NewCheckpointManager binds a manager to workDir. An empty workDir means
// the current process directory.
func NewCheckpointManager(workDir string) (*CheckpointManager, error) {
	if workDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("host: workdir: %w", err)
		}
		workDir = wd
	}
	abs, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("host: workdir: %w", err)
	}
	m := &CheckpointManager{workDir: abs, byLabel: make(map[string]*Checkpoint)}
	m.useGit = isGitRepo(abs)
	return m, nil
}

// WorkDir reports the snapshotted directory.
func (m *CheckpointManager) WorkDir() string { return m.workDir }

// UsesGit reports whether snapshots go through git.
func (m *CheckpointManager) UsesGit() bool { return m.useGit }

func isGitRepo(dir string) bool {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

func (m *CheckpointManager) git(args ...string) (string, error) {
	cmd := exec.Command("git", "-C", m.workDir)
	cmd.Args = append(cmd.Args, args...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// gitUntracked lists files git sees as untracked and not ignored.
func (m *CheckpointManager) gitUntracked() ([]string, error) {
	out, err := m.git("ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(out, "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

// Create snapshots the workdir under label, replacing any checkpoint that
// already has that label.
func (m *CheckpointManager) Create(label string, transcriptBytes int64) (*Checkpoint, error) {
	label, err := sanitizeLabel(label)
	if err != nil {
		return nil, err
	}
	cp := &Checkpoint{
		Label:           label,
		CreatedAt:       time.Now(),
		TranscriptBytes: transcriptBytes,
	}
	if m.useGit {
		// stash create mints a commit of the tracked changes without
		// touching the worktree or index. Note: it ignores untracked
		// files even with -u, so those get a file sidecar below.
		hash, err := m.git("stash", "create")
		if err != nil {
			return nil, fmt.Errorf("host: checkpoint: %w", err)
		}
		cp.Kind = "git"
		cp.Ref = hash // empty when no tracked changes: fall back to base HEAD
		if head, err := m.git("rev-parse", "HEAD"); err == nil {
			cp.baseHead = head
		}
		untracked, err := m.gitUntracked()
		if err != nil {
			return nil, fmt.Errorf("host: checkpoint: %w", err)
		}
		if len(untracked) > 0 {
			dir, err := os.MkdirTemp("", "backseat-checkpoint-untracked-*")
			if err != nil {
				return nil, err
			}
			for _, rel := range untracked {
				dst := filepath.Join(dir, rel)
				if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
					os.RemoveAll(dir)
					return nil, err
				}
				if err := copyFile(filepath.Join(m.workDir, rel), dst); err != nil {
					os.RemoveAll(dir)
					return nil, err
				}
			}
			cp.untrackedDir = dir
		}
	} else {
		cp.Kind = "files"
		dir, manifest, err := snapshotTree(m.workDir)
		if err != nil {
			return nil, fmt.Errorf("host: checkpoint: %w", err)
		}
		cp.Ref = dir
		cp.manifest = manifest
	}
	m.mu.Lock()
	m.byLabel[label] = cp
	m.mu.Unlock()
	return cp, nil
}

// Get returns the checkpoint with the label, if any.
func (m *CheckpointManager) Get(label string) (*Checkpoint, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp, ok := m.byLabel[label]
	return cp, ok
}

// List returns all checkpoints oldest first.
func (m *CheckpointManager) List() []*Checkpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Checkpoint, 0, len(m.byLabel))
	for _, cp := range m.byLabel {
		out = append(out, cp)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].CreatedAt.Before(out[i].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Restore rewinds the workdir to the named checkpoint. It first
// auto-checkpoints the current state so the rewind itself can be undone.
func (m *CheckpointManager) Restore(label string) (*Checkpoint, error) {
	m.mu.Lock()
	cp, ok := m.byLabel[label]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("host: no checkpoint %q", label)
	}
	autoLabel := fmt.Sprintf("auto-before-restore-%d", time.Now().Unix())
	// Best effort: never let the safety net fail the rewind.
	if _, err := m.Create(autoLabel, cp.TranscriptBytes); err != nil {
		return nil, fmt.Errorf("host: pre-restore snapshot failed, refusing rewind: %w", err)
	}
	if err := m.restore(cp); err != nil {
		return nil, err
	}
	return cp, nil
}

func (m *CheckpointManager) restore(cp *Checkpoint) error {
	if cp.Kind == "git" {
		return m.restoreGit(cp)
	}
	return m.restoreFiles(cp)
}

func (m *CheckpointManager) restoreGit(cp *Checkpoint) error {
	// Tracked files back to the snapshot. The stash commit holds the
	// checkpoint-time tracked state; when the tree was clean at
	// checkpoint time the stash is empty and we fall back to the
	// recorded HEAD.
	ref := cp.Ref
	if ref == "" {
		ref = cp.baseHead
	}
	if ref != "" {
		if _, err := m.git("checkout", ref, "--", "."); err != nil {
			return fmt.Errorf("host: rewind tracked files: %w", err)
		}
	}
	// Anything created after the checkpoint goes away. Ignored files
	// (build artifacts, .env) are left alone by default.
	if _, err := m.git("clean", "-fd"); err != nil {
		return fmt.Errorf("host: rewind new files: %w", err)
	}
	// Bring back the untracked files that existed at checkpoint time.
	if cp.untrackedDir != "" {
		err := filepath.Walk(cp.untrackedDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel, err := filepath.Rel(cp.untrackedDir, path)
			if err != nil {
				return err
			}
			dst := filepath.Join(m.workDir, rel)
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			return copyFile(path, dst)
		})
		if err != nil {
			return fmt.Errorf("host: rewind untracked files: %w", err)
		}
	}
	return nil
}

func (m *CheckpointManager) restoreFiles(cp *Checkpoint) error {
	if err := copyTree(cp.Ref, m.workDir); err != nil {
		return fmt.Errorf("host: rewind files: %w", err)
	}
	want := make(map[string]bool, len(cp.manifest))
	for _, rel := range cp.manifest {
		want[rel] = true
	}
	// Delete files created after the checkpoint.
	return filepath.Walk(m.workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(m.workDir, path)
		if err != nil {
			return nil
		}
		if !want[rel] {
			if rmErr := os.Remove(path); rmErr != nil {
				return rmErr
			}
		}
		return nil
	})
}

// snapshotTree copies dir into a fresh temp dir and returns the dir plus a
// manifest of relative file paths.
func snapshotTree(dir string) (string, []string, error) {
	dst, err := os.MkdirTemp("", "backseat-checkpoint-*")
	if err != nil {
		return "", nil, err
	}
	if err := copyTree(dir, dst); err != nil {
		os.RemoveAll(dst)
		return "", nil, err
	}
	var manifest []string
	err = filepath.Walk(dst, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dst, path)
		if err != nil {
			return nil
		}
		manifest = append(manifest, rel)
		return nil
	})
	if err != nil {
		os.RemoveAll(dst)
		return "", nil, err
	}
	return dst, manifest, nil
}

// copyTree copies the contents of src into dst (both must exist).
func copyTree(src, dst string) error {
	// -a preserves modes and symlinks; trailing /. copies contents.
	cmd := exec.Command("cp", "-a", src+string(os.PathSeparator)+".", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cp -a: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// copyFile copies one file, preserving its mode.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
