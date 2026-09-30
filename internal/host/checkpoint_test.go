package host

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func gitOK(t *testing.T) bool {
	t.Helper()
	if err := exec.Command("git", "--version").Run(); err != nil {
		t.Skip("git not available")
		return false
	}
	return true
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "test"},
		{"add", "-A"},
		{"commit", "-qm", "base"},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
	}
}

func TestCheckpointFilesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "v1")
	writeFile(t, filepath.Join(dir, "sub", "b.txt"), "v1")

	m, err := NewCheckpointManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.UsesGit() {
		t.Fatal("plain dir detected as git repo")
	}
	if _, err := m.Create("good", 123); err != nil {
		t.Fatal(err)
	}

	// Mutate: change a tracked file, add a new one, delete another.
	writeFile(t, filepath.Join(dir, "a.txt"), "v2")
	writeFile(t, filepath.Join(dir, "new.txt"), "new")
	os.Remove(filepath.Join(dir, "sub", "b.txt"))

	if _, err := m.Restore("good"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "a.txt")); got != "v1" {
		t.Fatalf("a.txt = %q, want v1", got)
	}
	if got := readFile(t, filepath.Join(dir, "sub", "b.txt")); got != "v1" {
		t.Fatalf("b.txt = %q, want v1", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "new.txt")); !os.IsNotExist(err) {
		t.Fatal("new.txt survived the rewind")
	}
	// The pre-restore auto-checkpoint must exist.
	found := false
	for _, cp := range m.List() {
		if len(cp.Label) > 20 && cp.Label[:20] == "auto-before-restore-" {
			found = true
		}
	}
	if !found {
		t.Fatal("no auto-before-restore checkpoint recorded")
	}
}

func TestCheckpointGitRoundTrip(t *testing.T) {
	if !gitOK(t) {
		return
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "v1")
	initGitRepo(t, dir)

	m, err := NewCheckpointManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !m.UsesGit() {
		t.Fatal("git repo not detected")
	}
	// Untracked file present at checkpoint time, plus a tracked change.
	writeFile(t, filepath.Join(dir, "u.txt"), "untracked-v1")
	writeFile(t, filepath.Join(dir, "a.txt"), "v1-dirty")
	cp, err := m.Create("good", 42)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Kind != "git" || cp.Ref == "" {
		t.Fatalf("bad git checkpoint: %+v", cp)
	}
	if cp.TranscriptBytes != 42 {
		t.Fatalf("transcript bytes = %d", cp.TranscriptBytes)
	}

	// Mutate tracked + untracked, add brand-new file.
	writeFile(t, filepath.Join(dir, "a.txt"), "v2")
	writeFile(t, filepath.Join(dir, "u.txt"), "untracked-v2")
	writeFile(t, filepath.Join(dir, "brand-new.txt"), "x")

	if _, err := m.Restore("good"); err != nil {
		t.Fatal(err)
	}
	// The snapshot was taken with a.txt dirty ("v1-dirty"): restore
	// brings back exactly the checkpoint-time state.
	if got := readFile(t, filepath.Join(dir, "a.txt")); got != "v1-dirty" {
		t.Fatalf("a.txt = %q, want v1-dirty", got)
	}
	if got := readFile(t, filepath.Join(dir, "u.txt")); got != "untracked-v1" {
		t.Fatalf("u.txt = %q, want untracked-v1", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "brand-new.txt")); !os.IsNotExist(err) {
		t.Fatal("brand-new.txt survived the rewind")
	}
}

func TestCheckpointGitCleanTree(t *testing.T) {
	if !gitOK(t) {
		return
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "v1")
	initGitRepo(t, dir)
	m, err := NewCheckpointManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := m.Create("clean", 0)
	if err != nil {
		t.Fatal(err)
	}
	// No changes: stash create returns empty, restore is a no-op.
	if cp.Ref != "" {
		t.Fatalf("expected empty ref for clean tree, got %q", cp.Ref)
	}
	if _, err := m.Restore("clean"); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointBadLabel(t *testing.T) {
	m, err := NewCheckpointManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "../evil", "a/b", "x y", "toolong" + string(make([]byte, 100))} {
		if _, err := m.Create(bad, 0); err == nil {
			t.Fatalf("label %q accepted", bad)
		}
	}
	if _, err := m.Restore("nope"); err == nil {
		t.Fatal("restore of missing checkpoint succeeded")
	}
}

func TestCheckpointListOrder(t *testing.T) {
	m, err := NewCheckpointManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"c", "a", "b"} {
		if _, err := m.Create(l, 0); err != nil {
			t.Fatal(err)
		}
	}
	list := m.List()
	if len(list) != 3 || list[0].Label != "c" || list[1].Label != "a" || list[2].Label != "b" {
		t.Fatalf("bad order: %v", list)
	}
}
