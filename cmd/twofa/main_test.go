// Юнит-тесты CLI-обвязки бэкапа: открытие приёмника дампа («-» → stdout,
// путь → файл с правами 0600 — дамп секретен) без обращения к БД.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenBackupOutputStdout(t *testing.T) {
	w, closeFn, err := openBackupOutput("-")
	if err != nil {
		t.Fatalf("openBackupOutput(\"-\"): %v", err)
	}
	defer closeFn()
	if w != os.Stdout {
		t.Fatalf("«-» должен давать os.Stdout, получил %T", w)
	}
}

func TestOpenBackupOutputFilePerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.sql")
	w, closeFn, err := openBackupOutput(path)
	if err != nil {
		t.Fatalf("openBackupOutput(%s): %v", path, err)
	}
	if _, err := w.Write([]byte("-- dump\n")); err != nil {
		t.Fatalf("запись: %v", err)
	}
	closeFn()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("права файла дампа = %v, want 0600 (дамп секретен)", fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "-- dump\n" {
		t.Fatalf("содержимое = %q err=%v", b, err)
	}
}

func TestOpenBackupOutputBadPath(t *testing.T) {
	if _, _, err := openBackupOutput(filepath.Join(t.TempDir(), "no-such-dir", "b.sql")); err == nil {
		t.Fatal("несуществующий каталог должен давать ошибку")
	}
}
