package store

import (
	"errors"
	"testing"
	"testing/fstest"
)

func TestParseMigrationsSortsNumerically(t *testing.T) {
	fsys := fstest.MapFS{
		"10_ten.sql": {Data: []byte("-- 10")},
		"2_two.sql":  {Data: []byte("-- 2")},
		"9_nine.sql": {Data: []byte("-- 9")},
		"1_one.sql":  {Data: []byte("-- 1")},
		"README.md":  {Data: []byte("не SQL — игнорируется")},
	}
	// Лексикографическая сортировка дала бы 1,10,2,9 — проверяем числовую.
	wantVersions := []int{1, 2, 9, 10}

	migs, err := parseMigrations(fsys)
	if err != nil {
		t.Fatalf("parseMigrations: %v", err)
	}
	if len(migs) != len(wantVersions) {
		t.Fatalf("получено %d миграций, ожидалось %d (не-SQL файлы должны игнорироваться)",
			len(migs), len(wantVersions))
	}
	for i, m := range migs {
		if m.version != wantVersions[i] {
			t.Errorf("миграция #%d: версия %d, ожидалась %d", i, m.version, wantVersions[i])
		}
	}
	if migs[0].sql != "-- 1" {
		t.Errorf("содержимое миграции не прочитано: %q", migs[0].sql)
	}
}

func TestParseMigrationsDuplicateVersion(t *testing.T) {
	fsys := fstest.MapFS{
		"1_first.sql":  {Data: []byte("-- 1")},
		"1_second.sql": {Data: []byte("-- 1 ещё раз")},
	}
	if _, err := parseMigrations(fsys); err == nil {
		t.Fatal("ожидалась ошибка дубликата версии, получен nil")
	} else if !errors.Is(err, errDuplicateVersion) {
		t.Errorf("ожидалась errDuplicateVersion, получено: %v", err)
	}
}

func TestParseMigrationsInvalidNames(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"нет версии":      {"init.sql": {Data: []byte("-- x")}},
		"версия не число": {"abc_init.sql": {Data: []byte("-- x")}},
	}
	for name, fsys := range cases {
		if _, err := parseMigrations(fsys); err == nil {
			t.Errorf("%s: ожидалась ошибка, получен nil", name)
		}
	}
}

func TestParseMigrationsEmbedded(t *testing.T) {
	// Встроенные миграции проекта валидны и непусты.
	migs, err := parseMigrations(migrationsFS)
	if err != nil {
		t.Fatalf("parseMigrations(встроенные): %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("встроенные миграции отсутствуют")
	}
	for _, m := range migs {
		if m.sql == "" {
			t.Errorf("миграция %s пуста", m.name)
		}
	}
}
