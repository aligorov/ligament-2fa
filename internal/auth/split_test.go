package auth

import (
	"reflect"
	"testing"
)

func TestSplitCandidates(t *testing.T) {
	cases := []struct {
		name    string
		s       string
		lengths []int
		want    []Split
	}{
		{
			name:    "пароль+код, длины [6,8] по порядку",
			s:       "secret123456",
			lengths: []int{6, 8},
			want: []Split{
				{Password: "secret", Code: "123456"},
				{Password: "secr", Code: "et123456"},
			},
		},
		{
			name:    "порядок длин сохраняется: [8,6]",
			s:       "secret123456",
			lengths: []int{8, 6},
			want: []Split{
				{Password: "secr", Code: "et123456"},
				{Password: "secret", Code: "123456"},
			},
		},
		{
			name:    "строка короче всех длин — кандидатов нет",
			s:       "123456",
			lengths: []int{6, 8},
			want:    nil,
		},
		{
			name:    "равная длина пропускается, меньшая — даёт кандидата",
			s:       "12345678",
			lengths: []int{6, 8},
			want:    []Split{{Password: "12", Code: "345678"}},
		},
		{
			name:    "строка равна единственной длине кода — кандидатов нет",
			s:       "12345678",
			lengths: []int{8},
			want:    nil,
		},
		{
			name:    "минимальный кандидат: один символ пароля",
			s:       "a123456",
			lengths: []int{6},
			want:    []Split{{Password: "a", Code: "123456"}},
		},
		{
			name:    "неположительные длины пропускаются",
			s:       "a123456",
			lengths: []int{0, -3, 6},
			want:    []Split{{Password: "a", Code: "123456"}},
		},
		{
			name:    "пароль без цифрового хвоста всё равно разбивается (код проверит VerifyAnyCode)",
			s:       "hunter2secret",
			lengths: []int{6},
			want:    []Split{{Password: "hunter2", Code: "secret"}},
		},
		{
			name:    "пустой список длин",
			s:       "secret123456",
			lengths: nil,
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitCandidates(tc.s, tc.lengths)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("SplitCandidates(%q, %v) = %+v, хочу %+v", tc.s, tc.lengths, got, tc.want)
			}
		})
	}
}
