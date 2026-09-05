package auth

// Split — кандидат разбиения строки «пароль+код» для RADIUS-режима
// «код приклеен к паролю» (спека §3.1): последние L символов трактуются
// как код, начало строки — как пароль.
type Split struct {
	Password string
	Code     string
}

// SplitCandidates возвращает все разбиения s по длинам кода lengths в
// порядке задания длин. Кандидат добавляется только когда строка строго
// длиннее длины кода — в части пароля должен остаться хотя бы один символ
// (равенство длин означало бы пустой пароль). Случай «вся строка — пароль,
// кода нет» кандидатом не является и обрабатывается отдельно вызывающими
// (проверка полного пароля + push-режим RADIUS).
func SplitCandidates(s string, lengths []int) []Split {
	out := make([]Split, 0, len(lengths))
	for _, l := range lengths {
		if l <= 0 || len(s) <= l {
			continue
		}
		out = append(out, Split{Password: s[:len(s)-l], Code: s[len(s)-l:]})
	}
	return out
}
