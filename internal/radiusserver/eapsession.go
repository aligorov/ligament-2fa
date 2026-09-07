// EAP-сессии (RFC 3748/RFC 5281): in-memory map keyed по hex(RADIUS State),
// TTL и кап против флуда; TLS-мост — адаптер net.Conn, через который
// crypto/tls гоняет handshake и phase-2 данные МЕЖДУ RADIUS-пакетами
// (паттерн go-eap: tls.Server поверх custom conn; каждый шаг EAP
// завершается Access-Challenge и возвратом из handleAuth — обработчик
// не блокируется навсегда, лимит — eapStepTimeout).
package radiusserver

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/aligorov/twofa/internal/radiusserver/eap"
)

// Параметры EAP-сессий и TLS-моста.
const (
	// eapSessionTTL — срок жизни сессии по RADIUS State: handshake TLS +
	// внутренняя аутентификация должны уложиться; просроченные выметаются
	// лениво при каждом обращении к store.
	eapSessionTTL = 90 * time.Second

	// eapSessionCap — потолок одновременных сессий (анти-flood): при
	// переполнении выметаются просроченные, затем самые старые.
	eapSessionCap = 1024

	// eapStepTimeout — потолок ожидания одного шага TLS-моста внутри
	// обработки одного RADIUS-пакета.
	eapStepTimeout = 5 * time.Second

	// eapKeyLabel/eapKeyBlockLen — keying material TTLS (RFC 5281 §10):
	// PRF(master_secret, "ttls keying material", client_random||
	// server_random) длиной 64 байта: первые 32 — MS-MPPE-Recv-Key,
	// вторые 32 — MS-MPPE-Send-Key.
	eapKeyLabel    = "ttls keying material"
	peapKeyLabel   = "client EAP encryption"
	eapKeyBlockLen = 64
)

// eapProtocol — тип внешнего протокола сессии.
type eapProtocol int

const (
	eapProtoPEAP eapProtocol = iota // PEAPv0 (дефолт для нативного входа iOS/Windows/Android)
	eapProtoTTLS                    // EAP-TTLS (для клиентов, запросивших TTLS через Nak)
)

// peapInnerState — состояние внутренней аутентификации MS-CHAPv2 внутри PEAP-туннеля.
type peapInnerState int

const (
	peapStateChallenge peapInnerState = iota // сервер отправил MS-CHAPv2 Challenge, ждёт Response
	peapStateSuccess                        // сервер отправил MS-CHAPv2 Success, ждёт Success ACK
	peapStateTLV                            // сервер отправил Result TLV, ждёт Result TLV Response
	peapStateFailed                         // сервер отправил MS-CHAPv2 Failure, ждёт Failure ACK
)

// eapConn — адаптер net.Conn для crypto/tls поверх EAP-TTLS. Read отдаёт
// накопленные TLS-записи из EAP-ответов клиента (deliver), Write складывает
// записи сервера в исходящий буфер (takeOutput → EAP-Request/TTLS).
// Deadline-методы — no-op: темп задаёт RADIUS-обмен, TTL сессии —
// ограничитель жизни. Сигнальные каналы ёмкости 1: wantIn — TLS-слою нужен
// ещё ввод (можно отправлять пустой ACK-запрос), outReady — появились
// исходящие записи.
type eapConn struct {
	mu     sync.Mutex
	inBuf  bytes.Buffer
	outBuf bytes.Buffer

	inReady  chan struct{}
	outReady chan struct{}
	wantIn   chan struct{}

	closedOnce sync.Once
	closed     chan struct{}
}

func newEAPConn() *eapConn {
	return &eapConn{
		inReady:  make(chan struct{}, 1),
		outReady: make(chan struct{}, 1),
		wantIn:   make(chan struct{}, 1),
		closed:   make(chan struct{}),
	}
}

// signal — неблокирующая отправка в канал ёмкости 1.
func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// deliver дописывает TLS-записи из EAP-ответа клиента.
func (c *eapConn) deliver(p []byte) {
	c.mu.Lock()
	c.inBuf.Write(p)
	c.mu.Unlock()
	// Сбросить возможный отложенный сигнал «жду ввода»: данные пришли.
	select {
	case <-c.wantIn:
	default:
	}
	signal(c.inReady)
}

// takeOutput забирает накопленные исходящие TLS-записи (nil — если пусто).
func (c *eapConn) takeOutput() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outBuf.Len() == 0 {
		return nil
	}
	out := append([]byte(nil), c.outBuf.Bytes()...)
	c.outBuf.Reset()
	return out
}

func (c *eapConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.inBuf.Len() > 0 {
			n, _ := c.inBuf.Read(p)
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()
		signal(c.wantIn)
		select {
		case <-c.inReady:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
}

func (c *eapConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.outBuf.Write(p)
	c.mu.Unlock()
	signal(c.outReady)
	return len(p), nil
}

func (c *eapConn) Close() error {
	c.closedOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *eapConn) LocalAddr() net.Addr              { return eapAddr{} }
func (c *eapConn) RemoteAddr() net.Addr             { return eapAddr{} }
func (c *eapConn) SetDeadline(time.Time) error      { return nil }
func (c *eapConn) SetReadDeadline(time.Time) error  { return nil }
func (c *eapConn) SetWriteDeadline(time.Time) error { return nil }

// eapAddr — заглушка адреса моста (net.Conn требует net.Addr).
type eapAddr struct{}

func (eapAddr) Network() string { return "eap-ttls" }
func (eapAddr) String() string  { return "eap-ttls" }

// ---- сессия ----

// eapPhase — фаза обмена.
type eapPhase int

const (
	eapPhaseHandshake     eapPhase = iota // TLS handshake в процессе
	eapPhaseHandshakeDone                 // TLS handshake завершён сервером, ждём ACK клиента
	eapPhaseInner                         // туннель поднят, ждём/обрабатываем phase-2
)

// ttlsFrag — фрагмент исходящего потока (очередь отправки).
type ttlsFrag struct {
	data     []byte
	first    bool
	last     bool
	declared int
}

// eapSession — одна EAP аутентификация (PEAPv0 или EAP-TTLS), резюмируется по State.
// Поля, кроме помеченных «store-мьютекс», трогает только RADIUS-хендлер
// (layeh/radius обслуживает пакеты последовательно на своём цикле); воркер
// runTLS пишет только в каналы, keyBlock и буферы conn.
type eapSession struct {
	state     []byte // сырые байты RADIUS State (кладутся в Challenge как есть)
	stateKey  string // hex(state) — ключ карты сессий
	createdAt time.Time
	lastUsed  time.Time // под мьютексом store

	conn        *eapConn
	tlsConn     *tls.Conn
	handshakeCh chan error  // результат handshake (одно значение)
	appData     chan []byte // расшифрованные phase-2 данные (ёмкость 1)
	workerErr   chan error  // фатальная ошибка воркера после handshake

	proto         eapProtocol
	innerState    peapInnerState
	authChallenge [16]byte
	innerReqID    byte
	innerMSCHAPID byte
	outerIdentity string

	phase        eapPhase
	keyBlock     []byte // 64 байта keying material (кладёт воркер)
	pendingInner []byte // частично пришедший AVP-блок или внутренний EAP-пакет
	frag         eap.Assembler
	outQueue     []ttlsFrag // недоразосланные фрагменты исходящего потока
	reqID        byte       // identifier следующего EAP-Request
	id           byte       // identifier последнего Response клиента (для Failure)
	fragSize     int        // размер фрагмента исходящего потока (по Framed-MTU или MaxFragment)

	// Ретрансмиты NAS (под мьютексом store): дубликат запроса — повтор
	// последнего ответа.
	lastReqEAP  []byte
	lastRespEAP []byte
}

// newEAPSession собирает сессию (stateKey = hex(raw)) и стартует TLS-воркер.
func newEAPSession(raw []byte, stateKey string, cert *tls.Certificate, proto eapProtocol) *eapSession {
	conn := newEAPConn()
	// EAP-TTLS и PEAPv0 определены на TLS 1.0–1.2: 1.3 не используется.
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
	}
	sess := &eapSession{
		state:         append([]byte(nil), raw...),
		stateKey:      stateKey,
		createdAt:     time.Now(),
		lastUsed:      time.Now(),
		conn:          conn,
		tlsConn:       tls.Server(conn, cfg),
		handshakeCh:   make(chan error, 1),
		appData:       make(chan []byte, 1),
		workerErr:     make(chan error, 1),
		proto:         proto,
		innerState:    peapStateChallenge,
		frag:          eap.Assembler{},
		reqID:         0,
		lastRespEAP:   nil,
		lastReqEAP:    nil,
		pendingInner:  nil,
	}
	go sess.runTLS()
	return sess
}

// runTLS — воркер сессии: TLS-handshake, затем расшифровка phase-2 данных.
// Живёт между RADIUS-пакетами: блокируется на Read моста, пока клиент не
// пришлёт данные; завершается по закрытию сессии или ошибке TLS.
func (sess *eapSession) runTLS() {
	if err := sess.tlsConn.Handshake(); err != nil {
		sess.handshakeCh <- err
		return
	}
	label := eapKeyLabel
	if sess.proto == eapProtoPEAP {
		label = peapKeyLabel
	}
	cs := sess.tlsConn.ConnectionState()
	kb, err := cs.ExportKeyingMaterial(label, nil, eapKeyBlockLen)
	if err != nil {
		sess.handshakeCh <- fmt.Errorf("экспорт keying material (%s): %w", label, err)
		return
	}
	sess.keyBlock = kb
	sess.handshakeCh <- nil
	for {
		buf := make([]byte, 16384)
		n, err := sess.tlsConn.Read(buf)
		if n > 0 {
			select {
			case sess.appData <- buf[:n]:
			case <-sess.conn.closed:
				return
			}
		}
		if err != nil {
			select {
			case sess.workerErr <- err:
			default:
			}
			return
		}
	}
}

// writeInner отправляет открытый EAP-пакет в TLS-туннель (для PEAP).
// Зашифрованные TLS-записи складываются в outBuf моста.
func (sess *eapSession) writeInner(pkt []byte) error {
	_, err := sess.tlsConn.Write(pkt)
	return err
}

// waitHandshakeStep собирает исходящие TLS-записи после доставки данных
// клиента до точки покоя: «TLS ждёт ещё ввода» (ответ — пустой ACK-запрос
// или продолжение очереди фрагментов) либо «handshake завершён».
// Не блокируется дольше eapStepTimeout.
func (sess *eapSession) waitHandshakeStep() (out []byte, handshakeFinished bool, err error) {
	timer := time.NewTimer(eapStepTimeout)
	defer timer.Stop()
	for {
		if b := sess.conn.takeOutput(); len(b) > 0 {
			out = append(out, b...)
			continue
		}
		// Проверяем handshakeCh ПРИОРИТЕТНО: воркер после Handshake() сразу
		// переходит к Read(), сигнализируя wantIn — случайный выбор select в Go
		// может предпочесть wantIn вместо завершённого handshakeCh.
		select {
		case herr := <-sess.handshakeCh:
			if b := sess.conn.takeOutput(); len(b) > 0 {
				out = append(out, b...)
			}
			if herr != nil {
				return nil, false, herr
			}
			return out, true, nil
		default:
		}

		select {
		case <-sess.conn.outReady:
			continue
		case herr := <-sess.handshakeCh:
			if b := sess.conn.takeOutput(); len(b) > 0 {
				out = append(out, b...)
			}
			if herr != nil {
				return nil, false, herr
			}
			return out, true, nil
		case <-sess.conn.wantIn:
			if b := sess.conn.takeOutput(); len(b) > 0 {
				out = append(out, b...)
				continue
			}
			select {
			case herr := <-sess.handshakeCh:
				if b := sess.conn.takeOutput(); len(b) > 0 {
					out = append(out, b...)
				}
				if herr != nil {
					return nil, false, herr
				}
				return out, true, nil
			default:
			}
			return out, false, nil
		case werr := <-sess.workerErr:
			return nil, false, werr
		case <-timer.C:
			return nil, false, errors.New("таймаут шага TLS handshake")
		}
	}
}

// waitAppData ждёт расшифровки phase-2 данных после доставки: возвращает
// накопленный plaintext (возможно пустой — тогда клиенту уходит пустой
// ACK-запрос). Ошибка воркера прерывает обмен; таймаут НЕ ошибка —
// возвращается то, что успело расшифроваться.
func (sess *eapSession) waitAppData() ([]byte, error) {
	timer := time.NewTimer(eapStepTimeout)
	defer timer.Stop()
	var out []byte
	for {
		select {
		case chunk := <-sess.appData:
			out = append(out, chunk...)
			continue
		default:
		}

		select {
		case chunk := <-sess.appData:
			out = append(out, chunk...)
			continue
		case <-sess.conn.wantIn:
			select {
			case chunk := <-sess.appData:
				out = append(out, chunk...)
			default:
			}
			return out, nil
		case err := <-sess.workerErr:
			return out, err
		case <-timer.C:
			return out, nil
		}
	}
}

// takeAppData — неблокирующий забор накопленных phase-2 данных (воркер
// мог расшифровать их раньше, чем пришёл следующий запрос).
func (sess *eapSession) takeAppData() []byte {
	select {
	case chunk := <-sess.appData:
		return chunk
	default:
		return nil
	}
}

// nextReqID возвращает identifier для следующего EAP-Request и инкрементирует его (RFC 3748 §4.1).
func (sess *eapSession) nextReqID() byte {
	id := sess.reqID
	sess.reqID++
	return id
}

// pushOutQueue режет исходящий поток на фрагменты ≤ eap.MaxFragment (или согласно Framed-MTU).
func (sess *eapSession) pushOutQueue(payload []byte) {
	if len(payload) == 0 {
		return
	}
	fragSize := sess.fragSize
	if fragSize <= 0 {
		fragSize = eap.MaxFragment
	}
	for off := 0; off < len(payload); {
		end := off + fragSize
		if end > len(payload) {
			end = len(payload)
		}
		sess.outQueue = append(sess.outQueue, ttlsFrag{
			data:     payload[off:end],
			first:    off == 0,
			last:     end == len(payload),
			declared: len(payload),
		})
		off = end
	}
}

// popOutFragment достаёт следующий фрагмент очереди и собирает полный
// EAP-Request/PEAP или EAP-Request/TTLS (первый — L с полной длиной, все кроме последнего — M;
// identifier — sess.nextReqID: каждый новый Request ≠ предыдущего, RFC 3748 §4.1).
func (sess *eapSession) popOutFragment() []byte {
	if len(sess.outQueue) == 0 {
		return nil
	}
	f := sess.outQueue[0]
	sess.outQueue = sess.outQueue[1:]
	id := sess.nextReqID()
	declared := -1
	if f.first {
		declared = f.declared
	}
	if sess.proto == eapProtoPEAP {
		var flags byte
		if f.first {
			flags |= eap.PEAPFlagLength
		}
		if !f.last {
			flags |= eap.PEAPFlagMore
		}
		return eap.BuildPEAP(eap.CodeRequest, id, flags, declared, f.data)
	}
	var flags byte
	if f.first {
		flags |= eap.TTLSFlagLength
	}
	if !f.last {
		flags |= eap.TTLSFlagMore
	}
	return eap.BuildTTLS(eap.CodeRequest, id, flags, declared, f.data)
}

// ---- store ----

// eapSessionStore — хранилище сессий keyed по hex(State).
type eapSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*eapSession
}

func newEAPSessionStore() *eapSessionStore {
	return &eapSessionStore{sessions: make(map[string]*eapSession)}
}

// get возвращает сессию по State (лениво выметая просроченные).
func (st *eapSessionStore) get(state string) *eapSession {
	if state == "" {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.cleanupLocked()
	s, ok := st.sessions[state]
	if !ok {
		return nil
	}
	s.lastUsed = time.Now()
	return s
}

// create делает новую сессию со свежим State (crypto/rand 16 байт),
// заданным протоколом (PEAP или TTLS) и стартует TLS-воркер. При
// переполнении капы выметаются просроченные, затем самые старые.
func (st *eapSessionStore) create(cert *tls.Certificate, proto eapProtocol) *eapSession {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.cleanupLocked()
	for len(st.sessions) >= eapSessionCap {
		var oldest string
		var oldestT time.Time
		for k, v := range st.sessions {
			if oldest == "" || v.lastUsed.Before(oldestT) {
				oldest, oldestT = k, v.lastUsed
			}
		}
		st.sessions[oldest].conn.Close()
		delete(st.sessions, oldest)
	}
	for {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			// crypto/rand практически не падает; защитная ветка на базе
			// времени (все 16 байт заполнить счетчиком и наносекундами).
			binary.BigEndian.PutUint64(b[8:], uint64(time.Now().UnixNano()))
		}
		state := hex.EncodeToString(b)
		if _, exists := st.sessions[state]; exists {
			continue
		}
		sess := newEAPSession(b, state, cert, proto)
		st.sessions[state] = sess
		return sess
	}
}

// delete убивает сессию (закрывая мост — воркер завершается).
func (st *eapSessionStore) delete(sess *eapSession) {
	if sess == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if cur, ok := st.sessions[sess.stateKey]; ok && cur == sess {
		delete(st.sessions, sess.stateKey)
	}
	sess.conn.Close()
}

// cleanupLocked выметает просроченные сессии (мьютекс захвачен).
func (st *eapSessionStore) cleanupLocked() {
	var expired []string
	for k, v := range st.sessions {
		if time.Since(v.lastUsed) > eapSessionTTL {
			expired = append(expired, k)
		}
	}
	for _, k := range expired {
		st.sessions[k].conn.Close()
		delete(st.sessions, k)
	}
}
