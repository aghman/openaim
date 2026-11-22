// Package tui is the OpenAIM terminal client, `openaim tui` (design §11.2):
// a buddy list on the left, an IM window on the right, and a status bar of
// key hints, drawn with Bubble Tea.
//
// The model is a client of the daemon API like every other frontend. It
// subscribes to the daemon's events first, waits for the stream's leading
// `ready`, then loads the buddy list, so it misses no change; when the stream
// ends (the daemon stopped, or the TUI fell behind) it drops the connection,
// shows why, and reconnects with backoff.
//
// Every string that comes from the daemon (petnames, handles, groups, IMs,
// away messages, error text) may come from another person, so it is cleaned
// with internal/termtext at the moment it is drawn: a hostile petname or IM
// can't move the cursor, retitle the window or reorder the screen.
//
// Update and View are plain functions of the model and its messages; all I/O
// happens in tea.Cmds against the Client interface, so tests drive the model
// with a fake client and read View's text.
package tui

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/aghman/openaim/internal/apipb"
)

// Options configure the TUI.
type Options struct {
	// Connect opens the daemon API; called again on every reconnect.
	Connect Connector
	// Socket is the API socket, for the daemon-down screen.
	Socket string
	// Embedded says the daemon runs inside this process (--embedded), so
	// the down screen doesn't suggest starting one.
	Embedded bool
	// Color allows colors; false for NO_COLOR. Text attributes such as
	// bold, italic and reverse are used either way where the terminal has
	// them (the selected row and unverified contacts rely on them).
	Color bool
	// Now is the clock for message times; nil means time.Now.
	Now func() time.Time
	// BackoffMin and BackoffMax bound the wait between reconnect attempts
	// (defaults 500 ms and 15 s). The wait doubles after each failure.
	BackoffMin, BackoffMax time.Duration
	// HistoryLimit is how many messages to load per conversation
	// (default 200).
	HistoryLimit uint32
}

type connState int

const (
	connConnecting connState = iota
	connUp
	connDown
)

type focusArea int

const (
	focusList focusArea = iota
	focusIM
)

// Model is the TUI's state. Use New; drive it with tea.Program (Run) or,
// in tests, by calling Update directly.
type Model struct {
	opt Options
	th  theme

	width, height int

	// The connection. gen increases with every attempt, so results from
	// an abandoned attempt or a dead stream are recognized and dropped.
	conn    connState
	gen     int
	client  Client
	cancel  context.CancelFunc // ends the event stream
	downErr error
	attempt int // failures since the last good connection
	retryIn time.Duration
	everUp  bool
	trying  bool // an attempt is in progress

	status    *pb.Status
	presence  *pb.Presence
	buddies   map[string]*pb.Buddy // by identity key
	collapsed map[string]bool      // by group key
	unread    map[string]int
	convs     map[string]*conv
	open      string // identity key of the open conversation, or ""
	cursor    string // row key of the selected buddy-list row
	focus     focusArea
	input     lineEdit
	dlg       *dialog
	notice    string // one line for the status bar, raw (cleaned when drawn)
	noticeErr bool
	lastAway  string
}

// conv is one conversation's messages, as far as they are loaded.
type conv struct {
	msgs    []*pb.Message
	ids     map[string]int // msg_id → index in msgs
	loaded  bool
	loading bool
	scroll  int // lines scrolled up from the newest
}

// New makes a model. Call Init (tea.Program does) to start connecting.
func New(opt Options) *Model {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.BackoffMin <= 0 {
		opt.BackoffMin = 500 * time.Millisecond
	}
	if opt.BackoffMax < opt.BackoffMin {
		opt.BackoffMax = max(15*time.Second, opt.BackoffMin)
	}
	if opt.HistoryLimit == 0 {
		opt.HistoryLimit = 200
	}
	return &Model{
		opt:       opt,
		th:        newTheme(opt.Color),
		buddies:   map[string]*pb.Buddy{},
		collapsed: map[string]bool{},
		unread:    map[string]int{},
		convs:     map[string]*conv{},
		input:     lineEdit{limit: 4 * maxIMBytes},
	}
}

// Close drops the daemon connection. Run calls it when the program ends.
func (m *Model) Close() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
}

// Messages from commands.
type (
	connectedMsg struct {
		gen     int
		client  Client
		stream  EventStream
		cancel  context.CancelFunc
		status  *pb.Status
		buddies []*pb.Buddy
	}
	connectFailedMsg struct {
		gen int
		err error
	}
	eventMsg struct {
		gen    int
		stream EventStream
		ev     *pb.Event
		err    error
	}
	retryMsg   struct{ gen int }
	historyMsg struct {
		gen  int
		key  string
		msgs []*pb.Message
		err  error
	}
	sentMsg struct {
		gen  int
		key  string
		text string
		resp *pb.SendIMResponse
		err  error
	}
	presenceMsg struct {
		gen int
		p   *pb.Presence
		err error
	}
	addedMsg struct {
		gen int
		b   *pb.Buddy
		err error
	}
	safetyMsg struct {
		gen int
		key string
		sn  *pb.SafetyNumber
		err error
	}
	verifiedMsg struct {
		gen int
		b   *pb.Buddy
		err error
	}
	removedMsg struct {
		gen  int
		key  string
		name string
		err  error
	}
)

// Init starts the first connection attempt.
func (m *Model) Init() tea.Cmd { return m.connect() }

// connect starts a connection attempt: dial, subscribe, wait for ready,
// then load the status and buddy list.
func (m *Model) connect() tea.Cmd {
	m.gen++
	gen := m.gen
	m.trying = true
	if m.conn != connDown {
		m.conn = connConnecting
	}
	dial := m.opt.Connect
	return func() tea.Msg {
		c, err := dial(context.Background())
		if err != nil {
			return connectFailedMsg{gen, err}
		}
		fail := func(err error) tea.Msg {
			c.Close()
			return connectFailedMsg{gen, err}
		}
		sctx, cancel := context.WithCancel(context.Background())
		stream, err := c.Subscribe(sctx)
		if err != nil {
			cancel()
			return fail(err)
		}
		// The daemon sends ready at once; don't wait forever for it.
		timer := time.AfterFunc(callTimeout, cancel)
		ev, err := stream.Recv()
		if !timer.Stop() && err != nil {
			err = status.Error(codes.DeadlineExceeded, "no ready event from openaimd")
		}
		if err == nil && ev.GetReady() == nil {
			err = errors.New("the event stream did not start with ready")
		}
		if err != nil {
			cancel()
			return fail(err)
		}
		ctx, done := withTimeout(context.Background())
		defer done()
		st, err := c.GetStatus(ctx)
		if err != nil {
			cancel()
			return fail(err)
		}
		bs, err := c.ListBuddies(ctx)
		if err != nil {
			cancel()
			return fail(err)
		}
		return connectedMsg{gen: gen, client: c, stream: stream, cancel: cancel, status: st, buddies: bs}
	}
}

func recvCmd(gen int, s EventStream) tea.Cmd {
	return func() tea.Msg {
		ev, err := s.Recv()
		return eventMsg{gen, s, ev, err}
	}
}

// backoff is the wait before reconnect attempt n (0-based).
func (m *Model) backoff(n int) time.Duration {
	d := m.opt.BackoffMin
	for i := 0; i < n && d < m.opt.BackoffMax; i++ {
		d *= 2
	}
	return min(d, m.opt.BackoffMax)
}

// down records a lost or failed connection and schedules the next attempt.
func (m *Model) down(err error) tea.Cmd {
	m.Close()
	m.conn = connDown
	m.trying = false
	m.downErr = err
	m.retryIn = m.backoff(m.attempt)
	m.attempt++
	if m.dlg != nil && m.dlg.kind != dlgHelp {
		m.dlg = nil
	}
	gen := m.gen
	return tea.Tick(m.retryIn, func(time.Time) tea.Msg { return retryMsg{gen} })
}

// Update handles one message.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyPressMsg:
		return m, m.key(msg)
	case tea.PasteMsg:
		m.paste(msg.Content)
		return m, nil

	case connectedMsg:
		if msg.gen != m.gen {
			msg.cancel()
			msg.client.Close()
			return m, nil
		}
		m.client, m.cancel, m.trying = msg.client, msg.cancel, false
		m.conn, m.everUp, m.attempt, m.downErr = connUp, true, 0, nil
		m.status = msg.status
		m.presence = msg.status.GetPresence()
		m.buddies = map[string]*pb.Buddy{}
		for _, b := range msg.buddies {
			m.buddies[b.GetIdentityKey()] = b
		}
		cmds := []tea.Cmd{recvCmd(m.gen, msg.stream)}
		// Reload conversations: messages may have come and gone while we
		// were away.
		for k, c := range m.convs {
			if _, ok := m.buddies[k]; !ok {
				delete(m.convs, k)
				continue
			}
			c.loaded = false
		}
		if m.open != "" {
			if _, ok := m.buddies[m.open]; ok {
				cmds = append(cmds, m.loadHistory(m.open))
			} else {
				m.closeConv()
			}
		}
		m.fixCursor()
		return m, tea.Batch(cmds...)

	case connectFailedMsg:
		if msg.gen != m.gen {
			return m, nil
		}
		return m, m.down(msg.err)

	case retryMsg:
		if msg.gen != m.gen || m.conn != connDown {
			return m, nil
		}
		return m, m.connect()

	case eventMsg:
		if msg.gen != m.gen || m.conn != connUp {
			return m, nil
		}
		if msg.err != nil {
			if status.Code(msg.err) == codes.ResourceExhausted {
				// We fell behind and missed events: start over at once.
				m.attempt = 0
				m.Close()
				m.conn = connConnecting
				return m, m.connect()
			}
			return m, m.down(msg.err)
		}
		m.event(msg.ev)
		return m, recvCmd(m.gen, msg.stream)

	case historyMsg:
		if msg.gen != m.gen {
			return m, nil
		}
		c := m.conv(msg.key)
		c.loading = false
		if msg.err != nil {
			m.setErr("loading history: " + errText(msg.err))
			return m, nil
		}
		c.merge(msg.msgs)
		return m, nil

	case sentMsg:
		if msg.err != nil {
			m.setErr("not sent: " + errText(msg.err))
			// Give the text back, unless something new was typed.
			if msg.key == m.open && m.input.Value() == "" {
				m.input.SetValue(msg.text)
			}
			return m, nil
		}
		m.addMessage(msg.resp.GetMessage())
		return m, nil

	case presenceMsg:
		if msg.err != nil {
			m.setErr("presence: " + errText(msg.err))
			return m, nil
		}
		m.presence = msg.p
		if msg.p.GetState() == pb.PresenceState_PRESENCE_STATE_AWAY {
			m.setNotice("You are away.")
		} else {
			m.setNotice("You are back.")
		}
		return m, nil

	case addedMsg:
		if m.dlg == nil || m.dlg.kind != dlgAdd {
			return m, nil
		}
		m.dlg.busy = false
		if msg.err != nil {
			m.dlg.err = errText(msg.err)
			return m, nil
		}
		m.dlg = nil
		m.buddies[msg.b.GetIdentityKey()] = msg.b
		m.cursor = buddyRow(msg.b.GetIdentityKey())
		m.focus = focusList
		m.setNotice("Added " + displayName(msg.b) + " (" + msg.b.GetKeyId() + "). Press v to compare safety numbers.")
		return m, nil

	case safetyMsg:
		if m.dlg == nil || m.dlg.kind != dlgVerify || m.dlg.target != msg.key {
			return m, nil
		}
		m.dlg.busy = false
		if msg.err != nil {
			m.dlg.err = errText(msg.err)
			return m, nil
		}
		m.dlg.sn = msg.sn
		return m, nil

	case verifiedMsg:
		if m.dlg != nil && m.dlg.kind == dlgVerify {
			m.dlg.busy = false
			if msg.err != nil {
				m.dlg.err = errText(msg.err)
				return m, nil
			}
			m.dlg = nil
		}
		if msg.err != nil {
			m.setErr(errText(msg.err))
			return m, nil
		}
		m.buddies[msg.b.GetIdentityKey()] = msg.b
		if msg.b.GetVerified() {
			m.setNotice(displayName(msg.b) + " is verified.")
		} else {
			m.setNotice(displayName(msg.b) + " is no longer verified.")
		}
		return m, nil

	case removedMsg:
		if msg.err != nil {
			m.setErr("remove: " + errText(msg.err))
			return m, nil
		}
		m.removeBuddy(msg.key)
		m.setNotice("Removed " + msg.name + ".")
		return m, nil
	}
	return m, nil
}

// event applies one daemon event.
func (m *Model) event(ev *pb.Event) {
	switch k := ev.GetKind().(type) {
	case *pb.Event_BuddyAdded:
		m.buddies[k.BuddyAdded.GetIdentityKey()] = k.BuddyAdded
	case *pb.Event_BuddyChanged:
		m.buddies[k.BuddyChanged.GetIdentityKey()] = k.BuddyChanged
	case *pb.Event_BuddyRemoved:
		key := k.BuddyRemoved.GetIdentityKey()
		if _, ok := m.buddies[key]; ok {
			m.removeBuddy(key)
		}
	case *pb.Event_MessageQueued:
		m.addMessage(k.MessageQueued)
	case *pb.Event_MessageReceived:
		msg := k.MessageReceived
		if m.addMessage(msg) && (msg.GetBuddyKey() != m.open || m.focus != focusIM) {
			m.unread[msg.GetBuddyKey()]++
		}
	case *pb.Event_PresenceChanged:
		m.presence = k.PresenceChanged
	}
	m.fixCursor()
}

func (m *Model) removeBuddy(key string) {
	delete(m.buddies, key)
	delete(m.convs, key)
	delete(m.unread, key)
	if m.open == key {
		m.closeConv()
	}
	if m.dlg != nil && m.dlg.target == key {
		m.dlg = nil
	}
	m.fixCursor()
}

func (m *Model) closeConv() {
	m.open = ""
	m.focus = focusList
	m.input.Reset()
}

func (m *Model) conv(key string) *conv {
	c, ok := m.convs[key]
	if !ok {
		c = &conv{ids: map[string]int{}}
		m.convs[key] = c
	}
	return c
}

// addMessage adds or updates a message and reports whether it is new.
func (m *Model) addMessage(msg *pb.Message) bool {
	if msg == nil || msg.GetBuddyKey() == "" {
		return false
	}
	return m.conv(msg.GetBuddyKey()).put(msg)
}

func (c *conv) put(msg *pb.Message) bool {
	if i, ok := c.ids[msg.GetMsgId()]; ok && msg.GetMsgId() != "" {
		c.msgs[i] = msg
		return false
	}
	c.ids[msg.GetMsgId()] = len(c.msgs)
	c.msgs = append(c.msgs, msg)
	return true
}

// merge replaces the messages with a loaded history, keeping any that
// arrived (by event) after the history was read.
func (c *conv) merge(hist []*pb.Message) {
	old := c.msgs
	c.msgs, c.ids = nil, map[string]int{}
	for _, msg := range hist {
		c.put(msg)
	}
	for _, msg := range old {
		if _, ok := c.ids[msg.GetMsgId()]; !ok {
			c.put(msg)
		}
	}
	c.loaded = true
}

func (m *Model) loadHistory(key string) tea.Cmd {
	c := m.conv(key)
	if c.loading || m.client == nil {
		return nil
	}
	c.loading = true
	cl, gen, limit := m.client, m.gen, m.opt.HistoryLimit
	return func() tea.Msg {
		ctx, cancel := withTimeout(context.Background())
		defer cancel()
		msgs, err := cl.History(ctx, key, limit)
		return historyMsg{gen, key, msgs, err}
	}
}

// openConv opens the IM window with a buddy and moves the focus there.
func (m *Model) openConv(key string) tea.Cmd {
	if _, ok := m.buddies[key]; !ok {
		return nil
	}
	if m.open != key {
		m.input.Reset()
	}
	m.open = key
	m.focus = focusIM
	m.cursor = buddyRow(key)
	delete(m.unread, key)
	if c := m.conv(key); !c.loaded {
		return m.loadHistory(key)
	}
	return nil
}

func (m *Model) send() tea.Cmd {
	text := m.input.Value()
	if m.open == "" || strings.TrimSpace(text) == "" {
		return nil
	}
	if n := len(text); n > maxIMBytes {
		m.setErr(counterText(n) + ": shorten the message to send it")
		return nil
	}
	m.input.Reset()
	if c := m.convs[m.open]; c != nil {
		c.scroll = 0
	}
	cl, gen, key := m.client, m.gen, m.open
	return func() tea.Msg {
		ctx, cancel := withTimeout(context.Background())
		defer cancel()
		r, err := cl.SendIM(ctx, key, text)
		return sentMsg{gen, key, text, r, err}
	}
}

func (m *Model) setNotice(s string) { m.notice, m.noticeErr = s, false }
func (m *Model) setErr(s string)    { m.notice, m.noticeErr = s, true }

func (m *Model) away() bool {
	return m.presence.GetState() == pb.PresenceState_PRESENCE_STATE_AWAY
}

func (m *Model) setPresence(state pb.PresenceState, msg string) tea.Cmd {
	cl, gen := m.client, m.gen
	return func() tea.Msg {
		ctx, cancel := withTimeout(context.Background())
		defer cancel()
		p, err := cl.SetPresence(ctx, state, msg)
		return presenceMsg{gen, p, err}
	}
}

// sortedBuddies is every buddy, by display name.
func sortedBuddies(bs map[string]*pb.Buddy) []*pb.Buddy {
	out := make([]*pb.Buddy, 0, len(bs))
	for _, b := range bs {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(displayName(out[i])), strings.ToLower(displayName(out[j]))
		if a != b {
			return a < b
		}
		return out[i].GetIdentityKey() < out[j].GetIdentityKey()
	})
	return out
}
