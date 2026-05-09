package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testRealmToken = "realm-token"
	testNonce      = "00112233445566778899aabbccddeeff"
	testObfs       = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

func TestMain(m *testing.M) {
	// Shrink the connect-response wait so tests that don't post a response
	// (i.e. exercise the fallback path) finish quickly. The new tests that
	// explicitly exercise the wait/respond path override this further.
	connectResponseTimeout = 100 * time.Millisecond
	os.Exit(m.Run())
}

func TestConnectForwardsPunchMetadata(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d, want %d", registerResp.Code, http.StatusOK)
	}
	var registerBody struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&registerBody); err != nil {
		t.Fatal(err)
	}

	eventsCtx, cancelEvents := context.WithCancel(context.Background())
	eventsReq := httptest.NewRequest(http.MethodGet, "/v1/example/events", nil).WithContext(eventsCtx)
	eventsReq.Header.Set("Authorization", "Bearer "+registerBody.SessionID)
	eventsResp := newFlushRecorder()
	eventsDone := make(chan struct{})
	go func() {
		s.handle(eventsResp, eventsReq)
		close(eventsDone)
	}()

	connectResp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, map[string]any{
		"addresses": []string{"198.51.100.20:4433"},
		"nonce":     testNonce,
		"obfs":      testObfs,
	})
	if connectResp.Code != http.StatusOK {
		t.Fatalf("connect status = %d, want %d", connectResp.Code, http.StatusOK)
	}
	var connectBody struct {
		Addresses []string `json:"addresses"`
		Nonce     string   `json:"nonce"`
		Obfs      string   `json:"obfs"`
	}
	if err := json.NewDecoder(connectResp.Body).Decode(&connectBody); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(connectBody.Addresses, ","), "203.0.113.10:4433"; got != want {
		t.Fatalf("connect addresses = %q, want %q", got, want)
	}
	if connectBody.Nonce != testNonce {
		t.Fatalf("connect nonce = %q, want %q", connectBody.Nonce, testNonce)
	}
	if connectBody.Obfs != testObfs {
		t.Fatalf("connect obfs = %q, want %q", connectBody.Obfs, testObfs)
	}

	waitForSSEData(t, eventsResp)
	cancelEvents()
	<-eventsDone

	scanner := bufio.NewScanner(eventsResp.Body)
	var eventData string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			eventData = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if eventData == "" {
		t.Fatal("missing SSE data line")
	}
	var ev punchEvent
	if err := json.Unmarshal([]byte(eventData), &ev); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(ev.Addresses, ","), "198.51.100.20:4433"; got != want {
		t.Fatalf("event addresses = %q, want %q", got, want)
	}
	if ev.Nonce != testNonce {
		t.Fatalf("event nonce = %q, want %q", ev.Nonce, testNonce)
	}
	if ev.Obfs != testObfs {
		t.Fatalf("event obfs = %q, want %q", ev.Obfs, testObfs)
	}
}

func TestConnectRequiresPunchMetadata(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d, want %d", registerResp.Code, http.StatusOK)
	}

	tests := []struct {
		name string
		body map[string]any
	}{
		{
			name: "missing nonce",
			body: map[string]any{
				"addresses": []string{"198.51.100.20:4433"},
				"obfs":      testObfs,
			},
		},
		{
			name: "invalid nonce",
			body: map[string]any{
				"addresses": []string{"198.51.100.20:4433"},
				"nonce":     "not-hex",
				"obfs":      testObfs,
			},
		},
		{
			name: "missing obfs",
			body: map[string]any{
				"addresses": []string{"198.51.100.20:4433"},
				"nonce":     testNonce,
			},
		},
		{
			name: "invalid obfs",
			body: map[string]any{
				"addresses": []string{"198.51.100.20:4433"},
				"nonce":     testNonce,
				"obfs":      "not-hex",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, tc.body)
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("connect status = %d, want %d", resp.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestHeartbeatUpdatesAddresses(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d, want %d", registerResp.Code, http.StatusOK)
	}
	var registerBody struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&registerBody); err != nil {
		t.Fatal(err)
	}

	heartbeatResp := doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", registerBody.SessionID, map[string]any{
		"addresses": []string{"203.0.113.11:4433"},
	})
	if heartbeatResp.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d, want %d", heartbeatResp.Code, http.StatusOK)
	}

	connectResp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, map[string]any{
		"addresses": []string{"198.51.100.20:4433"},
		"nonce":     testNonce,
		"obfs":      testObfs,
	})
	if connectResp.Code != http.StatusOK {
		t.Fatalf("connect status = %d, want %d", connectResp.Code, http.StatusOK)
	}
	var connectBody struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(connectResp.Body).Decode(&connectBody); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(connectBody.Addresses, ","), "203.0.113.11:4433"; got != want {
		t.Fatalf("connect addresses = %q, want %q", got, want)
	}
}

func TestHeartbeatRejectsInvalidAddresses(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d, want %d", registerResp.Code, http.StatusOK)
	}
	var registerBody struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&registerBody); err != nil {
		t.Fatal(err)
	}

	resp := doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", registerBody.SessionID, map[string]any{
		"addresses": []string{"not-an-address"},
	})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("heartbeat status = %d, want %d", resp.Code, http.StatusBadRequest)
	}
}

func TestHeartbeatPushesAckEvent(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d", registerResp.Code)
	}
	var registerBody struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&registerBody); err != nil {
		t.Fatal(err)
	}

	eventsCtx, cancelEvents := context.WithCancel(context.Background())
	eventsReq := httptest.NewRequest(http.MethodGet, "/v1/example/events", nil).WithContext(eventsCtx)
	eventsReq.Header.Set("Authorization", "Bearer "+registerBody.SessionID)
	eventsResp := newFlushRecorder()
	eventsDone := make(chan struct{})
	go func() {
		s.handle(eventsResp, eventsReq)
		close(eventsDone)
	}()

	hbResp := doRequest(t, s, http.MethodPost, "/v1/example/heartbeat", registerBody.SessionID, map[string]any{})
	if hbResp.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d", hbResp.Code)
	}

	waitForSSEData(t, eventsResp)
	cancelEvents()
	<-eventsDone

	body := eventsResp.Body.String()
	if !strings.Contains(body, "event: heartbeat_ack") {
		t.Fatalf("missing heartbeat_ack event in stream: %q", body)
	}
	if !strings.Contains(body, `"ttl":60`) {
		t.Fatalf("heartbeat_ack data missing ttl: %q", body)
	}
}

func TestConnectWaitsForResponse(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	// Make sure the wait is long enough for the goroutine below to run.
	old := connectResponseTimeout
	connectResponseTimeout = 2 * time.Second
	t.Cleanup(func() { connectResponseTimeout = old })

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d", registerResp.Code)
	}
	var rb struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&rb); err != nil {
		t.Fatal(err)
	}

	// Post the connect-response from a separate goroutine while /connect is
	// still waiting. Use a fresh address list to assert the response wins
	// over the registered cache.
	freshAddrs := []string{"198.51.100.1:9999"}
	go func() {
		// Small jitter to make sure /connect is already waiting on the channel.
		time.Sleep(50 * time.Millisecond)
		body, _ := json.Marshal(map[string]any{"addresses": freshAddrs})
		req := httptest.NewRequest(http.MethodPost, "/v1/example/connects/"+testNonce, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+rb.SessionID)
		resp := httptest.NewRecorder()
		s.handle(resp, req)
		if resp.Code != http.StatusNoContent {
			t.Errorf("connect-response status = %d, body = %s", resp.Code, resp.Body.String())
		}
	}()

	connectResp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.20:4433"},
		"nonce":     testNonce,
		"obfs":      testObfs,
	})
	if connectResp.Code != http.StatusOK {
		t.Fatalf("connect status = %d, body = %s", connectResp.Code, connectResp.Body.String())
	}
	var cb struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(connectResp.Body).Decode(&cb); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(cb.Addresses, ","), strings.Join(freshAddrs, ","); got != want {
		t.Fatalf("addresses = %q, want %q (fresh from connect-response)", got, want)
	}
}

func TestConnectFallsBackOnTimeout(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registered := []string{"203.0.113.10:4433"}
	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": registered,
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d", registerResp.Code)
	}

	// No connect-response goroutine; connect must time out and return cached.
	start := time.Now()
	connectResp := doRequest(t, s, http.MethodPost, "/v1/example/connect", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.20:4433"},
		"nonce":     testNonce,
		"obfs":      testObfs,
	})
	elapsed := time.Since(start)
	if connectResp.Code != http.StatusOK {
		t.Fatalf("connect status = %d", connectResp.Code)
	}
	if elapsed < connectResponseTimeout {
		t.Fatalf("returned in %v, want >= %v", elapsed, connectResponseTimeout)
	}
	if elapsed > connectResponseTimeout+time.Second {
		t.Fatalf("returned in %v, well past %v", elapsed, connectResponseTimeout)
	}
	var cb struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(connectResp.Body).Decode(&cb); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(cb.Addresses, ","), strings.Join(registered, ","); got != want {
		t.Fatalf("addresses = %q, want %q (registered cache)", got, want)
	}
}

func TestConnectResponseNotFoundForUnknownNonce(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d", registerResp.Code)
	}
	var rb struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&rb); err != nil {
		t.Fatal(err)
	}

	// No /connect call has happened, so this nonce has no pending entry.
	body, _ := json.Marshal(map[string]any{"addresses": []string{"198.51.100.1:9999"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/example/connects/"+testNonce, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+rb.SessionID)
	resp := httptest.NewRecorder()
	s.handle(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusNotFound)
	}
	var er struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&er)
	if er.Error != "attempt_not_found" {
		t.Fatalf("error code = %q, want attempt_not_found", er.Error)
	}
}

func TestEventsStreamClosesOnDeregister(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	registerResp := doRequest(t, s, http.MethodPost, "/v1/example", testRealmToken, map[string]any{
		"addresses": []string{"203.0.113.10:4433"},
	})
	if registerResp.Code != http.StatusOK {
		t.Fatalf("register status = %d", registerResp.Code)
	}
	var rb struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(registerResp.Body).Decode(&rb); err != nil {
		t.Fatal(err)
	}

	eventsReq := httptest.NewRequest(http.MethodGet, "/v1/example/events", nil)
	eventsReq.Header.Set("Authorization", "Bearer "+rb.SessionID)
	eventsResp := newFlushRecorder()
	eventsDone := make(chan struct{})
	go func() {
		s.handle(eventsResp, eventsReq)
		close(eventsDone)
	}()

	select {
	case <-eventsResp.flushed:
	case <-time.After(time.Second):
		t.Fatal("events stream did not start")
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/v1/example", nil)
	delReq.Header.Set("Authorization", "Bearer "+rb.SessionID)
	delResp := httptest.NewRecorder()
	s.handle(delResp, delReq)
	if delResp.Code != http.StatusNoContent {
		t.Fatalf("deregister status = %d", delResp.Code)
	}

	select {
	case <-eventsDone:
	case <-time.After(time.Second):
		t.Fatal("events stream did not close after deregister")
	}
	if eventsResp.Code != http.StatusOK {
		t.Fatalf("events status = %d", eventsResp.Code)
	}
}

func TestSendEventAfterRemoveSessionFails(t *testing.T) {
	s := newServer(serverConfig{})
	sess := &session{
		id:       "session",
		realmID:  "example",
		events:   make(chan sessionEvent, 1),
		done:     make(chan struct{}),
		clientIP: "1.1.1.1",
		pending:  make(map[string]chan punchResponsePayload),
	}
	s.realms[sess.realmID] = sess
	s.sessions[sess.id] = sess
	s.ipCounts[sess.clientIP] = 1

	s.removeSession(sess)
	if s.sendEvent(sess, sessionEvent{kind: "test"}) {
		t.Fatal("sendEvent succeeded on a removed session")
	}
}

func TestRemoveExpiredSessionRechecksExpiration(t *testing.T) {
	s := newServer(serverConfig{})
	now := time.Now()
	sess := &session{
		id:       "session",
		realmID:  "example",
		expires:  now.Add(time.Second),
		events:   make(chan sessionEvent, 1),
		done:     make(chan struct{}),
		clientIP: "1.1.1.1",
		pending:  make(map[string]chan punchResponsePayload),
	}
	s.realms[sess.realmID] = sess
	s.sessions[sess.id] = sess
	s.ipCounts[sess.clientIP] = 1

	if s.removeExpiredSession(sess, now) {
		t.Fatal("removed a session that was refreshed after the reaper scan")
	}
	if sess.closed {
		t.Fatal("session was closed")
	}
	if s.sessions[sess.id] == nil {
		t.Fatal("session was removed from index")
	}
}

func TestRejectsOversizedBody(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	body := bytes.Repeat([]byte("a"), maxRequestBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/example", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testRealmToken)
	resp := httptest.NewRecorder()
	s.handle(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusBadRequest)
	}
}

func registerWith(t *testing.T, s *server, realm, remoteAddr, header, headerValue string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"addresses": []string{"203.0.113.10:4433"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/"+realm, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testRealmToken)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if header != "" {
		req.Header.Set(header, headerValue)
	}
	resp := httptest.NewRecorder()
	s.handle(resp, req)
	return resp.Code
}

func TestGlobalRealmLimit(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{maxRealms: 2})

	if c := registerWith(t, s, "a", "1.1.1.1:1", "", ""); c != http.StatusOK {
		t.Fatalf("first = %d", c)
	}
	if c := registerWith(t, s, "b", "2.2.2.2:1", "", ""); c != http.StatusOK {
		t.Fatalf("second = %d", c)
	}
	if c := registerWith(t, s, "c", "3.3.3.3:1", "", ""); c != http.StatusTooManyRequests {
		t.Fatalf("third = %d, want 429", c)
	}
}

func TestPerIPRealmLimit(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{maxRealmsPerIP: 2})

	if c := registerWith(t, s, "a", "1.1.1.1:1", "", ""); c != http.StatusOK {
		t.Fatalf("a = %d", c)
	}
	if c := registerWith(t, s, "b", "1.1.1.1:2", "", ""); c != http.StatusOK {
		t.Fatalf("b = %d", c)
	}
	if c := registerWith(t, s, "c", "1.1.1.1:3", "", ""); c != http.StatusTooManyRequests {
		t.Fatalf("c = %d, want 429", c)
	}
	if c := registerWith(t, s, "d", "2.2.2.2:1", "", ""); c != http.StatusOK {
		t.Fatalf("different IP d = %d", c)
	}
}

func TestPerIPRealmLimitViaProxyHeader(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{maxRealmsPerIP: 1, proxyHeader: "X-Forwarded-For"})

	if c := registerWith(t, s, "a", "10.0.0.1:1", "X-Forwarded-For", "203.0.113.5"); c != http.StatusOK {
		t.Fatalf("a = %d", c)
	}
	if c := registerWith(t, s, "b", "10.0.0.1:1", "X-Forwarded-For", "203.0.113.5, 10.0.0.1"); c != http.StatusTooManyRequests {
		t.Fatalf("b = %d, want 429", c)
	}
	if c := registerWith(t, s, "c", "10.0.0.1:1", "X-Forwarded-For", "203.0.113.6"); c != http.StatusOK {
		t.Fatalf("c = %d", c)
	}
}

func TestPerIPLimitDecrementsOnDeregister(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{maxRealmsPerIP: 1})

	body, _ := json.Marshal(map[string]any{"addresses": []string{"203.0.113.10:4433"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/a", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testRealmToken)
	req.RemoteAddr = "1.1.1.1:1"
	resp := httptest.NewRecorder()
	s.handle(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("register = %d", resp.Code)
	}
	var rb struct {
		SessionID string `json:"session_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&rb)

	if c := registerWith(t, s, "b", "1.1.1.1:2", "", ""); c != http.StatusTooManyRequests {
		t.Fatalf("expected 429 before deregister, got %d", c)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/v1/a", nil)
	delReq.Header.Set("Authorization", "Bearer "+rb.SessionID)
	delReq.RemoteAddr = "1.1.1.1:1"
	delResp := httptest.NewRecorder()
	s.handle(delResp, delReq)
	if delResp.Code != http.StatusNoContent {
		t.Fatalf("deregister = %d", delResp.Code)
	}

	if c := registerWith(t, s, "b", "1.1.1.1:2", "", ""); c != http.StatusOK {
		t.Fatalf("expected OK after deregister, got %d", c)
	}
}

func TestRealmNameValidation(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{})

	cases := []struct {
		name string
		want int
	}{
		{"good", http.StatusOK},
		{"-leading-hyphen", http.StatusBadRequest},
		{"_leading-underscore", http.StatusBadRequest},
		{"has.dot", http.StatusBadRequest},
		{"has%20space", http.StatusBadRequest},
		{strings.Repeat("a", 65), http.StatusBadRequest},
		{"unicode-%C3%B1", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := registerWith(t, s, tc.name, "1.1.1.1:1", "", "")
			if c != tc.want {
				t.Fatalf("status = %d, want %d", c, tc.want)
			}
		})
	}
}

func TestRealmNameCustomPattern(t *testing.T) {
	realmToken = testRealmToken
	s := newServer(serverConfig{realmIDPattern: regexp.MustCompile(`^[0-9]+$`)})

	if c := registerWith(t, s, "12345", "1.1.1.1:1", "", ""); c != http.StatusOK {
		t.Fatalf("digits = %d", c)
	}
	if c := registerWith(t, s, "abc", "1.1.1.1:2", "", ""); c != http.StatusBadRequest {
		t.Fatalf("letters = %d, want 400", c)
	}
}

func TestGetenvBool(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_DEBUG_TEST", "true")
	if !getenvBool("HYSTERIA_REALM_DEBUG_TEST", false) {
		t.Fatal("expected true")
	}
	t.Setenv("HYSTERIA_REALM_DEBUG_TEST", "1")
	if !getenvBool("HYSTERIA_REALM_DEBUG_TEST", false) {
		t.Fatal("expected true for 1")
	}
	t.Setenv("HYSTERIA_REALM_DEBUG_TEST", "nope")
	if !getenvBool("HYSTERIA_REALM_DEBUG_TEST", true) {
		t.Fatal("expected default for invalid bool")
	}
	if getenvBool("HYSTERIA_REALM_DEBUG_TEST_UNSET", false) {
		t.Fatal("expected default false for unset")
	}
	_ = os.Unsetenv("HYSTERIA_REALM_DEBUG_TEST_UNSET")
}

func TestParseConfigEnvDefaults(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_LISTEN", ":9443")
	t.Setenv("HYSTERIA_REALM_TOKEN", "env-token")
	t.Setenv("HYSTERIA_REALM_CERT", "env.crt")
	t.Setenv("HYSTERIA_REALM_KEY", "env.key")
	t.Setenv("HYSTERIA_REALM_DEBUG", "true")

	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9443" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if cfg.Token != "env-token" {
		t.Fatalf("token = %q", cfg.Token)
	}
	if cfg.Cert != "env.crt" {
		t.Fatalf("cert = %q", cfg.Cert)
	}
	if cfg.Key != "env.key" {
		t.Fatalf("key = %q", cfg.Key)
	}
	if !cfg.Debug {
		t.Fatal("debug = false")
	}
}

func TestParseConfigFlagsOverrideEnv(t *testing.T) {
	t.Setenv("HYSTERIA_REALM_LISTEN", ":9443")
	t.Setenv("HYSTERIA_REALM_TOKEN", "env-token")
	t.Setenv("HYSTERIA_REALM_CERT", "env.crt")
	t.Setenv("HYSTERIA_REALM_KEY", "env.key")
	t.Setenv("HYSTERIA_REALM_DEBUG", "false")

	cfg, err := parseConfig([]string{
		"--listen", ":10443",
		"--token", "flag-token",
		"--cert", "flag.crt",
		"--key", "flag.key",
		"--debug",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":10443" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if cfg.Token != "flag-token" {
		t.Fatalf("token = %q", cfg.Token)
	}
	if cfg.Cert != "flag.crt" {
		t.Fatalf("cert = %q", cfg.Cert)
	}
	if cfg.Key != "flag.key" {
		t.Fatalf("key = %q", cfg.Key)
	}
	if !cfg.Debug {
		t.Fatal("debug = false")
	}
}

func doRequest(t *testing.T, s *server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	bs, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(bs))
	req.Header.Set("Authorization", "Bearer "+token)
	resp := httptest.NewRecorder()
	s.handle(resp, req)
	return resp
}

func waitForSSEData(t *testing.T, resp *flushRecorder) {
	t.Helper()
	select {
	case <-resp.wrote:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE data")
	}
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
	wrote   chan struct{}
	once    sync.Once
	write   sync.Once
}

func newFlushRecorder() *flushRecorder {
	return &flushRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		flushed:          make(chan struct{}),
		wrote:            make(chan struct{}),
	}
}

func (r *flushRecorder) Flush() {
	r.ResponseRecorder.Flush()
	r.once.Do(func() {
		close(r.flushed)
	})
}

func (r *flushRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseRecorder.Write(b)
	if n > 0 {
		r.write.Do(func() {
			close(r.wrote)
		})
	}
	return n, err
}
