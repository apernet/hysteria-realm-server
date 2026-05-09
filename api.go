package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

type punchEvent struct {
	Addresses []string `json:"addresses"`
	Nonce     string   `json:"nonce"`
	Obfs      string   `json:"obfs"`
}

const maxRequestBodyBytes = 4 << 10

var connectResponseTimeout = 10 * time.Second

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func (s *server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(limitBody)
	r.Post("/v1/{id}", s.register)
	r.Delete("/v1/{id}", s.deregister)
	r.Get("/v1/{id}/events", s.events)
	r.Post("/v1/{id}/heartbeat", s.heartbeat)
	r.Post("/v1/{id}/connect", s.connect)
	r.Post("/v1/{id}/connects/{nonce}", s.connectResponse)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not_found", "unknown path")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request", "method not allowed")
	})
	return r
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	s.routes().ServeHTTP(w, r)
}

func (s *server) checkRealmToken(r *http.Request) bool {
	expected := realmToken
	return expected != "" && bearer(r) == expected
}

func (s *server) realmID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := chi.URLParam(r, "id")
	if !s.realmIDPattern.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid realm name")
		return "", false
	}
	return id, true
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	if !s.checkRealmToken(r) {
		debugf("register unauthorized realm=%s remote=%s", id, r.RemoteAddr)
		writeErr(w, http.StatusUnauthorized, "invalid_token", "invalid realm token")
		return
	}
	var req struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if err := validateAddresses(req.Addresses); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	ip := clientIP(r, s.proxyHeader)
	s.mu.Lock()
	if _, exists := s.realms[id]; exists {
		s.mu.Unlock()
		debugf("register conflict realm=%s remote=%s", id, r.RemoteAddr)
		writeErr(w, http.StatusConflict, "realm_taken", "realm already registered")
		return
	}
	if s.maxRealms > 0 && len(s.realms) >= s.maxRealms {
		s.mu.Unlock()
		debugf("register rejected (global limit) realm=%s remote=%s", id, r.RemoteAddr)
		writeErr(w, http.StatusTooManyRequests, "realm_limit_reached", "global realm limit reached")
		return
	}
	if s.maxRealmsPerIP > 0 && s.ipCounts[ip] >= s.maxRealmsPerIP {
		s.mu.Unlock()
		debugf("register rejected (per-ip limit) realm=%s ip=%s remote=%s", id, ip, r.RemoteAddr)
		writeErr(w, http.StatusTooManyRequests, "ip_limit_reached", "per-ip realm limit reached")
		return
	}
	sess := &session{
		id:        randToken(),
		realmID:   id,
		addresses: req.Addresses,
		expires:   time.Now().Add(sessionTTL),
		events:    make(chan sessionEvent, 16),
		done:      make(chan struct{}),
		clientIP:  ip,
		pending:   make(map[string]chan punchResponsePayload),
	}
	s.realms[id] = sess
	s.sessions[sess.id] = sess
	s.ipCounts[ip]++
	s.mu.Unlock()
	debugf("registered realm=%s session=%s addresses=%d remote=%s", id, sess.id, len(req.Addresses), r.RemoteAddr)

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sess.id,
		"ttl":        int(sessionTTL.Seconds()),
	})
}

func (s *server) deregister(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	sess := s.getSessionByToken(bearer(r))
	if sess == nil || sess.realmID != id {
		debugf("deregister unauthorized realm=%s remote=%s", id, r.RemoteAddr)
		writeErr(w, http.StatusUnauthorized, "invalid_token", "invalid session token")
		return
	}
	debugf("deregistered realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
	s.removeSession(sess)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) heartbeat(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	sess := s.getSessionByToken(bearer(r))
	if sess == nil || sess.realmID != id {
		debugf("heartbeat unauthorized realm=%s remote=%s", id, r.RemoteAddr)
		writeErr(w, http.StatusUnauthorized, "invalid_token", "invalid session token")
		return
	}
	var req struct {
		Addresses []string `json:"addresses"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid json")
			return
		}
	}
	if req.Addresses != nil {
		if err := validateAddresses(req.Addresses); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
	}
	s.mu.Lock()
	if sess.closed {
		s.mu.Unlock()
		debugf("heartbeat closed realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
		writeErr(w, http.StatusUnauthorized, "invalid_token", "invalid session token")
		return
	}
	sess.expires = time.Now().Add(sessionTTL)
	if req.Addresses != nil {
		sess.addresses = append([]string(nil), req.Addresses...)
	}
	s.mu.Unlock()
	debugf("heartbeat realm=%s session=%s addressesUpdated=%t remote=%s", id, sess.id, req.Addresses != nil, r.RemoteAddr)
	if !s.sendEvent(sess, sessionEvent{kind: "heartbeat_ack", data: map[string]any{"ttl": int(sessionTTL.Seconds())}}) {
		debugf("heartbeat ack dropped realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ttl": int(sessionTTL.Seconds())})
}

func (s *server) events(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	sess := s.getSessionByToken(bearer(r))
	if sess == nil || sess.realmID != id {
		debugf("events unauthorized realm=%s remote=%s", id, r.RemoteAddr)
		writeErr(w, http.StatusUnauthorized, "invalid_token", "invalid session token")
		return
	}
	debugf("events connected realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "bad_request", "streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			debugf("events disconnected realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
			return
		case <-sess.done:
			debugf("events closed realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
			return
		case ev := <-sess.events:
			data, _ := json.Marshal(ev.data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.kind, data)
			flusher.Flush()
		}
	}
}

func (s *server) connect(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	if !s.checkRealmToken(r) {
		debugf("connect unauthorized realm=%s remote=%s", id, r.RemoteAddr)
		writeErr(w, http.StatusUnauthorized, "invalid_token", "invalid realm token")
		return
	}
	var req struct {
		Addresses []string `json:"addresses"`
		Nonce     string   `json:"nonce"`
		Obfs      string   `json:"obfs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if err := validateAddresses(req.Addresses); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := validateHexField("nonce", req.Nonce, nonceHexLength); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := validateHexField("obfs", req.Obfs, obfsHexLength); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	s.mu.Lock()
	sess := s.realms[id]
	if sess == nil || sess.closed || time.Now().After(sess.expires) {
		s.mu.Unlock()
		debugf("connect realm not found realm=%s remote=%s", id, r.RemoteAddr)
		writeErr(w, http.StatusNotFound, "realm_not_found", "realm not registered")
		return
	}
	serverAddrs := append([]string(nil), sess.addresses...)
	s.mu.Unlock()

	// Register the pending entry BEFORE pushing the punch event,
	// so a fast Hysteria server can never deliver before we're ready.
	respCh, ok := s.registerPending(sess, req.Nonce)
	if !ok {
		debugf("connect rate limited (pending) realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
		writeErr(w, http.StatusServiceUnavailable, "rate_limited", "too many in-flight connect attempts")
		return
	}
	defer s.cancelPending(sess, req.Nonce)

	if s.sendEvent(sess, sessionEvent{kind: "punch", data: punchEvent{Addresses: req.Addresses, Nonce: req.Nonce, Obfs: req.Obfs}}) {
		debugf("connect notified realm=%s session=%s clientAddresses=%d serverAddresses=%d remote=%s", id, sess.id, len(req.Addresses), len(serverAddrs), r.RemoteAddr)
	} else {
		debugf("connect rate limited realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
		writeErr(w, http.StatusServiceUnavailable, "rate_limited", "server event buffer full")
		return
	}

	// Now we wait for the fresh addresses to arrive.
	timer := time.NewTimer(connectResponseTimeout)
	defer timer.Stop()
	select {
	case payload, ok := <-respCh:
		if !ok {
			debugf("connect canceled realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
			writeErr(w, http.StatusNotFound, "realm_not_found", "realm not registered")
			return
		}
		if len(payload.addresses) > 0 {
			serverAddrs = payload.addresses
			debugf("connect fresh addresses realm=%s session=%s addresses=%d remote=%s", id, sess.id, len(serverAddrs), r.RemoteAddr)
		}
	case <-timer.C:
		debugf("connect response timed out realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
	case <-sess.done:
		debugf("connect canceled realm=%s session=%s remote=%s", id, sess.id, r.RemoteAddr)
		writeErr(w, http.StatusNotFound, "realm_not_found", "realm not registered")
		return
	case <-r.Context().Done():
		// Client gave up
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"addresses": serverAddrs,
		"nonce":     req.Nonce,
		"obfs":      req.Obfs,
	})
}

func (s *server) connectResponse(w http.ResponseWriter, r *http.Request) {
	id, ok := s.realmID(w, r)
	if !ok {
		return
	}
	nonce := chi.URLParam(r, "nonce")
	if err := validateHexField("nonce", nonce, nonceHexLength); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	sess := s.getSessionByToken(bearer(r))
	if sess == nil || sess.realmID != id {
		debugf("connect-response unauthorized realm=%s remote=%s", id, r.RemoteAddr)
		writeErr(w, http.StatusUnauthorized, "invalid_token", "invalid session token")
		return
	}
	var req struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if err := validateAddresses(req.Addresses); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if !s.deliverPending(sess, nonce, punchResponsePayload{addresses: req.Addresses}) {
		debugf("connect-response no pending realm=%s session=%s nonce=%s remote=%s", id, sess.id, nonce, r.RemoteAddr)
		writeErr(w, http.StatusNotFound, "attempt_not_found", "no pending attempt for nonce")
		return
	}
	debugf("connect-response delivered realm=%s session=%s addresses=%d remote=%s", id, sess.id, len(req.Addresses), r.RemoteAddr)
	w.WriteHeader(http.StatusNoContent)
}
