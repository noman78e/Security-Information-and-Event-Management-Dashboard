package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// Hub broadcasts live events to every open dashboard.
type Hub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func NewHub() *Hub {
	return &Hub{clients: make(map[chan []byte]struct{})}
}

func (h *Hub) subscribe() chan []byte {
	ch := make(chan []byte, 16) // small buffer keeps RAM low
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

func (h *Hub) Broadcast(msg []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default: // slow client: drop the message instead of blocking
		}
	}
}

func (h *Hub) BroadcastJSON(v any) {
	if b, err := json.Marshal(v); err == nil {
		h.Broadcast(b)
	}
}

func (h *Hub) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// serveEvents streams events to the browser using Server-Sent Events.
func (h *Hub) serveEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	if h.ClientCount() >= 20 { // a small computer should not serve unlimited live streams
		http.Error(w, "too many dashboards are open", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := h.subscribe()
	defer h.unsubscribe(ch)

	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
