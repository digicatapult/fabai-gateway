package gateway

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestStreamedResponse(t *testing.T) {
	const chunks = 20
	release := make(chan struct{})
	r := newReplica(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := range chunks {
			if i == 1 {
				select {
				case <-release:
				case <-req.Context().Done():
					return
				}
			}
			_, _ = fmt.Fprintf(w, "data: chunk %d\n\n", i)
			_ = http.NewResponseController(w).Flush()
		}
	}))
	gw, _, _ := gatewayFor(t, r)
	resp := send(t, sealedRequest(t, gw.URL, strings.NewReader("sealed")))

	first := make(chan string, 1)
	reader := bufio.NewReader(resp.Body)
	go func() {
		line, _ := reader.ReadString('\n')
		first <- line
	}()
	select {
	case line := <-first:
		if line != "data: chunk 0\n" {
			t.Fatalf("first line %q", line)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the first chunk didn't arrive before the replica sent the rest")
	}
	close(release)
	rest := readAll(t, reader)
	if got := strings.Count(string(rest), "data: "); got != chunks-1 {
		t.Errorf("%d more chunks, want %d", got, chunks-1)
	}
}

func TestLargeBody(t *testing.T) {
	r := newReplica(t, nil)
	gw, _, logs := gatewayFor(t, r)
	body := make([]byte, 16<<20)
	_, _ = rand.Read(body)
	resp := send(t, sealedRequest(t, gw.URL, strings.NewReader(string(body))))
	_, _ = io.Copy(io.Discard, resp.Body)
	_, bodies := r.received()
	if len(bodies) != 1 || sha256.Sum256(bodies[0]) != sha256.Sum256(body) {
		t.Fatal("the replica didn't receive the same bytes")
	}
	if out := waitForLines(t, logs, 1); !strings.Contains(out, fmt.Sprintf(`"bytes_in":%d`, len(body))) {
		t.Errorf("logs don't count %d bytes in:\n%s", len(body), logs)
	}
}

func TestSwap(t *testing.T) {
	release := make(chan struct{})
	old := newReplica(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/stream" {
			_, _ = io.WriteString(w, "old: started\n")
			_ = http.NewResponseController(w).Flush()
			<-release
			_, _ = io.WriteString(w, "old: finished\n")
			return
		}
		_, _ = io.WriteString(w, "old")
	}))
	modified := newReplica(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "modified")
	}))
	gw, routes, logs := gatewayFor(t, old)

	// One connection to the old replica stays busy with a stream, and a
	// second is idle when the swap happens.
	streamReq := sealedRequest(t, gw.URL, nil)
	streamReq.URL.Path = "/stream"
	stream := send(t, streamReq)
	streamBody := bufio.NewReader(stream.Body)
	if line, _ := streamBody.ReadString('\n'); line != "old: started\n" {
		t.Fatalf("stream: %q", line)
	}
	if got := readAll(t, send(t, sealedRequest(t, gw.URL, nil)).Body); string(got) != "old" {
		t.Fatalf("before the swap: %q", got)
	}

	if err := routes.Swap(protectedHost, modified.addr(t)); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, send(t, sealedRequest(t, gw.URL, nil)).Body); string(got) != "modified" {
		t.Errorf("after the swap: %q", got)
	}
	resp := send(t, newRequest(t, http.MethodGet, gw.URL+relayPathV3+"?nonce=00&enclave="+protectedHost, nil))
	if got := readAll(t, resp.Body); string(got) != "modified" {
		t.Errorf("relay after the swap: %q", got)
	}

	close(release)
	if rest := readAll(t, streamBody); string(rest) != "old: finished\n" {
		t.Errorf("the stream in flight didn't finish on the old replica: %q", rest)
	}
	deadline := time.Now().Add(5 * time.Second)
	for old.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if old.closed.Load() == 0 {
		t.Error("the idle connection to the old replica wasn't closed")
	}
	if !strings.Contains(logs.String(), `"msg":"route swapped","host":"`+protectedHost+`"`) {
		t.Errorf("the swap wasn't logged:\n%s", logs)
	}
}

func TestSwapRefuses(t *testing.T) {
	r := newReplica(t, nil)
	_, routes, _ := gatewayFor(t, r)
	if err := routes.Swap("other.fabai.internal", r.addr(t)); err != ErrUnknownHost {
		t.Errorf("unknown host: %v", err)
	}
	if err := routes.Swap(protectedHost, netip.AddrPortFrom(r.addr(t).Addr(), 0)); err == nil {
		t.Error("accepted port 0")
	}
}
