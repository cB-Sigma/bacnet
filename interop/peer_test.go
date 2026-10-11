// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// image is the reference peer's image, built from ./peer.
const image = "sigma-bacnet-interop:bacnet-stack-1.6.1"

// envVar turns the tests on.
const envVar = "SIGMA_BACNET_INTEROP"

// needDocker skips the test unless the environment variable is 1 and
// Docker answers, and builds the peer image.
func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv(envVar) != "1" {
		t.Skip("set " + envVar + "=1 to run the interop tests (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not running")
	}
	// Built every time (Docker reuses its cached layers), so edits to the
	// Dockerfile are never tested against a stale image.
	out, err := exec.Command("docker", "build", "-q", "-t", image, "peer").CombinedOutput()
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
}

// freeUDPPort returns a UDP port free on the loopback interface.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// freeTCPPort returns a TCP port free on the loopback interface.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// peer is a bacnet-stack program running in a container; its output lines
// are collected.
type peer struct {
	t     *testing.T
	name  string
	cmd   *exec.Cmd
	lines chan string

	mu  sync.Mutex
	log []string
}

// startPeer runs `docker run --rm --name <unique> <args...>`.
func startPeer(t *testing.T, args ...string) *peer {
	t.Helper()
	p := &peer{t: t, name: fmt.Sprintf("sigma-bacnet-%d", time.Now().UnixNano()), lines: make(chan string, 4096)}
	full := append([]string{"run", "--rm", "--name", p.name}, args...)
	p.cmd = exec.Command("docker", full...)
	r, w := io.Pipe()
	p.cmd.Stdout, p.cmd.Stderr = w, w
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			p.mu.Lock()
			p.log = append(p.log, line)
			p.mu.Unlock()
			select {
			case p.lines <- line:
			default:
			}
		}
	}()
	go func() {
		if err := p.cmd.Wait(); err != nil {
			p.mu.Lock()
			p.log = append(p.log, "(exit: "+err.Error()+")")
			p.mu.Unlock()
		}
		_ = w.Close()
	}()
	t.Cleanup(func() {
		_ = exec.Command("docker", "stop", "-t", "1", p.name).Run()
		if t.Failed() || os.Getenv(envVar+"_LOG") == "1" {
			t.Logf("peer output:\n%s", p.output())
		}
	})
	return p
}

func (p *peer) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.log, "\n")
}

// expect waits for an output line containing all the parts, skipping
// others, and returns it.
func (p *peer) expect(within time.Duration, parts ...string) string {
	p.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case l := <-p.lines:
			ok := true
			for _, part := range parts {
				if !strings.Contains(l, part) {
					ok = false
					break
				}
			}
			if ok {
				return l
			}
		case <-deadline:
			p.t.Fatalf("no peer line with %q within %s", parts, within)
			return ""
		}
	}
}

// run runs one bacnet-stack command to its end in a fresh container and
// returns its output.
func run(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"run", "--rm"}, args...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
