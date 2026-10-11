package bacnet

import (
	"context"
	"errors"
	"time"
)

// Unconfirmed sends an unconfirmed request to the device.
func (c *Client) Unconfirmed(ctx context.Context, t Target, svc byte, body []byte) error {
	to, _, err := c.via(ctx, t)
	if err != nil {
		return err
	}
	return c.SendAPDU(to, t.Dest, false, append([]byte{PDUUnconfirmed << 4, svc}, body...))
}

// WhoHas sends Who-Has to the device and collects the I-Haves that come
// back within the timeout.
func (c *Client) WhoHas(ctx context.Context, t Target, body []byte) ([]iHave, error) {
	ch := make(chan iHave, 16)
	c.Mu.Lock()
	c.ihaves = append(c.ihaves, ch)
	c.Mu.Unlock()
	defer func() {
		c.Mu.Lock()
		for i, x := range c.ihaves {
			if x == ch {
				c.ihaves = append(c.ihaves[:i], c.ihaves[i+1:]...)
				break
			}
		}
		c.Mu.Unlock()
	}()
	if err := c.Unconfirmed(ctx, t, SvcWhoHas, body); err != nil {
		return nil, err
	}
	tm := time.NewTimer(t.Timeout)
	defer tm.Stop()
	var out []iHave
	for {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case h := <-ch:
			out = append(out, h)
		case <-tm.C:
			return out, nil
		}
	}
}

func (c *Client) gotIHave(data []byte) {
	h, err := DecodeIHave(data)
	if err != nil {
		return
	}
	c.Mu.Lock()
	defer c.Mu.Unlock()
	for _, ch := range c.ihaves {
		select {
		case ch <- h:
		default:
		}
	}
}

// WriteMultiple sends the writes in one WritePropertyMultiple.
func (c *Client) WriteMultiple(ctx context.Context, t Target, ws []PropWrite) error {
	body, err := EncodeWritePropertyMultiple(ws)
	if err != nil {
		return err
	}
	a, err := c.Request(ctx, t, SvcWritePropertyMulti, body)
	if err != nil {
		if a.Typ == PDUError {
			return DecodeWPMError(a.Data)
		}
		return err
	}
	if a.Typ != PDUSimpleACK {
		return errors.New("WritePropertyMultiple was not answered with a Simple-ACK")
	}
	return nil
}
