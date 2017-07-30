// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package saml

import "time"

type TimeInstant time.Time

func (m *TimeInstant) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*m = TimeInstant(time.Time{})
		return nil
	}
	t, err1 := time.Parse(time.RFC3339, string(text))
	if err1 == nil {
		*m = TimeInstant(t)
		return nil
	}

	t, err2 := time.Parse(time.RFC3339Nano, string(text))
	if err2 == nil {
		*m = TimeInstant(t)
		return nil
	}

	t, err2 = time.Parse("2006-01-02T15:04:05.999999999", string(text))
	if err2 == nil {
		*m = TimeInstant(t)
		return nil
	}

	return err1
}
