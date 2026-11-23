// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

// Package samples has the sample configuration in the program, for the
// help of dmodem-login -setup's screens.
package samples

import _ "embed"

// Conf is dmodem-login.conf.sample.
//
//go:embed dmodem-login.conf.sample
var Conf string
