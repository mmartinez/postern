//go:build darwin && cgo

package approval

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

typedef struct {
	int ok;
	long code;
	char *desc;
} laResult;

// The LAContext crosses into Go only as a retained opaque handle.
static uintptr_t laNew(void) {
	return (uintptr_t)CFBridgingRetain([[LAContext alloc] init]);
}

// laEvaluate blocks until the reply arrives. desc is malloc'd; the caller frees it.
static laResult laEvaluate(uintptr_t h, const char *reason) {
	__block laResult res = {0, 0, NULL};
	@autoreleasepool {
		LAContext *ctx = (__bridge LAContext *)(void *)h;
		dispatch_semaphore_t done = dispatch_semaphore_create(0);
		[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
		    localizedReason:[NSString stringWithUTF8String:reason]
		              reply:^(BOOL ok, NSError *err) {
			res.ok = ok;
			if (!ok) {
				res.code = (long)err.code;
				res.desc = strdup(err.localizedDescription.UTF8String ?: "");
			}
			dispatch_semaphore_signal(done);
		}];
		dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
	}
	return res;
}

// laInvalidate makes a pending evaluation reply with LAErrorAppCancel.
static void laInvalidate(uintptr_t h) {
	@autoreleasepool {
		[(__bridge LAContext *)(void *)h invalidate];
	}
}

static void laRelease(uintptr_t h) {
	CFRelease((CFTypeRef)(void *)h);
}
*/
import "C"

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	"github.com/mmartinez/postern/internal/broker"
)

const (
	laAuthenticationFailed = C.LAErrorAuthenticationFailed
	laUserCancel           = C.LAErrorUserCancel
	laSystemCancel         = C.LAErrorSystemCancel
	laAppCancel            = C.LAErrorAppCancel
)

// LocalAuth asks LocalAuthentication to verify the device owner with Touch
// ID, an Apple Watch, or the account password.
type LocalAuth struct{}

// New returns the LocalAuthentication approver.
func New() LocalAuth {
	return LocalAuth{}
}

// Approve shows reason in the system authentication dialog and maps the
// reply to an outcome. Cancelling ctx invalidates the context, which closes
// the dialog.
func (LocalAuth) Approve(ctx context.Context, reason string) (broker.Outcome, error) {
	h := C.laNew()
	defer C.laRelease(h)
	// stringWithUTF8String returns nil for invalid UTF-8, and a nil reason raises.
	cReason := C.CString(strings.ToValidUTF8(reason, "?"))
	defer C.free(unsafe.Pointer(cReason))

	done := make(chan C.laResult, 1)
	go func() { done <- C.laEvaluate(h, cReason) }()
	var res C.laResult
	select {
	case res = <-done:
	case <-ctx.Done():
		C.laInvalidate(h)
		res = <-done
	}
	defer C.free(unsafe.Pointer(res.desc))

	if err := ctx.Err(); err != nil {
		return broker.OutcomeUnavailable, fmt.Errorf("localauthentication: %w", err)
	}
	if res.ok != 0 {
		return broker.OutcomeApproved, nil
	}
	code := int(res.code)
	if o := laOutcome(code); o != broker.OutcomeUnavailable {
		return o, nil
	}
	return broker.OutcomeUnavailable, fmt.Errorf("localauthentication error %d: %s", code, C.GoString(res.desc))
}

// laOutcome maps an LAError code from a failed evaluation to an outcome.
func laOutcome(code int) broker.Outcome {
	switch code {
	case laAuthenticationFailed:
		return broker.OutcomeDenied
	case laUserCancel, laSystemCancel, laAppCancel:
		return broker.OutcomeDismissed
	default:
		return broker.OutcomeUnavailable
	}
}
