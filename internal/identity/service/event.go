package service

import (
	"context"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

func emitEvent(ctx context.Context, sink domain.EventSink, event domain.Event) {
	if sink == nil {
		return
	}
	defer func() {
		// Observers are deliberately outside the identity transaction boundary.
		// A broken telemetry integration must not turn a committed operation
		// into an application-visible failure.
		_ = recover()
	}()
	if event.Attributes != nil {
		attributes := make(map[string]string, len(event.Attributes))
		for key, value := range event.Attributes {
			attributes[key] = value
		}
		event.Attributes = attributes
	}
	sink.Record(ctx, event)
}
