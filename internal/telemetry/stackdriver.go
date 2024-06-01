// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package telemetry

import (
	"context"
	"os"

	"contrib.go.opencensus.io/exporter/stackdriver"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opencensus.io/stats/view"
	"go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

var (
	DefaultTracer = otel.GetTracerProvider().Tracer("github.com/govargo/open-match")
)

func bindStackDriverMetrics(ctx context.Context, p Params, b Bindings) error {
	cfg := p.Config()

	gcpProjectID := cfg.GetString("telemetry.stackdriverMetrics.gcpProjectId")
	metricPrefix := cfg.GetString("telemetry.stackdriverMetrics.prefix")
	samplingFraction := p.Config().GetFloat64("telemetry.traceSamplingFraction")

	if !cfg.GetBool("telemetry.stackdriverMetrics.enable") {
		logger.Info("StackDriver Metrics: Disabled")
	} else {
		logger.WithFields(logrus.Fields{
			"gcpProjectID": gcpProjectID,
			"metricPrefix": metricPrefix,
		}).Info("StackDriver Metrics: ENABLED")

		sd, err := stackdriver.NewExporter(stackdriver.Options{
			ProjectID: gcpProjectID,
			// MetricPrefix helps uniquely identify your metrics.
			MetricPrefix: metricPrefix,
		})
		if err != nil {
			return errors.Wrap(err, "Failed to initialize OpenCensus exporter to Stack Driver")
		}

		view.RegisterExporter(sd)

		b.AddCloser(func(ctx context.Context) {
			view.UnregisterExporter(sd)
			// It is imperative to invoke flush before your main function exits
			sd.Flush()
		})
	}

	// OpenTelemetry setting
	otelAgentAddr, ok := os.LookupEnv("OTEL_EXPORTER_ENDPOINT")
	if !ok {
		otelAgentAddr = "0.0.0.0:4317"
	}
	otlptraceClient := otlptracegrpc.NewClient(
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(otelAgentAddr))
	exporter, err := otlptrace.New(ctx, otlptraceClient)
	if err != nil {
		return errors.Wrap(err, "Failed to crete new OTLP span exporter")
	}

	res, err := resource.New(ctx,
		// Use the GCP resource detector to detect information about the GCP platform
		resource.WithDetectors(gcp.NewDetector()),
		// Keep the default detectors
		resource.WithTelemetrySDK(),
		// Add your own custom attributes to identify your application
		resource.WithAttributes(
			semconv.ServiceNameKey.String("open-match"),
			semconv.ServiceNamespaceKey.String("open-match"),
		),
	)
	if err != nil {
		return errors.Wrap(err, "Failed to crete new resource")
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplingFraction))),
	)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
	otel.SetTracerProvider(tp)

	logger.WithFields(logrus.Fields{
		"samplingFraction": samplingFraction,
	}).Info("OLTP span exporter: ENABLED")

	b.AddCloser(func(ctx context.Context) {
		// It is imperative to invoke flush before your main function exits
		err = tp.ForceFlush(ctx)
		if err != nil {
			logger.Errorf("Failed to flush trace provider: %s", err.Error())
		}
	})

	return nil
}
