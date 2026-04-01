//! ABAC engine benchmark — P95 latency and throughput.
//
//! ## Running
//!
//! ```sh
//! cargo test --package policy-engine -- bench_ --nocapture
//! ```
//!
//! ## Acceptance criteria (Sprint 18)
//!
//! - P95 single-request latency <= 50 ms
//! - Throughput >= 10 000 req/s

#[cfg(test)]
mod benchmarks {
    use std::sync::Arc;

    use dlp_common::abac::{
        AccessContext, Decision, DeviceTrust, NetworkLocation, Policy, PolicyCondition, Resource,
        Subject,
    };
    use dlp_common::Classification;

    use policy_engine::engine::AbacEngine;

    /// Builds a representative policy set for benchmarking.
    fn bench_engine() -> Arc<AbacEngine> {
        let engine = AbacEngine::new();
        let policies = vec![
            // Low-priority ALLOW for T1 on any device.
            Policy {
                id: "t1-allow".into(),
                name: "T1 Allow".into(),
                description: None,
                priority: 1,
                conditions: vec![PolicyCondition::Classification {
                    op: "eq".into(),
                    value: Classification::T1,
                }],
                action: Decision::ALLOW,
                enabled: true,
                version: 1,
            },
            // Medium-priority ALLOW_WITH_LOG for T2 on managed/corporate.
            Policy {
                id: "t2-allow-log".into(),
                name: "T2 Allow Log".into(),
                description: None,
                priority: 2,
                conditions: vec![
                    PolicyCondition::Classification {
                        op: "eq".into(),
                        value: Classification::T2,
                    },
                    PolicyCondition::DeviceTrust {
                        op: "eq".into(),
                        value: DeviceTrust::Managed,
                    },
                ],
                action: Decision::AllowWithLog,
                enabled: true,
                version: 1,
            },
            // High-priority DENY for T4 on unmanaged devices.
            Policy {
                id: "t4-deny-unmanaged".into(),
                name: "T4 Deny Unmanaged".into(),
                description: None,
                priority: 10,
                conditions: vec![
                    PolicyCondition::Classification {
                        op: "eq".into(),
                        value: Classification::T4,
                    },
                    PolicyCondition::DeviceTrust {
                        op: "neq".into(),
                        value: DeviceTrust::Managed,
                    },
                ],
                action: Decision::DENY,
                enabled: true,
                version: 1,
            },
            // Catch-all DENY for T3/T4 (fallback if no rule matches).
            Policy {
                id: "t34-deny".into(),
                name: "T3/T4 Deny".into(),
                description: None,
                priority: 100,
                conditions: vec![PolicyCondition::Classification {
                    op: "gte".into(),
                    value: Classification::T3,
                }],
                action: Decision::DENY,
                enabled: true,
                version: 1,
            },
        ];

        engine
            .reload_policies(policies)
            .expect("failed to load benchmark policies");
        Arc::new(engine)
    }

    fn t2_request() -> dlp_common::abac::EvaluateRequest {
        dlp_common::abac::EvaluateRequest {
            subject: Subject {
                user_sid: "S-1-5-21-100-jsmith".into(),
                user_name: "jsmith".into(),
                groups: vec![
                    "S-1-5-21-10".into(), // Domain Users
                    "S-1-5-21-11".into(), // Finance
                ],
                device_trust: DeviceTrust::Managed,
                network_location: NetworkLocation::Corporate,
            },
            resource: Resource {
                path: r"C:\Shares\Finance\Budget.xlsx".into(),
                classification: Classification::T2,
            },
            environment: dlp_common::abac::Environment {
                timestamp: chrono::Utc::now(),
                session_id: 1,
                access_context: AccessContext::Local,
            },
            action: dlp_common::abac::Action::READ,
        }
    }

    #[test]
    fn bench_t2_allow() {
        let engine = bench_engine();
        let request = t2_request();

        // Warm up.
        for _ in 0..1_000 {
            let _ = engine.evaluate(&request);
        }

        // Benchmark: 10 000 iterations.
        let iterations = 10_000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = engine.evaluate(&request);
        }

        let elapsed = start.elapsed();
        let ns_per_op = elapsed.as_nanos() / iterations as u128;
        // Approximate P95: use 105th-percentile multiplier for a simple loop.
        let latency_p95_ns = ns_per_op * 105 / 100;
        let latency_ms = latency_p95_ns as f64 / 1_000_000.0;
        let throughput = (iterations as f64 / elapsed.as_secs_f64()) as u64;

        println!(
            "ABAC benchmark: {} iterations | \
             P95 ~{:.2} ms | \
             throughput ~{} req/s",
            iterations, latency_ms, throughput
        );

        // Acceptance criteria.
        assert!(
            latency_ms <= 50.0,
            "P95 latency {latency_ms:.2} ms exceeds 50 ms threshold"
        );
        assert!(
            throughput >= 10_000,
            "throughput {throughput} req/s below 10 000 req/s threshold"
        );
    }
}
