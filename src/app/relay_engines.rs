// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Where the run's engine rule becomes a routing every relay surface holds.
//!
//! The composition root is the one layer that may name the relay
//! implementation, so the constructor that reaches an engine is built here:
//! an rtpengine ng control client per control address, with the timeout every
//! other relay question uses. The rule itself is resolved and refused once, by
//! [`crate::cli::Cli::engine_selection`] during planning.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::cli::Cli;
use crate::relay::engines::{Connect, EngineRouting, EngineSelection};
use crate::relay::reconcile::ReadOnlyRelay;
use crate::rtpengine::control::{ControlClient, DEFAULT_CONTROL_TIMEOUT};

/// The routing for this run, or `None` when no engine rule is configured or
/// `--rtpengine-control` does not parse.
///
/// Planning refuses a rule without `--rtpengine-control`, so `None` from a
/// configured rule means the control address is unparseable; every surface
/// already reports that address as not configured, and with no default
/// engine there is nothing to route beside it.
#[must_use]
pub fn routing(cli: &Cli, selection: Option<&EngineSelection>) -> Option<Arc<EngineRouting>> {
    let selection = selection?;
    let default = cli
        .rtp_args
        .rtpengine_control
        .as_deref()?
        .parse::<SocketAddr>()
        .ok()?;
    let connect: Connect = Arc::new(|addr| -> Arc<dyn ReadOnlyRelay + Send + Sync> {
        Arc::new(ControlClient::new(addr, DEFAULT_CONTROL_TIMEOUT))
    });
    Some(Arc::new(EngineRouting::new(
        selection.rules.clone(),
        default,
        selection.previous,
        connect,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::engines::EngineRule;
    use clap::Parser;

    type TestError = Box<dyn std::error::Error>;

    #[test]
    fn a_rule_becomes_a_routing_around_the_control_address() -> Result<(), TestError> {
        let cli = Cli::try_parse_from(["sipnab", "--rtpengine-control", "192.0.2.1:2223"])?;
        let selection = EngineSelection {
            rules: EngineRule::TrustSdp { control_port: 2223 }.into(),
            previous: true,
        };
        let routing = routing(&cli, Some(&selection)).ok_or("a routing")?;
        assert_eq!(
            routing.default_engine(),
            "192.0.2.1:2223".parse()?,
            "a rule becomes a routing around the control address"
        );
        assert!(
            routing.asks_previous(),
            "a rule becomes a routing around the control address"
        );
        assert_eq!(
            routing.relay("198.51.100.10:2223".parse()?).describe(),
            "rtpengine at 198.51.100.10:2223",
            "an engine is reached by a control client at its control address"
        );
        Ok(())
    }

    #[test]
    fn no_rule_or_no_parseable_default_is_no_routing() -> Result<(), TestError> {
        let cli = Cli::try_parse_from(["sipnab", "--rtpengine-control", "192.0.2.1:2223"])?;
        assert!(
            routing(&cli, None).is_none(),
            "no rule or no parseable default is no routing"
        );
        let bad = Cli::try_parse_from(["sipnab", "--rtpengine-control", "relay-without-a-port"])?;
        let selection = EngineSelection {
            rules: EngineRule::TrustSdp { control_port: 2223 }.into(),
            previous: false,
        };
        assert!(
            routing(&bad, Some(&selection)).is_none(),
            "no rule or no parseable default is no routing"
        );
        Ok(())
    }
}
