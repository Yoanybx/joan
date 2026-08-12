#[derive(PartialEq)]
struct InformationLabel {
    classification: &'static str,
    tenant: &'static str,
    purpose: &'static str,
}

fn main() -> Result<(), &'static str> {
    let label = InformationLabel {
        classification: "secret",
        tenant: "agent_a",
        purpose: "handoff",
    };
    let expected = InformationLabel {
        classification: "secret",
        tenant: "agent_a",
        purpose: "handoff",
    };
    let mut send_once = true;
    if label != expected || !send_once {
        return Err("handoff rejected");
    }
    send_once = false;
    if send_once {
        return Err("authority not consumed");
    }
    println!("{{\"effect_requests\":[{{\"arguments\":[{{\"type\":\"string\",\"value\":\"bounded-agent-context\"}}],\"authority_slot\":\"send_once\",\"effect\":\"network_send\",\"information\":{{\"class\":\"secret\",\"purpose\":\"handoff\",\"tenant\":\"agent_a\"}}}}],\"result\":{{\"type\":\"unit\"}}}}");
    Ok(())
}
