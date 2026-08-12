type InformationLabel = { class: "secret"; tenant: string; purpose: string };

const label: InformationLabel = { class: "secret", tenant: "agent_a", purpose: "handoff" };
let sendOnce = true;
if (label.tenant !== "agent_a" || label.purpose !== "handoff" || !sendOnce) {
  throw new Error("handoff rejected");
}
sendOnce = false;
if (sendOnce) throw new Error("authority not consumed");
process.stdout.write(`${JSON.stringify({
  effect_requests: [{
    arguments: [{ type: "string", value: "bounded-agent-context" }],
    authority_slot: "send_once",
    effect: "network_send",
    information: label,
  }],
  result: { type: "unit" },
})}\n`);
