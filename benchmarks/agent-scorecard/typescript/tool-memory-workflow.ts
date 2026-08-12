type AuthoritySlot = { effect: string; consumed: boolean };

function consume(slot: AuthoritySlot, effect: string): void {
  if (slot.consumed || slot.effect !== effect) throw new Error("authority rejected");
  slot.consumed = true;
}

const apiOnce: AuthoritySlot = { effect: "api_call", consumed: false };
const memoryOnce: AuthoritySlot = { effect: "memory_write", consumed: false };
const result: bigint = 6n * 7n;
consume(apiOnce, "api_call");
consume(memoryOnce, "memory_write");
process.stdout.write(`${JSON.stringify({
  effect_requests: [
    {
      arguments: [{ type: "string", value: "model" }, { type: "i64", value: result.toString() }],
      authority_slot: "api_once",
      effect: "api_call",
      information: { class: "public" },
    },
    {
      arguments: [{ type: "string", value: "session" }, { type: "i64", value: result.toString() }],
      authority_slot: "memory_once",
      effect: "memory_write",
      information: { class: "public" },
    },
  ],
  result: { type: "i64", value: result.toString() },
})}\n`);
