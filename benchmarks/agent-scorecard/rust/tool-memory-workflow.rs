struct AuthoritySlot {
    effect: &'static str,
    consumed: bool,
}

impl AuthoritySlot {
    fn consume(&mut self, effect: &str) -> Result<(), &'static str> {
        if self.consumed || self.effect != effect {
            return Err("authority rejected");
        }
        self.consumed = true;
        Ok(())
    }
}

fn main() -> Result<(), &'static str> {
    let mut api_once = AuthoritySlot { effect: "api_call", consumed: false };
    let mut memory_once = AuthoritySlot { effect: "memory_write", consumed: false };
    let result = 6_i64 * 7_i64;
    api_once.consume("api_call")?;
    memory_once.consume("memory_write")?;
    println!("{{\"effect_requests\":[{{\"arguments\":[{{\"type\":\"string\",\"value\":\"model\"}},{{\"type\":\"i64\",\"value\":\"{result}\"}}],\"authority_slot\":\"api_once\",\"effect\":\"api_call\",\"information\":{{\"class\":\"public\"}}}},{{\"arguments\":[{{\"type\":\"string\",\"value\":\"session\"}},{{\"type\":\"i64\",\"value\":\"{result}\"}}],\"authority_slot\":\"memory_once\",\"effect\":\"memory_write\",\"information\":{{\"class\":\"public\"}}}}],\"result\":{{\"type\":\"i64\",\"value\":\"{result}\"}}}}");
    Ok(())
}
