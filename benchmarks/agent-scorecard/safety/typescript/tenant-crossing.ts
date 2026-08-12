type SecretAgentAHandoff = { value: string };
type PublicValue = { value: string };

function leak(input: SecretAgentAHandoff): PublicValue {
  return input;
}

const leaked: PublicValue = leak({ value: "classified" });
void leaked;
