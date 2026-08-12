type Authority = { consumed: boolean };

function consume(slot: Authority): void {
  slot.consumed = true;
}

const once: Authority = { consumed: false };
consume(once);
consume(once);
