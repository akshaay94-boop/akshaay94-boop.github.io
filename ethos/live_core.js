/* Our Ethos live: the link between the wall and the phones.
   A small MQTT 3.1.1 client over WebSocket talks to several free public relays at once, so one
   relay being down or blocked does not stop the room. Every message is sealed with AES-GCM using a
   key derived from the six-character join code, so the relays only ever carry scrambled bytes.
   The wall publishes the screen state (retained) on <topic>/s; phones publish answers on <topic>/u. */
(function (G) {
  const RELAYS = [
    { name: 'EMQX', url: 'wss://broker.emqx.io:8084/mqtt' },
    { name: 'HiveMQ', url: 'wss://broker.hivemq.com:8884/mqtt' },
    { name: 'Shiftr', url: 'wss://public.cloud.shiftr.io', user: 'public', pass: 'public' },
    { name: 'Mosquitto', url: 'wss://test.mosquitto.org:8081/mqtt' }
  ];
  const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const te = new TextEncoder(), td = new TextDecoder();
  const rid = (n, a = 'abcdefghijkmnopqrstuvwxyz23456789') => { const b = crypto.getRandomValues(new Uint8Array(n)); let s = ''; for (const x of b) s += a[x % a.length]; return s; };
  const str = s => { const b = te.encode(s); return [b.length >> 8, b.length & 255, ...b]; };
  const packet = (head, body) => { const len = []; let n = body.length; do { let d = n % 128; n = Math.floor(n / 128); if (n) d |= 128; len.push(d); } while (n); const out = new Uint8Array(1 + len.length + body.length); out[0] = head; out.set(len, 1); out.set(body, 1 + len.length); return out; };
  const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };

  class Relay {
    constructor(cfg, hub) { this.cfg = cfg; this.hub = hub; this.subs = new Set(); this.up = false; this.wait = 800; this.buf = new Uint8Array(0); this.open(); }
    open() {
      if (this.dead) return;
      let ws; try { ws = new WebSocket(this.cfg.url, ['mqtt']); } catch (e) { this.fail = String(e && e.name || e); return this.retry(); }
      this.ws = ws; ws.binaryType = 'arraybuffer'; this.buf = new Uint8Array(0);
      const guard = setTimeout(() => { if (!this.up) try { ws.close(); } catch (e) { } }, 9000);
      ws.onopen = () => {
        let flags = 2; const pl = [...str('ihce' + rid(14))];
        if (this.cfg.user) { flags |= 0xc0; pl.push(...str(this.cfg.user), ...str(this.cfg.pass || '')); }
        ws.send(packet(0x10, [...str('MQTT'), 4, flags, 0, 60, ...pl]));
      };
      ws.onmessage = e => { if (this.ws === ws) this.feed(new Uint8Array(e.data)); };
      ws.onclose = () => { clearTimeout(guard); if (this.ws !== ws) return; clearInterval(this.ping); this.set(false); this.retry(); };
      ws.onerror = () => { };
    }
    retry() { clearTimeout(this.rt); if (this.dead) return; this.rt = setTimeout(() => this.open(), this.wait); this.wait = Math.min(this.wait * 2, 12000); }
    feed(chunk) {
      this.buf = this.buf.length ? cat(this.buf, chunk) : chunk;
      for (;;) {
        const b = this.buf; if (b.length < 2) return;
        let len = 0, mul = 1, i = 1, d;
        do { if (i >= b.length) return; d = b[i++]; len += (d & 127) * mul; mul *= 128; } while (d & 128 && i < 5);
        if (b.length < i + len) return;
        this.packet(b[0] >> 4, b[0] & 15, b.subarray(i, i + len));
        this.buf = b.slice(i + len);
      }
    }
    packet(type, flags, b) {
      if (type === 2) {
        if (b[1] !== 0) { try { this.ws.close(); } catch (e) { } return; }
        this.wait = 800; this.set(true); this.subs.forEach(t => this.sendSub(t));
        clearInterval(this.ping); this.ping = setInterval(() => this.raw(new Uint8Array([0xc0, 0])), 25000);
      } else if (type === 3) {
        const tl = (b[0] << 8) | b[1]; const topic = td.decode(b.subarray(2, 2 + tl)); let o = 2 + tl;
        if ((flags >> 1) & 3) o += 2;
        this.hub.onPacket(topic, b.slice(o), this);
      }
    }
    sub(t) { this.subs.add(t); if (this.up) this.sendSub(t); }
    sendSub(t) { this.raw(packet(0x82, [0, 1, ...str(t), 0])); }
    pub(t, payload, retain) { if (!this.up) return false; const tb = str(t); const body = new Uint8Array(tb.length + payload.length); body.set(tb); body.set(payload, tb.length); this.raw(packet(0x30 | (retain ? 1 : 0), body)); return true; }
    raw(bytes) { try { this.ws.send(bytes); } catch (e) { } }
    set(v) { if (this.up !== v) { this.up = v; this.hub.onStatus(); } }
    close() { this.dead = true; clearTimeout(this.rt); clearInterval(this.ping); try { this.ws && this.ws.close(); } catch (e) { } }
  }

  /* key and topic from the join code (PBKDF2, so the code cannot be read back from the topic) */
  async function derive(code) {
    const base = await crypto.subtle.importKey('raw', te.encode(code.toUpperCase()), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: te.encode('ihc-our-ethos-live-2026'), iterations: 100000, hash: 'SHA-256' }, base, 256));
    const key = await crypto.subtle.importKey('raw', bits.slice(0, 16), 'AES-GCM', false, ['encrypt', 'decrypt']);
    const topic = 'ihcethos/' + [...bits.slice(16, 26)].map(x => x.toString(16).padStart(2, '0')).join('');
    return { key, topic };
  }

  function relaysFromUrl() {
    try { const r = new URLSearchParams(location.search).get('relay'); if (r) return r.split(',').map((url, i) => ({ name: 'Relay ' + (i + 1), url })); } catch (e) { }
    return RELAYS;
  }

  /* role 'wall' listens on /u and publishes /s; role 'phone' the reverse */
  async function connect(code, role, on) {
    if (!(G.crypto && crypto.subtle)) throw new Error('nocrypto');
    const { key, topic } = await derive(code);
    const inT = topic + (role === 'wall' ? '/u' : '/s'), outT = topic + (role === 'wall' ? '/s' : '/u');
    const seen = new Map();
    const hub = {
      relays: [],
      onStatus() { on.status && on.status(hub.relays.filter(r => r.up).length, hub.relays.length); },
      async onPacket(t, bytes) {
        if (t !== inT || bytes.length < 29) return;
        try {
          const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, key, bytes.slice(12));
          const msg = JSON.parse(td.decode(pt));
          if (msg.m) { if (seen.has(msg.m)) return; seen.set(msg.m, 1); if (seen.size > 6000) seen.delete(seen.keys().next().value); }
          on.message(msg);
        } catch (e) { }
      }
    };
    hub.relays = relaysFromUrl().map(c => new Relay(c, hub));
    hub.relays.forEach(r => r.sub(inT));
    const seal = async obj => { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj)))); return cat(iv, ct); };
    return {
      topic,
      up: () => hub.relays.filter(r => r.up).length,
      total: () => hub.relays.length,
      names: () => hub.relays.map(r => [r.cfg.name, r.up]),
      async send(obj, retain) { obj.m = obj.m || rid(10); const b = await seal(obj); let n = 0; hub.relays.forEach(r => { if (r.pub(outT, b, retain)) n++; }); return n; },
      close() { hub.relays.forEach(r => r.close()); }
    };
  }

  const newCode = () => rid(6, ALPHA);
  const cleanCode = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6);
  G.LiveCore = { connect, newCode, cleanCode, rid, RELAYS, ALPHA };
})(window);
